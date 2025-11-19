#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "common/array.h"
#include "common/error.h"
#include "common/json_util.h"
#include "common/log.h"
#include "common/net_proto.h"
#include "common/randutil.h"
#include "nm_state.h"

#define MAX_PEERS 256
#define TICKET_TTL 30
#define DEFAULT_STATE_PATH "nm_state.db"
#define LOG_GENERAL_PATH "nm.log"
#define LOG_REQUESTS_PATH "nm_requests.log"
#define MAX_JSON 4096

#define IO_OWNER_NONE 0
#define IO_OWNER_WORKER 1
#define IO_OWNER_RPC 2

#define STATE_LOCK(ctx) pthread_mutex_lock(&(ctx)->state_lock)
#define STATE_UNLOCK(ctx) pthread_mutex_unlock(&(ctx)->state_lock)

struct nm_context;
static struct nm_context *g_nm_ctx = NULL;

enum peer_type {
    PEER_UNUSED = 0,
    PEER_UNKNOWN,
    PEER_CLIENT,
    PEER_SERVER
};

struct peer {
    int fd;
    enum peer_type type;
    int server_index;
    char user[NM_MAX_USER];
    pthread_t thread;
    int thread_active;
    int index;
    pthread_mutex_t io_lock;
    pthread_cond_t io_cond;
    int io_lock_ready;
    int rpc_waiting;
    char *rpc_response;
};

struct active_user {
    char name[NM_MAX_USER];
};

struct ticket_entry {
    char token[64];
    char file[NM_MAX_NAME];
    char user[NM_MAX_USER];
    char op[16];
    time_t expiry;
    int ss_index;
};

struct replication_task {
    char file[NM_MAX_NAME];
    char owner[NM_MAX_USER];
    int primary_index;
    int backup_index;
    int assign_mode;
};

struct nm_context {
    int listen_fd;
    struct peer peers[MAX_PEERS];
    struct nm_state state;
    struct array tickets; /* struct ticket_entry */
    struct array active_users; /* struct active_user */
    struct array replication_queue; /* struct replication_task */
    struct log_writer log_general;
    struct log_writer log_requests;
    pthread_mutex_t state_lock;
    pthread_mutex_t ticket_lock;
    pthread_mutex_t user_lock;
    pthread_mutex_t peer_lock;
    pthread_mutex_t log_general_lock;
    pthread_mutex_t log_requests_lock;
    pthread_mutex_t replication_lock;
    pthread_cond_t replication_cond;
    int locks_ready;
    int shutting_down;
    pthread_t prune_thread;
    int prune_thread_running;
    pthread_t replication_thread;
    int replication_thread_running;
};

static void peer_reset_fields(struct peer *p) {
    p->fd = -1;
    p->type = PEER_UNUSED;
    p->server_index = -1;
    p->user[0] = '\0';
    p->thread = 0;
    p->thread_active = 0;
    p->index = -1;
}

static int peer_slot_setup(struct peer *p) {
    memset(p, 0, sizeof(*p));
    if (pthread_mutex_init(&p->io_lock, NULL) != 0) {
        return -1;
    }
    if (pthread_cond_init(&p->io_cond, NULL) != 0) {
        pthread_mutex_destroy(&p->io_lock);
        return -1;
    }
    p->io_lock_ready = 1;
    p->rpc_waiting = 0;
    p->rpc_response = NULL;
    peer_reset_fields(p);
    return 0;
}

static void peer_slot_destroy(struct peer *p) {
    if (!p) {
        return;
    }
    if (p->io_lock_ready) {
        pthread_mutex_lock(&p->io_lock);
        if (p->rpc_response) {
            free(p->rpc_response);
            p->rpc_response = NULL;
        }
        pthread_mutex_unlock(&p->io_lock);
        pthread_mutex_destroy(&p->io_lock);
        pthread_cond_destroy(&p->io_cond);
        p->io_lock_ready = 0;
    }
}

static int init_context_locks(struct nm_context *ctx) {
    if (pthread_mutex_init(&ctx->state_lock, NULL) != 0) {
        return -1;
    }
    if (pthread_mutex_init(&ctx->ticket_lock, NULL) != 0) {
        pthread_mutex_destroy(&ctx->state_lock);
        return -1;
    }
    if (pthread_mutex_init(&ctx->user_lock, NULL) != 0) {
        pthread_mutex_destroy(&ctx->ticket_lock);
        pthread_mutex_destroy(&ctx->state_lock);
        return -1;
    }
    if (pthread_mutex_init(&ctx->peer_lock, NULL) != 0) {
        pthread_mutex_destroy(&ctx->user_lock);
        pthread_mutex_destroy(&ctx->ticket_lock);
        pthread_mutex_destroy(&ctx->state_lock);
        return -1;
    }
    if (pthread_mutex_init(&ctx->log_general_lock, NULL) != 0) {
        pthread_mutex_destroy(&ctx->peer_lock);
        pthread_mutex_destroy(&ctx->user_lock);
        pthread_mutex_destroy(&ctx->ticket_lock);
        pthread_mutex_destroy(&ctx->state_lock);
        return -1;
    }
    if (pthread_mutex_init(&ctx->log_requests_lock, NULL) != 0) {
        pthread_mutex_destroy(&ctx->log_general_lock);
        pthread_mutex_destroy(&ctx->peer_lock);
        pthread_mutex_destroy(&ctx->user_lock);
        pthread_mutex_destroy(&ctx->ticket_lock);
        pthread_mutex_destroy(&ctx->state_lock);
        return -1;
    }
    if (pthread_mutex_init(&ctx->replication_lock, NULL) != 0) {
        pthread_mutex_destroy(&ctx->log_requests_lock);
        pthread_mutex_destroy(&ctx->log_general_lock);
        pthread_mutex_destroy(&ctx->peer_lock);
        pthread_mutex_destroy(&ctx->user_lock);
        pthread_mutex_destroy(&ctx->ticket_lock);
        pthread_mutex_destroy(&ctx->state_lock);
        return -1;
    }
    if (pthread_cond_init(&ctx->replication_cond, NULL) != 0) {
        pthread_mutex_destroy(&ctx->replication_lock);
        pthread_mutex_destroy(&ctx->log_requests_lock);
        pthread_mutex_destroy(&ctx->log_general_lock);
        pthread_mutex_destroy(&ctx->peer_lock);
        pthread_mutex_destroy(&ctx->user_lock);
        pthread_mutex_destroy(&ctx->ticket_lock);
        pthread_mutex_destroy(&ctx->state_lock);
        return -1;
    }
    ctx->locks_ready = 1;
    return 0;
}

static void destroy_context_locks(struct nm_context *ctx) {
    if (!ctx || !ctx->locks_ready) {
        return;
    }
    for (int i = 0; i < MAX_PEERS; ++i) {
        peer_slot_destroy(&ctx->peers[i]);
    }
    pthread_mutex_destroy(&ctx->log_requests_lock);
    pthread_cond_destroy(&ctx->replication_cond);
    pthread_mutex_destroy(&ctx->replication_lock);
    pthread_mutex_destroy(&ctx->log_general_lock);
    pthread_mutex_destroy(&ctx->peer_lock);
    pthread_mutex_destroy(&ctx->user_lock);
    pthread_mutex_destroy(&ctx->ticket_lock);
    pthread_mutex_destroy(&ctx->state_lock);
    ctx->locks_ready = 0;
}

static void peer_close(struct nm_context *ctx, struct peer *p) {
    if (!ctx || !p) {
        return;
    }
    pthread_mutex_lock(&ctx->peer_lock);
    if (p->io_lock_ready) {
        pthread_mutex_lock(&p->io_lock);
        if (p->rpc_response) {
            free(p->rpc_response);
            p->rpc_response = NULL;
        }
        p->rpc_waiting = 0;
        pthread_cond_broadcast(&p->io_cond);
        if (p->fd >= 0) {
            net_close(p->fd);
        }
        peer_reset_fields(p);
        pthread_mutex_unlock(&p->io_lock);
    } else {
        if (p->fd >= 0) {
            net_close(p->fd);
        }
        peer_reset_fields(p);
    }
    pthread_mutex_unlock(&ctx->peer_lock);
}

static void peer_reset(struct nm_context *ctx, struct peer *p) {
    if (!ctx || !p) {
        return;
    }
    pthread_mutex_lock(&ctx->peer_lock);
    if (p->io_lock_ready) {
        pthread_mutex_lock(&p->io_lock);
        if (p->rpc_response) {
            free(p->rpc_response);
            p->rpc_response = NULL;
        }
        p->rpc_waiting = 0;
        pthread_cond_broadcast(&p->io_cond);
        peer_reset_fields(p);
        pthread_mutex_unlock(&p->io_lock);
    } else {
        peer_reset_fields(p);
    }
    pthread_mutex_unlock(&ctx->peer_lock);
}

static void log_event(struct nm_context *ctx, const char *fmt, ...) {
    if (!ctx || !ctx->log_general.fp) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    char message[1024];
    vsnprintf(message, sizeof(message), fmt, ap);
    va_end(ap);
    pthread_mutex_lock(&ctx->log_general_lock);
    log_appendf(&ctx->log_general, "%s", message);
    pthread_mutex_unlock(&ctx->log_general_lock);
}

static void log_request(struct nm_context *ctx, const char *fmt, ...) {
    if (!ctx || !ctx->log_requests.fp) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    char message[1024];
    vsnprintf(message, sizeof(message), fmt, ap);
    va_end(ap);
    pthread_mutex_lock(&ctx->log_requests_lock);
    log_appendf(&ctx->log_requests, "%s", message);
    pthread_mutex_unlock(&ctx->log_requests_lock);
}

static int send_ok(int fd, const char *extra) {
    char buf[MAX_JSON];
    if (extra && extra[0]) {
        if (snprintf(buf, sizeof(buf), "{\"status\":\"OK\",%s}", extra) >= (int)sizeof(buf)) {
            return -1;
        }
    } else {
        if (snprintf(buf, sizeof(buf), "{\"status\":\"OK\"}") >= (int)sizeof(buf)) {
            return -1;
        }
    }
    return net_send_json(fd, buf);
}

static int send_error_response(int fd, error_code_t code, const char *message) {
    char buf[MAX_JSON];
    const char *msg = message ? message : error_code_message(code);
    if (snprintf(buf, sizeof(buf),
                 "{\"status\":\"ERR\",\"code\":\"%s\",\"message\":\"%s\"}",
                 error_code_name(code), msg) >= (int)sizeof(buf)) {
        return -1;
    }
    if (g_nm_ctx) {
        log_event(g_nm_ctx, "ERROR_RESP fd=%d code=%s message=%s",
                  fd, error_code_name(code), msg);
    }
    return net_send_json(fd, buf);
}

static int parse_status(const char *response,
                        char *status_buf,
                        size_t status_len,
                        char *msg_buf,
                        size_t msg_len) {
    if (json_get_string(response, "status", status_buf, status_len) < 0) {
        return -1;
    }
    if (msg_buf && msg_len > 0) {
        if (json_get_string(response, "message", msg_buf, msg_len) < 0) {
            msg_buf[0] = '\0';
        }
    }
    return 0;
}

static struct storage_server *select_storage_server(struct nm_context *ctx,
                                                   struct file_entry *file,
                                                   int *server_index_out);
static int handle_server_message(struct nm_context *ctx, const char *json);
static int server_is_available(const struct storage_server *ss);
static void drop_backup_only(struct nm_context *ctx, struct file_entry *file, const char *reason);
static void drop_file_backup(struct nm_context *ctx, struct file_entry *file, const char *reason);
static void try_assign_backup(struct nm_context *ctx, const char *file_name);
static int has_backup_candidate(const struct nm_context *ctx, int primary_index);
static void *peer_thread_main(void *arg);
static int schedule_replication(struct nm_context *ctx,
                                const char *file_name,
                                const char *owner,
                                int primary_index,
                                int backup_index,
                                int assign_mode);
static void *replication_worker(void *arg);
static void *ticket_prune_worker(void *arg);
static struct peer *find_server_peer(struct nm_context *ctx, int server_index);
static int obtain_ticket_for_file(struct nm_context *ctx,
                                  const char *file_name,
                                  const char *user,
                                  int required_perm,
                                  const char *op,
                                  char *token_out,
                                  int *ss_index_out,
                                  struct storage_server **ss_out);

struct peer_thread_arg {
    struct nm_context *ctx;
    int index;
};

static void ticket_prune(struct nm_context *ctx) {
    time_t now = time(NULL);
    size_t i = 0;
    pthread_mutex_lock(&ctx->ticket_lock);
    while (i < ctx->tickets.len) {
        struct ticket_entry *entry = array_get(&ctx->tickets, i);
        if (entry->expiry && entry->expiry < now) {
            array_remove(&ctx->tickets, i);
        } else {
            i++;
        }
    }
    pthread_mutex_unlock(&ctx->ticket_lock);
}

static int active_user_add(struct nm_context *ctx, const char *user) {
    if (!ctx || !user || !user[0]) {
        return -1;
    }
    int rc = 0;
    pthread_mutex_lock(&ctx->user_lock);
    for (size_t i = 0; i < ctx->active_users.len; ++i) {
        struct active_user *entry = array_get(&ctx->active_users, i);
        if (entry && strcmp(entry->name, user) == 0) {
            errno = EEXIST;
            pthread_mutex_unlock(&ctx->user_lock);
            return -1;
        }
    }
    struct active_user entry;
    memset(&entry, 0, sizeof(entry));
    snprintf(entry.name, sizeof(entry.name), "%s", user);
    if (array_push(&ctx->active_users, &entry) < 0) {
        rc = -1;
    }
    pthread_mutex_unlock(&ctx->user_lock);
    return rc;
}

static void active_user_remove(struct nm_context *ctx, const char *user) {
    if (!ctx || !user || !user[0]) {
        return;
    }
    pthread_mutex_lock(&ctx->user_lock);
    for (size_t i = 0; i < ctx->active_users.len; ++i) {
        struct active_user *entry = array_get(&ctx->active_users, i);
        if (entry && strcmp(entry->name, user) == 0) {
            array_remove(&ctx->active_users, i);
            break;
        }
    }
    pthread_mutex_unlock(&ctx->user_lock);
}

static int username_in_use(struct nm_context *ctx, const char *user) {
    if (!ctx || !user || !user[0]) {
        return 0;
    }
    int in_use = 0;
    pthread_mutex_lock(&ctx->user_lock);
    for (size_t i = 0; i < ctx->active_users.len; ++i) {
        struct active_user *entry = array_get(&ctx->active_users, i);
        if (entry && strcmp(entry->name, user) == 0) {
            in_use = 1;
            break;
        }
    }
    pthread_mutex_unlock(&ctx->user_lock);
    return in_use;
}

static int forward_command(struct nm_context *ctx,
                           struct storage_server *ss,
                           const char *payload,
                           char **response_out) {
    if (!ss) {
        return -1;
    }
    struct peer *server_peer = find_server_peer(ctx, ss->ctrl_fd);
    if (!server_peer) {
        return -1;
    }
    if (!server_peer->io_lock_ready) {
        return -1;
    }
    pthread_mutex_lock(&server_peer->io_lock);
    while (server_peer->rpc_waiting && !ctx->shutting_down) {
        pthread_cond_wait(&server_peer->io_cond, &server_peer->io_lock);
    }
    if (ctx->shutting_down) {
        pthread_mutex_unlock(&server_peer->io_lock);
        return -1;
    }
    server_peer->rpc_waiting = 1;
    if (server_peer->rpc_response) {
        free(server_peer->rpc_response);
        server_peer->rpc_response = NULL;
    }
    pthread_mutex_unlock(&server_peer->io_lock);

    log_event(ctx, "FORWARD server=%s sending payload=%s", ss->id, payload);
    if (net_send_json(ss->ctrl_fd, payload) < 0) {
        pthread_mutex_lock(&server_peer->io_lock);
        server_peer->rpc_waiting = 0;
        pthread_cond_broadcast(&server_peer->io_cond);
        pthread_mutex_unlock(&server_peer->io_lock);
        return -1;
    }

    pthread_mutex_lock(&server_peer->io_lock);
    while (server_peer->rpc_waiting && !ctx->shutting_down) {
        pthread_cond_wait(&server_peer->io_cond, &server_peer->io_lock);
    }
    char *response = server_peer->rpc_response;
    server_peer->rpc_response = NULL;
    pthread_mutex_unlock(&server_peer->io_lock);

    if (!response) {
        log_event(ctx, "FORWARD server=%s failed (no response)", ss->id);
        return -1;
    }
    if (response_out) {
        *response_out = response;
    } else {
        free(response);
    }
    log_event(ctx, "FORWARD server=%s complete rc=0", ss->id);
    return 0;
}

static int issue_ticket(struct nm_context *ctx,
                        struct storage_server *ss,
                        int ss_index,
                        const char *file,
                        const char *user,
                        const char *op,
                        char *token_out) {
    ticket_prune(ctx);
    struct ticket_entry entry;
    memset(&entry, 0, sizeof(entry));
    randutil_seed();
    randutil_token(entry.token, sizeof(entry.token));
    snprintf(entry.file, sizeof(entry.file), "%s", file);
    snprintf(entry.user, sizeof(entry.user), "%s", user);
    snprintf(entry.op, sizeof(entry.op), "%s", op);
    entry.expiry = time(NULL) + TICKET_TTL;
    entry.ss_index = ss_index;

    char payload[512];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"NM_TICKET\",\"token\":\"%s\",\"file\":\"%s\","
                 "\"user\":\"%s\",\"op\":\"%s\",\"expiry\":%ld}",
                 entry.token, entry.file, entry.user, entry.op, (long)entry.expiry) >=
        (int)sizeof(payload)) {
        return -1;
    }

    char *response = NULL;
    if (forward_command(ctx, ss, payload, &response) < 0) {
        free(response);
        return -1;
    }
    char status[16];
    int ok = (json_get_string(response, "status", status, sizeof(status)) == 0) &&
             strcmp(status, "OK") == 0;
    free(response);
    if (!ok) {
        return -1;
    }

    pthread_mutex_lock(&ctx->ticket_lock);
    int push_rc = array_push(&ctx->tickets, &entry);
    pthread_mutex_unlock(&ctx->ticket_lock);
    if (push_rc < 0) {
        return -1;
    }
    if (token_out) {
        snprintf(token_out, 64, "%s", entry.token);
    }
    return 0;
}

static struct peer *allocate_peer(struct nm_context *ctx, int *index_out) {
    struct peer *slot = NULL;
    pthread_mutex_lock(&ctx->peer_lock);
    for (int i = 0; i < MAX_PEERS; ++i) {
        if (ctx->peers[i].type == PEER_UNUSED) {
            slot = &ctx->peers[i];
            peer_reset_fields(slot);
            slot->index = i;
            break;
        }
    }
    pthread_mutex_unlock(&ctx->peer_lock);
    if (slot && index_out) {
        *index_out = slot->index;
    }
    return slot;
}

static int ss_fetch_content(struct storage_server *ss,
                            const char *file,
                            const char *user,
                            const char *ticket,
                            char **out_content) {
    int fd = net_connect(ss->host, ss->data_port);
    if (fd < 0) {
        return -1;
    }
    char *file_esc = json_escape_dup(file);
    char *user_esc = json_escape_dup(user);
    char *ticket_esc = json_escape_dup(ticket);
    if (!file_esc || !user_esc || !ticket_esc) {
        free(file_esc);
        free(user_esc);
        free(ticket_esc);
        net_close(fd);
        return -1;
    }
    char payload[MAX_JSON];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"READ\",\"file\":\"%s\",\"user\":\"%s\",\"ticket\":\"%s\"}",
                 file_esc, user_esc, ticket_esc) >= (int)sizeof(payload)) {
        free(file_esc);
        free(user_esc);
        free(ticket_esc);
        net_close(fd);
        return -1;
    }
    free(file_esc);
    free(user_esc);
    free(ticket_esc);

    char *response = NULL;
    if (net_send_json(fd, payload) < 0 || net_recv_json(fd, &response) < 0) {
        net_close(fd);
        free(response);
        return -1;
    }
    net_close(fd);
    char status[16];
    if (json_get_string(response, "status", status, sizeof(status)) < 0 || strcmp(status, "OK") != 0) {
        free(response);
        return -1;
    }
    char *content = NULL;
    if (json_get_string_alloc(response, "content", &content) < 0) {
        free(response);
        return -1;
    }
    free(response);
    *out_content = content;
    return 0;
}

static int is_exec_delim_char(char c) {
    return (c == '.' || c == '!' || c == '?');
}

static char *flatten_exec_script(const char *script) {
    if (!script) {
        return strdup("");
    }
    size_t len = strlen(script);
    char *flat = malloc(len + 1);
    if (!flat) {
        return NULL;
    }
    size_t pos = 0;
    char last_non_newline = '\0';
    for (size_t i = 0; i < len; ++i) {
        char c = script[i];
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            if (last_non_newline && is_exec_delim_char(last_non_newline)) {
                continue;
            }
            flat[pos++] = c;
            continue;
        }
        flat[pos++] = c;
        last_non_newline = c;
    }
    flat[pos] = '\0';
    return flat;
}

static int run_exec_commands(const char *script, char **output) {
    char template[] = "/tmp/docspp-exec-XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0) {
        return -1;
    }
    char *normalized = flatten_exec_script(script);
    if (!normalized) {
        close(fd);
        unlink(template);
        return -1;
    }
    size_t len = strlen(normalized);
    if (len > 0) {
        if (write(fd, normalized, len) != (ssize_t)len) {
            free(normalized);
            close(fd);
            unlink(template);
            return -1;
        }
    }
    free(normalized);
    const char newline = '\n';
    if (write(fd, &newline, 1) != 1) {
        close(fd);
        unlink(template);
        return -1;
    }
    close(fd);

    char command[PATH_MAX + 32];
    if (snprintf(command, sizeof(command), "sh < \"%s\" 2>&1", template) >= (int)sizeof(command)) {
        unlink(template);
        return -1;
    }

    FILE *pipe = popen(command, "r");
    if (!pipe) {
        unlink(template);
        return -1;
    }

    size_t cap = 256;
    size_t size = 0;
    char *buf = malloc(cap);
    if (!buf) {
        pclose(pipe);
        unlink(template);
        return -1;
    }
    buf[0] = '\0';
    char chunk[256];
    while (fgets(chunk, sizeof(chunk), pipe)) {
        size_t add = strlen(chunk);
        if (size + add + 1 > cap) {
            while (size + add + 1 > cap) {
                cap *= 2;
            }
            char *tmp = realloc(buf, cap);
            if (!tmp) {
                free(buf);
                pclose(pipe);
                unlink(template);
                return -1;
            }
            buf = tmp;
        }
        memcpy(buf + size, chunk, add);
        size += add;
        buf[size] = '\0';
    }
    int status = pclose(pipe);
    unlink(template);
    (void)status;
    *output = buf;
    return 0;
}

static int valid_filename(const char *name) {
    if (!name || !name[0]) {
        return 0;
    }
    for (const unsigned char *p = (const unsigned char *)name; *p; ++p) {
        if (*p == '.' && (p == (const unsigned char *)name || *(p + 1) == '.')) {
            return 0;
        }
        if (*p == '/' || *p == '\\') {
            return 0;
        }
        if (*p < 32 || *p > 126) {
            return 0;
        }
    }
    return 1;
}

static void handle_server_disconnect(struct nm_context *ctx, struct peer *p) {
    if (p->type == PEER_CLIENT && p->user[0]) {
        log_event(ctx, "client %s disconnected", p->user);
        active_user_remove(ctx, p->user);
    }
    if (p->type == PEER_SERVER && p->server_index >= 0) {
        pthread_mutex_lock(&ctx->state_lock);
        int server_index = p->server_index;
        nm_mark_server_down(&ctx->state, server_index);
        log_event(ctx, "server %d disconnected", server_index);
        int state_dirty = 0;
        char pending_backup[NM_MAX_FILES][NM_MAX_NAME];
        size_t pending_count = 0;
        for (size_t i = 0; i < ctx->state.file_count; ++i) {
            struct file_entry *file = &ctx->state.files[i];
            int file_dirty = 0;
            if (file->ss_index == server_index) {
                if (file->backup_index >= 0) {
                    struct storage_server *backup =
                        nm_get_server(&ctx->state, file->backup_index);
                    if (server_is_available(backup)) {
                        file->ss_index = file->backup_index;
                        file->backup_index = -1;
                        log_event(ctx,
                                  "failover file=%s newPrimary=%s due to server=%d down",
                                  file->name,
                                  backup->id,
                                  server_index);
                        file_dirty = 1;
                    } else {
                        drop_backup_only(ctx, file, "backup unavailable during failover");
                        log_event(ctx,
                                  "file=%s has no replicas after server=%d down",
                                  file->name,
                                  server_index);
                        file_dirty = 1;
                    }
                } else {
                    log_event(ctx,
                              "file=%s primary offline server=%d and no backup",
                              file->name,
                              server_index);
                    file_dirty = 1;
                }
            }
            if (file->backup_index == server_index) {
                drop_backup_only(ctx, file, "backup server disconnected");
                file_dirty = 1;
            }
            if (file_dirty) {
                state_dirty = 1;
                if (file->backup_index < 0 && file->ss_index >= 0 &&
                    has_backup_candidate(ctx, file->ss_index)) {
                    if (pending_count < NM_MAX_FILES) {
                        strncpy(pending_backup[pending_count], file->name, NM_MAX_NAME - 1);
                        pending_backup[pending_count][NM_MAX_NAME - 1] = '\0';
                        pending_count++;
                    }
                }
            }
        }
        if (state_dirty) {
            nm_state_save(&ctx->state);
        }
        pthread_mutex_unlock(&ctx->state_lock);
        for (size_t i = 0; i < pending_count; ++i) {
            try_assign_backup(ctx, pending_backup[i]);
        }
    }
}

static int file_has_access(struct file_entry *file, const char *user, int perm) {
    if (!user || !user[0]) {
        errno = EACCES;
        return -1;
    }
    if (strcmp(file->owner, user) == 0) {
        return 0;
    }
    for (size_t i = 0; i < file->acl_count; ++i) {
        if (strcmp(file->acl[i].user, user) == 0) {
            if ((file->acl[i].perm & perm) == perm) {
                return 0;
            }
            errno = EACCES;
            return -1;
        }
    }
    errno = EACCES;
    return -1;
}

static int valid_checkpoint_tag(const char *tag) {
    if (!tag || !tag[0]) {
        return 0;
    }
    for (const unsigned char *p = (const unsigned char *)tag; *p; ++p) {
        if (*p == '.' && (p == (const unsigned char *)tag || *(p + 1) == '.')) {
            return 0;
        }
        if (*p == '/' || *p == '\\') {
            return 0;
        }
        if (*p < 32 || *p > 126) {
            return 0;
        }
    }
    return 1;
}

static int forward_to_available_server(struct nm_context *ctx,
                                       struct storage_server *primary,
                                       struct storage_server *backup,
                                       const char *payload,
                                       char **response_out) {
    if (primary && primary->ctrl_fd >= 0) {
        if (forward_command(ctx, primary, payload, response_out) == 0) {
            return 0;
        }
    }
    if (backup && backup != primary && backup->ctrl_fd >= 0) {
        if (forward_command(ctx, backup, payload, response_out) == 0) {
            return 0;
        }
    }
    return -1;
}

static struct access_request *find_access_request(struct nm_state *state,
                                                 const char *file,
                                                 const char *requester) {
    if (!state || !file || !requester) {
        return NULL;
    }
    for (size_t i = 0; i < state->request_count; ++i) {
        struct access_request *req = &state->requests[i];
        if (strcmp(req->file, file) == 0 && strcmp(req->requester, requester) == 0) {
            return req;
        }
    }
    return NULL;
}

static const char *access_request_status_label(int status) {
    switch (status) {
        case NM_REQUEST_PENDING:
            return "PENDING";
        case NM_REQUEST_APPROVED:
            return "APPROVED";
        case NM_REQUEST_DENIED:
            return "DENIED";
        default:
            return "UNKNOWN";
    }
}

static const char *access_request_type_label(int perm) {
    if (perm & NM_PERM_WRITE) {
        return "WRITE";
    }
    return "READ";
}

static int json_append(char *buf, size_t buf_size, int *offset, const char *fmt, ...) {
    if (*offset < 0) {
        return -1;
    }
    va_list ap;
    va_start(ap, fmt);
    int written = vsnprintf(buf + *offset, buf_size - (size_t)*offset, fmt, ap);
    va_end(ap);
    if (written < 0 || (size_t)written >= buf_size - (size_t)*offset) {
        *offset = -1;
        return -1;
    }
    *offset += written;
    return 0;
}

static int append_access_array(char *buf,
                               size_t buf_size,
                               int *offset,
                               const char *key,
                               struct file_entry *file,
                               int perm) {
    if (json_append(buf, buf_size, offset, "\"%s\":[", key) < 0) {
        return -1;
    }
    char user_esc[256];
    if (json_escape_string(user_esc, sizeof(user_esc), file->owner) < 0) {
        return -1;
    }
    if (json_append(buf, buf_size, offset, "\"%s\"", user_esc) < 0) {
        return -1;
    }
    for (size_t i = 0; i < file->acl_count; ++i) {
        struct file_acl_entry *acl = &file->acl[i];
        if ((acl->perm & perm) != perm) {
            continue;
        }
        if (json_escape_string(user_esc, sizeof(user_esc), acl->user) < 0) {
            return -1;
        }
        if (json_append(buf, buf_size, offset, ",\"%s\"", user_esc) < 0) {
            return -1;
        }
    }
    if (json_append(buf, buf_size, offset, "]") < 0) {
        return -1;
    }
    return 0;
}

static int handle_client_view(struct nm_context *ctx, struct peer *p, const char *json) {
    char flags[8] = "";
    json_get_string(json, "flags", flags, sizeof(flags));
    int show_all = strchr(flags, 'a') != NULL;
    int long_format = strchr(flags, 'l') != NULL;

    char extra[MAX_JSON];
    int offset = 0;
    json_append(extra, sizeof(extra), &offset, "\"files\":[");
    int first = 1;
    STATE_LOCK(ctx);
    for (size_t i = 0; i < ctx->state.file_count; ++i) {
        struct file_entry *file = &ctx->state.files[i];
        int accessible = show_all || (file_has_access(file, p->user, NM_PERM_READ) == 0);
        errno = 0; /* reset for subsequent checks */
        if (!accessible) {
            continue;
        }
        if (!first) {
            json_append(extra, sizeof(extra), &offset, ",");
        }
        first = 0;
        char name_esc[256];
        char owner_esc[256];
        char last_user_esc[256];
        if (json_escape_string(name_esc, sizeof(name_esc), file->name) < 0 ||
            json_escape_string(owner_esc, sizeof(owner_esc), file->owner) < 0 ||
            json_escape_string(last_user_esc, sizeof(last_user_esc), file->last_access_user) < 0) {
            return send_error_response(p->fd, ERR_INTERNAL, "encoding error");
        }
        char primary_id[256] = "";
        char backup_id[256] = "";
        const char *primary_status = "none";
        const char *backup_status = "none";
        struct storage_server *primary = (file->ss_index >= 0)
                                           ? nm_get_server(&ctx->state, file->ss_index)
                                           : NULL;
        struct storage_server *backup = (file->backup_index >= 0)
                                          ? nm_get_server(&ctx->state, file->backup_index)
                                          : NULL;
        if (primary) {
            json_escape_string(primary_id, sizeof(primary_id), primary->id);
            primary_status = server_is_available(primary) ? "online" : "offline";
        } else if (file->ss_index >= 0) {
            primary_status = "unknown";
        }
        if (backup) {
            json_escape_string(backup_id, sizeof(backup_id), backup->id);
            backup_status = server_is_available(backup) ? "online" : "offline";
        } else if (file->backup_index >= 0) {
            backup_status = "unknown";
        }
        if (long_format) {
            json_append(extra, sizeof(extra), &offset,
                        "{\"name\":\"%s\",\"owner\":\"%s\",\"words\":%zu,",
                        name_esc, owner_esc, file->word_count);
            json_append(extra, sizeof(extra), &offset,
                        "\"chars\":%zu,\"lastAccess\":%ld,\"lastAccessUser\":\"%s\",",
                        file->char_count, (long)file->last_access, last_user_esc);
            json_append(extra, sizeof(extra), &offset,
                        "\"primaryServer\":\"%s\",\"primaryStatus\":\"%s\","
                        "\"backupServer\":\"%s\",\"backupStatus\":\"%s\"}",
                        primary_id[0] ? primary_id : "",
                        primary_status,
                        backup_id[0] ? backup_id : "",
                        backup_status);
        } else {
            json_append(extra, sizeof(extra), &offset, "{\"name\":\"%s\"}", name_esc);
        }
    }
    json_append(extra, sizeof(extra), &offset, "]");
    if (offset < 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_INTERNAL, "response too large");
    }
    STATE_UNLOCK(ctx);
    log_request(ctx, "VIEW user=%s flags=%s", p->user, flags);
    return send_ok(p->fd, extra);
}

static int handle_client_list_users(struct nm_context *ctx, struct peer *p) {
    char extra[MAX_JSON];
    int offset = 0;
    json_append(extra, sizeof(extra), &offset, "\"users\":[");
    STATE_LOCK(ctx);
    for (size_t i = 0; i < ctx->state.user_count; ++i) {
        char user_esc[256];
        if (json_escape_string(user_esc, sizeof(user_esc), ctx->state.users[i].name) < 0) {
            STATE_UNLOCK(ctx);
            return send_error_response(p->fd, ERR_INTERNAL, "encoding error");
        }
        if (i > 0) {
            json_append(extra, sizeof(extra), &offset, ",");
        }
        json_append(extra, sizeof(extra), &offset, "\"%s\"", user_esc);
    }
    json_append(extra, sizeof(extra), &offset, "]");
    if (offset < 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_INTERNAL, "response too large");
    }
    STATE_UNLOCK(ctx);
    log_request(ctx, "LIST user=%s", p->user);
    return send_ok(p->fd, extra);
}

static int handle_client_info(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing file");
    }
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (file_has_access(file, p->user, NM_PERM_READ) != 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOAUTH, "no read access");
    }
    char name_esc[256];
    char owner_esc[256];
    char last_user_esc[256];
    if (json_escape_string(name_esc, sizeof(name_esc), file->name) < 0 ||
        json_escape_string(owner_esc, sizeof(owner_esc), file->owner) < 0 ||
        json_escape_string(last_user_esc, sizeof(last_user_esc), file->last_access_user) < 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_INTERNAL, "encoding error");
    }
    char primary_id[256] = "";
    char backup_id[256] = "";
    const char *primary_status = "none";
    const char *backup_status = "none";
    struct storage_server *primary = (file->ss_index >= 0)
                                       ? nm_get_server(&ctx->state, file->ss_index)
                                       : NULL;
    struct storage_server *backup = (file->backup_index >= 0)
                                      ? nm_get_server(&ctx->state, file->backup_index)
                                      : NULL;
    if (primary) {
        json_escape_string(primary_id, sizeof(primary_id), primary->id);
        primary_status = server_is_available(primary) ? "online" : "offline";
    } else if (file->ss_index >= 0) {
        primary_status = "unknown";
    }
    if (backup) {
        json_escape_string(backup_id, sizeof(backup_id), backup->id);
        backup_status = server_is_available(backup) ? "online" : "offline";
    } else if (file->backup_index >= 0) {
        backup_status = "unknown";
    }
    char extra[MAX_JSON];
    int offset = 0;
    json_append(extra, sizeof(extra), &offset,
                "\"file\":{\"name\":\"%s\",\"owner\":\"%s\",\"words\":%zu,",
                name_esc, owner_esc, file->word_count);
    json_append(extra, sizeof(extra), &offset,
                "\"chars\":%zu,\"created\":%ld,\"modified\":%ld,",
                file->char_count, (long)file->created, (long)file->modified);
    json_append(extra, sizeof(extra), &offset,
                "\"lastAccess\":%ld,\"lastAccessUser\":\"%s\",",
                (long)file->last_access, last_user_esc);
    if (json_append(extra, sizeof(extra), &offset,
                    "\"primaryServer\":\"%s\",\"primaryStatus\":\"%s\","\
                    "\"backupServer\":\"%s\",\"backupStatus\":\"%s\",",
                    primary_id[0] ? primary_id : "",
                    primary_status,
                    backup_id[0] ? backup_id : "",
                    backup_status) < 0 ||
        append_access_array(extra, sizeof(extra), &offset, "readAccess", file, NM_PERM_READ) < 0 ||
        json_append(extra, sizeof(extra), &offset, ",") < 0 ||
        append_access_array(extra, sizeof(extra), &offset, "writeAccess", file, NM_PERM_WRITE) < 0 ||
        json_append(extra, sizeof(extra), &offset, "}") < 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_INTERNAL, "response too large");
    }
    if (offset < 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_INTERNAL, "response too large");
    }
    log_request(ctx, "INFO user=%s file=%s", p->user, file->name);
    int rc = send_ok(p->fd, extra);
    STATE_UNLOCK(ctx);
    return rc;
}

static int handle_client_create(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing file");
    }
    if (!valid_filename(file_name)) {
        return send_error_response(p->fd, ERR_BADREQ, "invalid name");
    }
    if (!p->user[0]) {
        return send_error_response(p->fd, ERR_NOAUTH, "anonymous user");
    }
    STATE_LOCK(ctx);
    struct file_entry *existing = nm_find_file(&ctx->state, file_name);
    if (existing) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_EXISTS, "file exists");
    }
    int ss_index = nm_pick_server(&ctx->state);
    if (ss_index < 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_UNAVAILABLE, "no storage server");
    }
    struct storage_server *ss = nm_get_server(&ctx->state, ss_index);
    if (!ss || ss->ctrl_fd < 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_UNAVAILABLE, "server offline");
    }
    STATE_UNLOCK(ctx);
    if (!ss || ss->ctrl_fd < 0) {
        return send_error_response(p->fd, ERR_UNAVAILABLE, "server offline");
    }
    char payload[512];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"NM_CREATE\",\"file\":\"%s\",\"owner\":\"%s\"}",
                 file_name, p->user) >= (int)sizeof(payload)) {
        return send_error_response(p->fd, ERR_INTERNAL, "payload too large");
    }
    char *response = NULL;
    if (forward_command(ctx, ss, payload, &response) < 0) {
        free(response);
        STATE_LOCK(ctx);
        nm_mark_server_down(&ctx->state, ss_index);
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_UNAVAILABLE, "server unreachable");
    }
    char status[16];
    int ok = (json_get_string(response, "status", status, sizeof(status)) == 0) &&
             strcmp(status, "OK") == 0;
    free(response);
    if (!ok) {
        return send_error_response(p->fd, ERR_INTERNAL, "create failed");
    }
    time_t now = time(NULL);
    int backup_index = -1;
    STATE_LOCK(ctx);
    size_t server_count = ctx->state.server_count;
    STATE_UNLOCK(ctx);
    for (size_t i = 0; i < server_count; ++i) {
        if ((int)i == ss_index) {
            continue;
        }
        STATE_LOCK(ctx);
        struct storage_server *backup = nm_get_server(&ctx->state, (int)i);
        STATE_UNLOCK(ctx);
        if (!server_is_available(backup)) {
            continue;
        }
        char *backup_resp = NULL;
        char backup_status[16] = "";
        if (forward_command(ctx, backup, payload, &backup_resp) < 0) {
            log_event(ctx, "BACKUP create unreachable file=%s server=%s",
                      file_name, backup->id);
            free(backup_resp);
            continue;
        }
        if (parse_status(backup_resp, backup_status, sizeof(backup_status), NULL, 0) == 0 &&
            strcmp(backup_status, "OK") == 0) {
            backup_index = (int)i;
            free(backup_resp);
            break;
        }
        log_event(ctx, "BACKUP create failed file=%s server=%s status=%s",
                  file_name, backup->id,
                  backup_status[0] ? backup_status : "unknown");
        free(backup_resp);
    }
    STATE_LOCK(ctx);
    if (nm_add_file(&ctx->state, file_name, p->user, ss_index, backup_index, now) < 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_INTERNAL, "state update failed");
    }
    nm_grant_access(&ctx->state, file_name, p->user, NM_PERM_WRITE | NM_PERM_READ);
    nm_cache_put(&ctx->state, file_name, ss_index);
    nm_state_save(&ctx->state);
    STATE_UNLOCK(ctx);
    log_request(ctx, "CREATE user=%s file=%s", p->user, file_name);
    return send_ok(p->fd, "\"op\":\"CREATE\"");
}

static int handle_client_delete(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing file");
    }
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (file_has_access(file, p->user, NM_PERM_WRITE) != 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOAUTH, "no write access");
    }
    int ss_index = -1;
    struct storage_server *ss = select_storage_server(ctx, file, &ss_index);
    if (!ss) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_UNAVAILABLE, "server offline");
    }
    ss = select_storage_server(ctx, file, &ss_index);
    STATE_UNLOCK(ctx);
    char payload[256];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"NM_DELETE\",\"file\":\"%s\"}", file_name) >=
        (int)sizeof(payload)) {
        return send_error_response(p->fd, ERR_INTERNAL, "payload too large");
    }
    char *response = NULL;
    if (forward_command(ctx, ss, payload, &response) < 0) {
        free(response);
        STATE_LOCK(ctx);
        nm_mark_server_down(&ctx->state, ss_index);
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_UNAVAILABLE, "server unreachable");
    }
    char status[16];
    int ok = (json_get_string(response, "status", status, sizeof(status)) == 0) &&
             strcmp(status, "OK") == 0;
    free(response);
    if (!ok) {
        return send_error_response(p->fd, ERR_INTERNAL, "delete failed");
    }
    int backup_index = file->backup_index;
    nm_remove_file(&ctx->state, file_name);
    STATE_UNLOCK(ctx);
    if (backup_index >= 0) {
        struct storage_server *backup = nm_get_server(&ctx->state, backup_index);
        if (backup && backup->ctrl_fd >= 0) {
            char *backup_resp = NULL;
            if (forward_command(ctx, backup, payload, &backup_resp) < 0) {
                log_event(ctx, "BACKUP delete failed file=%s server=%d", file_name, backup_index);
            }
            free(backup_resp);
        }
    }
    nm_state_save(&ctx->state);
    log_request(ctx, "DELETE user=%s file=%s", p->user, file_name);
    return send_ok(p->fd, "\"op\":\"DELETE\"");
}

static int respond_with_endpoint(struct peer *p,
                                 const char *file_name,
                                 struct storage_server *ss,
                                 const char *op,
                                 const char *token,
                                 int sentence_index) {
    char host_esc[256];
    char port_esc[64];
    char server_id_esc[256];
    char file_esc[256];
    char token_esc[256];
    if (json_escape_string(host_esc, sizeof(host_esc), ss->host) < 0 ||
        json_escape_string(port_esc, sizeof(port_esc), ss->data_port) < 0 ||
        json_escape_string(server_id_esc, sizeof(server_id_esc), ss->id) < 0 ||
        json_escape_string(file_esc, sizeof(file_esc), file_name ? file_name : "") < 0 ||
        json_escape_string(token_esc, sizeof(token_esc), token) < 0) {
        return send_error_response(p->fd, ERR_INTERNAL, "encoding error");
    }
    char extra[MAX_JSON];
    int offset = 0;
    json_append(extra, sizeof(extra), &offset,
                "\"op\":\"%s\",\"file\":\"%s\",\"host\":\"%s\",\"port\":\"%s\",",
                op, file_esc, host_esc, port_esc);
    json_append(extra, sizeof(extra), &offset,
                "\"server\":\"%s\",\"ticket\":\"%s\"", server_id_esc, token_esc);
    if (sentence_index >= 0) {
        json_append(extra, sizeof(extra), &offset, ",\"sentence\":%d", sentence_index);
    }
    if (offset < 0) {
        return send_error_response(p->fd, ERR_INTERNAL, "response too large");
    }
    return send_ok(p->fd, extra);
}

static int server_is_available(const struct storage_server *ss) {
    return ss && ss->ctrl_fd >= 0 && ss->online;
}

static int has_backup_candidate(const struct nm_context *ctx, int primary_index) {
    for (size_t i = 0; i < ctx->state.server_count; ++i) {
        if ((int)i == primary_index) {
            continue;
        }
        const struct storage_server *ss = ctx->state.servers + i;
        if (server_is_available(ss)) {
            return 1;
        }
    }
    return 0;
}

static void drop_backup_only(struct nm_context *ctx, struct file_entry *file, const char *reason) {
    if (!file || file->backup_index < 0) {
        return;
    }
    int old_index = file->backup_index;
    const char *server_id = "unknown";
    struct storage_server *ss = nm_get_server(&ctx->state, old_index);
    if (ss && ss->id[0]) {
        server_id = ss->id;
    }
    log_event(ctx,
              "dropping backup for file=%s server=%s(idx=%d) (%s)",
              file->name,
              server_id,
              old_index,
              reason ? reason : "reason unknown");
    file->backup_index = -1;
}

static void drop_file_backup(struct nm_context *ctx, struct file_entry *file, const char *reason) {
    drop_backup_only(ctx, file, reason);
    nm_state_save(&ctx->state);
}

static struct storage_server *select_storage_server(struct nm_context *ctx,
                                                   struct file_entry *file,
                                                   int *server_index_out) {
    if (!file) {
        return NULL;
    }
    if (file->ss_index >= 0) {
        struct storage_server *ss = nm_get_server(&ctx->state, file->ss_index);
        if (server_is_available(ss)) {
            if (server_index_out) {
                *server_index_out = file->ss_index;
            }
            log_event(ctx, "select_storage_server primary ok file=%s server=%d",
                      file->name, file->ss_index);
            return ss;
        } else if (ss && !ss->online) {
            log_event(ctx, "primary offline for file=%s server=%s", file->name, ss->id);
        }
    }
    if (file->backup_index >= 0) {
        struct storage_server *backup = nm_get_server(&ctx->state, file->backup_index);
        if (server_is_available(backup)) {
            file->ss_index = file->backup_index;
            file->backup_index = -1;
            nm_state_save(&ctx->state);
            log_event(ctx, "failover file=%s server=%s", file->name, backup->id);
            if (server_index_out) {
                *server_index_out = file->ss_index;
            }
            return backup;
        } else {
            drop_file_backup(ctx, file, "backup offline during selection");
            log_event(ctx, "select_storage_server backup offline file=%s idx=%d",
                      file->name, file->backup_index);
        }
    }
    /*
     * If we reach here, neither the primary nor the existing backup is
     * currently reachable. Do NOT silently remap the file to a different
     * server because that server would not have the file’s data. Leave the
     * mapping untouched so callers can surface ERR_UNAVAILABLE and the
     * replication logic can explicitly reassign once a fresh copy exists.
     */
    log_event(ctx,
              "select_storage_server no replicas online for file=%s (primary=%d, backup=%d)",
              file->name,
              file->ss_index,
              file->backup_index);
    return NULL;
}

static int obtain_ticket_for_file(struct nm_context *ctx,
                                  const char *file_name,
                                  const char *user,
                                  int required_perm,
                                  const char *op,
                                  char *token_out,
                                  int *ss_index_out,
                                  struct storage_server **ss_out) {
    if (token_out) {
        token_out[0] = '\0';
    }
    for (int attempt = 0; attempt < 2; ++attempt) {
        log_event(ctx, "TICKET attempt=%d file=%s user=%s op=%s", attempt, file_name, user, op);
        STATE_LOCK(ctx);
        struct file_entry *file = nm_find_file(&ctx->state, file_name);
        if (!file) {
            STATE_UNLOCK(ctx);
            return ERR_NOTFOUND;
        }
        if (file_has_access(file, user, required_perm) != 0) {
            STATE_UNLOCK(ctx);
            return ERR_NOAUTH;
        }
        int ss_index = -1;
        struct storage_server *ss = select_storage_server(ctx, file, &ss_index);
        if (!ss) {
            STATE_UNLOCK(ctx);
            return ERR_UNAVAILABLE;
        }
        STATE_UNLOCK(ctx);
        if (issue_ticket(ctx, ss, ss_index, file_name, user, op, token_out) == 0) {
            STATE_LOCK(ctx);
            nm_cache_put(&ctx->state, file_name, ss_index);
            STATE_UNLOCK(ctx);
            if (ss_index_out) {
                *ss_index_out = ss_index;
            }
            if (ss_out) {
                *ss_out = ss;
            }
            log_event(ctx, "TICKET success file=%s user=%s server=%d", file_name, user, ss_index);
            return 0;
        }
        STATE_LOCK(ctx);
        nm_mark_server_down(&ctx->state, ss_index);
        STATE_UNLOCK(ctx);
        log_event(ctx, "ticket failure, retrying backup for file=%s", file_name);
    }
    log_event(ctx, "TICKET failed file=%s user=%s", file_name, user);
    return ERR_UNAVAILABLE;
}

static int handle_lookup_common(struct nm_context *ctx,
                                struct peer *p,
                                const char *json,
                                const char *op,
                                int required_perm,
                                int include_sentence) {
    char file_name[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing file");
    }
    char token[64];
    int ss_index = -1;
    struct storage_server *ss = NULL;
    int rc = obtain_ticket_for_file(ctx, file_name, p->user, required_perm, op, token, &ss_index, &ss);
    if (rc != 0 || !ss) {
        return send_error_response(p->fd,
                                   (rc == ERR_NOAUTH) ? ERR_NOAUTH :
                                   (rc == ERR_NOTFOUND) ? ERR_NOTFOUND :
                                                          ERR_UNAVAILABLE,
                                   (rc == ERR_NOAUTH)
                                       ? "access denied"
                                       : (rc == ERR_NOTFOUND) ? "file not found" : "server offline");
    }
    int sentence = -1;
    if (include_sentence) {
        if (json_get_int(json, "sentence", &sentence) < 0) {
            sentence = 0;
        }
    }
    log_request(ctx, "%s user=%s file=%s", op, p->user, file_name);
    return respond_with_endpoint(p, file_name, ss, op, token, sentence);
}

static int handle_client_read(struct nm_context *ctx, struct peer *p, const char *json) {
    return handle_lookup_common(ctx, p, json, "READ", NM_PERM_READ, 0);
}

static int handle_client_stream(struct nm_context *ctx, struct peer *p, const char *json) {
    return handle_lookup_common(ctx, p, json, "STREAM", NM_PERM_READ, 0);
}

static int handle_client_write(struct nm_context *ctx, struct peer *p, const char *json) {
    return handle_lookup_common(ctx, p, json, "WRITE", NM_PERM_WRITE, 1);
}

static int handle_client_addaccess(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    char target[NM_MAX_USER];
    char mode[8];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0 ||
        json_get_string(json, "user", target, sizeof(target)) < 0 ||
        json_get_string(json, "mode", mode, sizeof(mode)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing fields");
    }
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (strcmp(file->owner, p->user) != 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOAUTH, "only owner");
    }
    int perm = NM_PERM_READ;
    if (strchr(mode, 'W') || strchr(mode, 'w')) {
        perm |= NM_PERM_WRITE;
    }
    int rc = nm_grant_access(&ctx->state, file_name, target, perm);
    if (rc < 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_INTERNAL, "grant failed");
    }
    nm_state_save(&ctx->state);
    STATE_UNLOCK(ctx);
    log_request(ctx, "ADDACCESS owner=%s file=%s user=%s mode=%s", p->user, file_name, target, mode);
    return send_ok(p->fd, "\"op\":\"ADDACCESS\"");
}

static int handle_client_removeaccess(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    char target[NM_MAX_USER];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0 ||
        json_get_string(json, "user", target, sizeof(target)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing fields");
    }
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (strcmp(file->owner, p->user) != 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOAUTH, "only owner");
    }
    nm_remove_access(&ctx->state, file_name, target);
    nm_state_save(&ctx->state);
    STATE_UNLOCK(ctx);
    log_request(ctx, "REMACCESS owner=%s file=%s user=%s", p->user, file_name, target);
    return send_ok(p->fd, "\"op\":\"REMACCESS\"");
}

static int handle_client_reqaccess(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    char mode[8];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0 ||
        json_get_string(json, "mode", mode, sizeof(mode)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing fields");
    }
    int has_flag = 0;
    int perm = NM_PERM_READ;
    if (strchr(mode, 'R') || strchr(mode, 'r')) {
        has_flag = 1;
    }
    if (strchr(mode, 'W') || strchr(mode, 'w')) {
        perm |= NM_PERM_WRITE;
        has_flag = 1;
    }
    if (!has_flag) {
        return send_error_response(p->fd, ERR_BADREQ, "invalid mode");
    }
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (strcmp(file->owner, p->user) == 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_CONFLICT, "owner already has access");
    }
    if (nm_check_access(&ctx->state, file_name, p->user, perm) == 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_CONFLICT, "access already granted");
    }
    struct access_request *req = find_access_request(&ctx->state, file_name, p->user);
    if (!req) {
        if (ctx->state.request_count >= NM_MAX_REQUESTS) {
            STATE_UNLOCK(ctx);
            return send_error_response(p->fd, ERR_INTERNAL, "request limit reached");
        }
        req = &ctx->state.requests[ctx->state.request_count++];
        memset(req, 0, sizeof(*req));
        snprintf(req->file, sizeof(req->file), "%s", file_name);
        snprintf(req->requester, sizeof(req->requester), "%s", p->user);
    }
    snprintf(req->owner, sizeof(req->owner), "%s", file->owner);
    req->perm = perm;
    req->status = NM_REQUEST_PENDING;
    nm_state_save(&ctx->state);
    STATE_UNLOCK(ctx);
    log_request(ctx, "REQACCESS requester=%s file=%s owner=%s mode=%s", p->user, file_name, file->owner, mode);
    return send_ok(p->fd, "\"op\":\"REQACCESS\"");
}

static int handle_client_viewreqs(struct nm_context *ctx, struct peer *p, const char *json) {
    char direction[16];
    if (json_get_string(json, "direction", direction, sizeof(direction)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing direction");
    }
    int want_sent = (strcasecmp(direction, "SENT") == 0);
    int want_received = (strcasecmp(direction, "RECEIVED") == 0);
    if (!want_sent && !want_received) {
        return send_error_response(p->fd, ERR_BADREQ, "invalid direction");
    }
    char extra[MAX_JSON];
    int offset = 0;
    json_append(extra, sizeof(extra), &offset, "\"requests\":[");
    int first = 1;
    STATE_LOCK(ctx);
    for (size_t i = 0; i < ctx->state.request_count; ++i) {
        struct access_request *req = &ctx->state.requests[i];
        if (want_sent) {
            if (strcmp(req->requester, p->user) != 0) {
                continue;
            }
        } else {
            if (strcmp(req->owner, p->user) != 0 || req->status != NM_REQUEST_PENDING) {
                continue;
            }
        }
        if (!first) {
            json_append(extra, sizeof(extra), &offset, ",");
        }
        first = 0;
        char file_esc[256];
        if (json_escape_string(file_esc, sizeof(file_esc), req->file) < 0) {
            STATE_UNLOCK(ctx);
            return send_error_response(p->fd, ERR_INTERNAL, "encoding error");
        }
        const char *access = access_request_type_label(req->perm);
        if (want_sent) {
            const char *status = access_request_status_label(req->status);
            if (json_append(extra, sizeof(extra), &offset,
                            "{\"file\":\"%s\",\"access\":\"%s\",\"status\":\"%s\"}",
                            file_esc, access, status) < 0) {
                break;
            }
        } else {
            char user_esc[256];
            if (json_escape_string(user_esc, sizeof(user_esc), req->requester) < 0) {
                STATE_UNLOCK(ctx);
                return send_error_response(p->fd, ERR_INTERNAL, "encoding error");
            }
            if (json_append(extra, sizeof(extra), &offset,
                            "{\"file\":\"%s\",\"access\":\"%s\",\"user\":\"%s\"}",
                            file_esc, access, user_esc) < 0) {
                break;
            }
        }
    }
    json_append(extra, sizeof(extra), &offset, "]");
    if (offset < 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_INTERNAL, "response too large");
    }
    STATE_UNLOCK(ctx);
    log_request(ctx, "VIEWREQS user=%s direction=%s", p->user, direction);
    return send_ok(p->fd, extra);
}

static int handle_client_handlereq(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    char requester[NM_MAX_USER];
    char action[16];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0 ||
        json_get_string(json, "user", requester, sizeof(requester)) < 0 ||
        json_get_string(json, "action", action, sizeof(action)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing fields");
    }
    int approve = (strcasecmp(action, "APPROVE") == 0);
    int deny = (strcasecmp(action, "DENY") == 0);
    if (!approve && !deny) {
        return send_error_response(p->fd, ERR_BADREQ, "invalid action");
    }
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (strcmp(file->owner, p->user) != 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOAUTH, "only owner");
    }
    struct access_request *req = find_access_request(&ctx->state, file_name, requester);
    if (!req) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "request not found");
    }
    if (req->status != NM_REQUEST_PENDING) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_CONFLICT, "request already handled");
    }
    if (approve) {
        if (nm_grant_access(&ctx->state, file_name, requester, req->perm) < 0) {
            STATE_UNLOCK(ctx);
            return send_error_response(p->fd, ERR_INTERNAL, "grant failed");
        }
        req->status = NM_REQUEST_APPROVED;
    } else {
        req->status = NM_REQUEST_DENIED;
    }
    nm_state_save(&ctx->state);
    STATE_UNLOCK(ctx);
    log_request(ctx, "HANDLEREQ owner=%s file=%s requester=%s action=%s", p->user, file_name, requester, action);
    return send_ok(p->fd, "\"op\":\"HANDLEREQ\"");
}

static int handle_client_undo(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing file");
    }
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (file_has_access(file, p->user, NM_PERM_WRITE) != 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOAUTH, "no write access");
    }
    int ss_index = -1;
    struct storage_server *ss = select_storage_server(ctx, file, &ss_index);
    if (!ss) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_UNAVAILABLE, "server offline");
    }
    STATE_UNLOCK(ctx);
    char payload[512];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"NM_UNDO\",\"file\":\"%s\",\"user\":\"%s\"}",
                 file_name, p->user) >= (int)sizeof(payload)) {
        return send_error_response(p->fd, ERR_INTERNAL, "payload too large");
    }
    char *response = NULL;
    if (forward_command(ctx, ss, payload, &response) < 0) {
        free(response);
        STATE_LOCK(ctx);
        nm_mark_server_down(&ctx->state, ss_index);
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_UNAVAILABLE, "server unreachable");
    }
    char status[16];
    int ok = (json_get_string(response, "status", status, sizeof(status)) == 0) &&
             strcmp(status, "OK") == 0;
    if (!ok) {
        log_event(ctx, "UNDO failure response: %s", response ? response : "<null>");
        send_error_response(p->fd, ERR_CONFLICT, "undo not possible");
    } else {
        send_ok(p->fd, "\"op\":\"UNDO\"");
    }
    free(response);
    log_request(ctx, "UNDO user=%s file=%s", p->user, file_name);
    return 0;
}

static int handle_client_exec(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing file");
    }
    char token[64];
    int ss_index = -1;
    struct storage_server *ss = NULL;
    int rc = obtain_ticket_for_file(ctx, file_name, p->user, NM_PERM_READ, "READ", token, &ss_index, &ss);
    if (rc != 0 || !ss) {
        return send_error_response(p->fd,
                                   (rc == ERR_NOTFOUND) ? ERR_NOTFOUND
                                                        : (rc == ERR_NOAUTH) ? ERR_NOAUTH : ERR_UNAVAILABLE,
                                   (rc == ERR_NOAUTH)
                                       ? "no read access"
                                       : (rc == ERR_NOTFOUND) ? "file not found" : "server offline");
    }
    char *content = NULL;
    if (ss_fetch_content(ss, file_name, p->user, token, &content) < 0) {
        return send_error_response(p->fd, ERR_UNAVAILABLE, "fetch failed");
    }

    char *output = NULL;
    if (run_exec_commands(content, &output) < 0) {
        free(content);
        return send_error_response(p->fd, ERR_INTERNAL, "exec failed");
    }
    free(content);

    char *escaped = json_escape_dup(output);
    free(output);
    if (!escaped) {
        return send_error_response(p->fd, ERR_INTERNAL, "encode failed");
    }
    char extra[MAX_JSON];
    if (snprintf(extra, sizeof(extra), "\"op\":\"EXEC\",\"output\":\"%s\"", escaped) >=
        (int)sizeof(extra)) {
        free(escaped);
        return send_error_response(p->fd, ERR_INTERNAL, "response too large");
    }
    free(escaped);
    log_request(ctx, "EXEC user=%s file=%s", p->user, file_name);
    return send_ok(p->fd, extra);
}

static int handle_client_checkpoint(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    char tag[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0 ||
        json_get_string(json, "tag", tag, sizeof(tag)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing fields");
    }
    if (!valid_checkpoint_tag(tag)) {
        return send_error_response(p->fd, ERR_BADREQ, "invalid tag");
    }
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (file_has_access(file, p->user, NM_PERM_WRITE) != 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOAUTH, "no write access");
    }
    if (nm_file_find_checkpoint(file, tag)) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_EXISTS, "checkpoint exists");
    }
    int primary_index = file->ss_index;
    int backup_index = file->backup_index;
    STATE_UNLOCK(ctx);

    if (primary_index < 0) {
        return send_error_response(p->fd, ERR_UNAVAILABLE, "primary offline");
    }
    struct storage_server *primary = nm_get_server(&ctx->state, primary_index);
    if (!primary || primary->ctrl_fd < 0) {
        return send_error_response(p->fd, ERR_UNAVAILABLE, "primary offline");
    }

    char file_esc[NM_MAX_NAME * 2];
    char tag_esc[NM_MAX_NAME * 2];
    char user_esc[NM_MAX_USER * 2];
    if (json_escape_string(file_esc, sizeof(file_esc), file_name) < 0 ||
        json_escape_string(tag_esc, sizeof(tag_esc), tag) < 0 ||
        json_escape_string(user_esc, sizeof(user_esc), p->user) < 0) {
        return send_error_response(p->fd, ERR_INTERNAL, "encoding error");
    }
    char payload[MAX_JSON];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"NM_CHECKPOINT_CREATE\",\"file\":\"%s\",\"tag\":\"%s\",\"user\":\"%s\"}",
                 file_esc, tag_esc, user_esc) >= (int)sizeof(payload)) {
        return send_error_response(p->fd, ERR_INTERNAL, "payload too large");
    }

    char *response = NULL;
    if (forward_command(ctx, primary, payload, &response) < 0) {
        free(response);
        return send_error_response(p->fd, ERR_UNAVAILABLE, "primary unreachable");
    }
    char status[16];
    if (json_get_string(response, "status", status, sizeof(status)) < 0 || strcmp(status, "OK") != 0) {
        log_event(ctx, "CHECKPOINT primary failed file=%s status=%s",
                  file_name, status[0] ? status : "unknown");
        free(response);
        return send_error_response(p->fd, ERR_INTERNAL, "checkpoint failed");
    }
    free(response);

    STATE_LOCK(ctx);
    file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "file missing");
    }
    if (nm_file_find_checkpoint(file, tag)) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_EXISTS, "checkpoint exists");
    }
    time_t now = time(NULL);
    if (nm_file_add_checkpoint(&ctx->state, file_name, tag, p->user, now) < 0) {
        int err = errno;
        STATE_UNLOCK(ctx);
        if (err == ENOSPC) {
            return send_error_response(p->fd, ERR_INTERNAL, "checkpoint limit reached");
        }
        return send_error_response(p->fd, ERR_INTERNAL, "checkpoint metadata failed");
    }
    nm_state_save(&ctx->state);
    STATE_UNLOCK(ctx);

    log_request(ctx, "CHECKPOINT user=%s file=%s tag=%s", p->user, file_name, tag);

    if (backup_index >= 0) {
        struct storage_server *backup = nm_get_server(&ctx->state, backup_index);
        if (backup && backup != primary && backup->ctrl_fd >= 0) {
            char *backup_resp = NULL;
            if (forward_command(ctx, backup, payload, &backup_resp) < 0) {
                log_event(ctx, "CHECKPOINT backup unreachable file=%s server=%s", file_name, backup->id);
            } else {
                char backup_status[16];
                if (json_get_string(backup_resp, "status", backup_status, sizeof(backup_status)) < 0 ||
                    strcmp(backup_status, "OK") != 0) {
                    log_event(ctx, "CHECKPOINT backup failed file=%s server=%s status=%s",
                              file_name, backup->id,
                              backup_status[0] ? backup_status : "unknown");
                }
                free(backup_resp);
            }
        }
    }

    return send_ok(p->fd, "\"op\":\"CHECKPOINT\"");
}

static int handle_client_viewcheckpoint(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    char tag[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0 ||
        json_get_string(json, "tag", tag, sizeof(tag)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing fields");
    }
    if (!valid_checkpoint_tag(tag)) {
        return send_error_response(p->fd, ERR_BADREQ, "invalid tag");
    }
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (file_has_access(file, p->user, NM_PERM_READ) != 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOAUTH, "no read access");
    }
    if (!nm_file_find_checkpoint(file, tag)) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "checkpoint not found");
    }
    int primary_index = file->ss_index;
    int backup_index = file->backup_index;
    STATE_UNLOCK(ctx);

    struct storage_server *primary = (primary_index >= 0) ? nm_get_server(&ctx->state, primary_index) : NULL;
    struct storage_server *backup = (backup_index >= 0) ? nm_get_server(&ctx->state, backup_index) : NULL;
    if (!primary && !backup) {
        return send_error_response(p->fd, ERR_UNAVAILABLE, "no storage available");
    }

    char file_esc[NM_MAX_NAME * 2];
    char tag_esc[NM_MAX_NAME * 2];
    char user_esc[NM_MAX_USER * 2];
    if (json_escape_string(file_esc, sizeof(file_esc), file_name) < 0 ||
        json_escape_string(tag_esc, sizeof(tag_esc), tag) < 0 ||
        json_escape_string(user_esc, sizeof(user_esc), p->user) < 0) {
        return send_error_response(p->fd, ERR_INTERNAL, "encoding error");
    }
    char payload[MAX_JSON];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"NM_CHECKPOINT_VIEW\",\"file\":\"%s\",\"tag\":\"%s\",\"user\":\"%s\"}",
                 file_esc, tag_esc, user_esc) >= (int)sizeof(payload)) {
        return send_error_response(p->fd, ERR_INTERNAL, "payload too large");
    }

    char *response = NULL;
    if (forward_to_available_server(ctx, primary, backup, payload, &response) < 0) {
        free(response);
        return send_error_response(p->fd, ERR_UNAVAILABLE, "checkpoint unavailable");
    }
    char status[16];
    if (json_get_string(response, "status", status, sizeof(status)) < 0 || strcmp(status, "OK") != 0) {
        free(response);
        return send_error_response(p->fd, ERR_INTERNAL, "checkpoint view failed");
    }
    char *content = NULL;
    if (json_get_string_alloc(response, "content", &content) < 0) {
        free(response);
        return send_error_response(p->fd, ERR_INTERNAL, "missing content");
    }
    free(response);

    char *escaped = json_escape_dup(content);
    free(content);
    if (!escaped) {
        return send_error_response(p->fd, ERR_INTERNAL, "encoding error");
    }
    char extra[MAX_JSON];
    if (snprintf(extra, sizeof(extra), "\"content\":\"%s\"", escaped) >= (int)sizeof(extra)) {
        free(escaped);
        return send_error_response(p->fd, ERR_INTERNAL, "response too large");
    }
    free(escaped);
    log_request(ctx, "VIEWCHECKPOINT user=%s file=%s tag=%s", p->user, file_name, tag);
    return send_ok(p->fd, extra);
}

static int handle_client_revert(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    char tag[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0 ||
        json_get_string(json, "tag", tag, sizeof(tag)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing fields");
    }
    if (!valid_checkpoint_tag(tag)) {
        return send_error_response(p->fd, ERR_BADREQ, "invalid tag");
    }
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (file_has_access(file, p->user, NM_PERM_WRITE) != 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOAUTH, "no write access");
    }
    if (!nm_file_find_checkpoint(file, tag)) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "checkpoint not found");
    }
    int primary_index = file->ss_index;
    int backup_index = file->backup_index;
    STATE_UNLOCK(ctx);

    if (primary_index < 0) {
        return send_error_response(p->fd, ERR_UNAVAILABLE, "primary offline");
    }
    struct storage_server *primary = nm_get_server(&ctx->state, primary_index);
    if (!primary || primary->ctrl_fd < 0) {
        return send_error_response(p->fd, ERR_UNAVAILABLE, "primary offline");
    }

    char file_esc[NM_MAX_NAME * 2];
    char tag_esc[NM_MAX_NAME * 2];
    char user_esc[NM_MAX_USER * 2];
    if (json_escape_string(file_esc, sizeof(file_esc), file_name) < 0 ||
        json_escape_string(tag_esc, sizeof(tag_esc), tag) < 0 ||
        json_escape_string(user_esc, sizeof(user_esc), p->user) < 0) {
        return send_error_response(p->fd, ERR_INTERNAL, "encoding error");
    }
    char payload[MAX_JSON];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"NM_CHECKPOINT_REVERT\",\"file\":\"%s\",\"tag\":\"%s\",\"user\":\"%s\"}",
                 file_esc, tag_esc, user_esc) >= (int)sizeof(payload)) {
        return send_error_response(p->fd, ERR_INTERNAL, "payload too large");
    }

    char *response = NULL;
    if (forward_command(ctx, primary, payload, &response) < 0) {
        free(response);
        return send_error_response(p->fd, ERR_UNAVAILABLE, "primary unreachable");
    }
    char status[16];
    if (json_get_string(response, "status", status, sizeof(status)) < 0 || strcmp(status, "OK") != 0) {
        log_event(ctx, "REVERT primary failed file=%s status=%s", file_name, status[0] ? status : "unknown");
        free(response);
        return send_error_response(p->fd, ERR_INTERNAL, "revert failed");
    }
    free(response);

    if (backup_index >= 0) {
        struct storage_server *backup = nm_get_server(&ctx->state, backup_index);
        if (backup && backup != primary && backup->ctrl_fd >= 0) {
            char *backup_resp = NULL;
            if (forward_command(ctx, backup, payload, &backup_resp) < 0) {
                log_event(ctx, "REVERT backup unreachable file=%s server=%s", file_name, backup->id);
            } else {
                char backup_status[16];
                if (json_get_string(backup_resp, "status", backup_status, sizeof(backup_status)) < 0 ||
                    strcmp(backup_status, "OK") != 0) {
                    log_event(ctx, "REVERT backup failed file=%s server=%s status=%s",
                              file_name, backup->id,
                              backup_status[0] ? backup_status : "unknown");
                }
                free(backup_resp);
            }
        }
    }

    log_request(ctx, "REVERT user=%s file=%s tag=%s", p->user, file_name, tag);
    return send_ok(p->fd, "\"op\":\"REVERT\"");
}

static int handle_client_listcheckpoints(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing file");
    }
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (file_has_access(file, p->user, NM_PERM_READ) != 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_NOAUTH, "no read access");
    }
    char file_esc[NM_MAX_NAME * 2];
    if (json_escape_string(file_esc, sizeof(file_esc), file_name) < 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_INTERNAL, "encoding error");
    }
    char extra[MAX_JSON];
    int offset = 0;
    if (json_append(extra, sizeof(extra), &offset, "\"file\":\"%s\",\"checkpoints\":[", file_esc) < 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_INTERNAL, "response too large");
    }
    for (size_t i = 0; i < file->checkpoint_count; ++i) {
        struct checkpoint_entry *entry = &file->checkpoints[i];
        char tag_esc[NM_MAX_NAME * 2];
        char user_esc[NM_MAX_USER * 2];
        char ts_buf[32];
        if (json_escape_string(tag_esc, sizeof(tag_esc), entry->tag) < 0 ||
            json_escape_string(user_esc, sizeof(user_esc), entry->user) < 0) {
            STATE_UNLOCK(ctx);
            return send_error_response(p->fd, ERR_INTERNAL, "encoding error");
        }
        if (snprintf(ts_buf, sizeof(ts_buf), "%ld", (long)entry->timestamp) < 0) {
            STATE_UNLOCK(ctx);
            return send_error_response(p->fd, ERR_INTERNAL, "timestamp error");
        }
        if (i > 0) {
            if (json_append(extra, sizeof(extra), &offset, ",") < 0) {
                STATE_UNLOCK(ctx);
                return send_error_response(p->fd, ERR_INTERNAL, "response too large");
            }
        }
        if (json_append(extra, sizeof(extra), &offset,
                        "{\"tag\":\"%s\",\"user\":\"%s\",\"timestamp\":\"%s\"}",
                        tag_esc, user_esc, ts_buf) < 0) {
            STATE_UNLOCK(ctx);
            return send_error_response(p->fd, ERR_INTERNAL, "response too large");
        }
    }
    if (json_append(extra, sizeof(extra), &offset, "]") < 0) {
        STATE_UNLOCK(ctx);
        return send_error_response(p->fd, ERR_INTERNAL, "response too large");
    }
    STATE_UNLOCK(ctx);
    log_request(ctx, "LISTCHECKPOINTS user=%s file=%s", p->user, file_name);
    return send_ok(p->fd, extra);
}

static int handle_client_message(struct nm_context *ctx, struct peer *p, const char *json) {
    char type[64];
    if (json_get_string(json, "type", type, sizeof(type)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing type");
    }
    if (strcmp(type, "VIEW") == 0) {
        return handle_client_view(ctx, p, json);
    }
    if (strcmp(type, "LIST") == 0) {
        return handle_client_list_users(ctx, p);
    }
    if (strcmp(type, "INFO") == 0) {
        return handle_client_info(ctx, p, json);
    }
    if (strcmp(type, "CREATE") == 0) {
        return handle_client_create(ctx, p, json);
    }
    if (strcmp(type, "DELETE") == 0) {
        return handle_client_delete(ctx, p, json);
    }
    if (strcmp(type, "READ") == 0) {
        return handle_client_read(ctx, p, json);
    }
    if (strcmp(type, "WRITE") == 0) {
        return handle_client_write(ctx, p, json);
    }
    if (strcmp(type, "STREAM") == 0) {
        return handle_client_stream(ctx, p, json);
    }
    if (strcmp(type, "CHECKPOINT") == 0) {
        return handle_client_checkpoint(ctx, p, json);
    }
    if (strcmp(type, "VIEWCHECKPOINT") == 0) {
        return handle_client_viewcheckpoint(ctx, p, json);
    }
    if (strcmp(type, "REVERT") == 0) {
        return handle_client_revert(ctx, p, json);
    }
    if (strcmp(type, "LISTCHECKPOINTS") == 0) {
        return handle_client_listcheckpoints(ctx, p, json);
    }
    if (strcmp(type, "ADDACCESS") == 0) {
        return handle_client_addaccess(ctx, p, json);
    }
    if (strcmp(type, "REMACCESS") == 0) {
        return handle_client_removeaccess(ctx, p, json);
    }
    if (strcmp(type, "REQACCESS") == 0) {
        return handle_client_reqaccess(ctx, p, json);
    }
    if (strcmp(type, "VIEWREQS") == 0) {
        return handle_client_viewreqs(ctx, p, json);
    }
    if (strcmp(type, "HANDLEREQ") == 0) {
        return handle_client_handlereq(ctx, p, json);
    }
    if (strcmp(type, "UNDO") == 0) {
        return handle_client_undo(ctx, p, json);
    }
    if (strcmp(type, "EXEC") == 0) {
        return handle_client_exec(ctx, p, json);
    }
    if (strcmp(type, "CLIENT_EXIT") == 0) {
        log_request(ctx, "CLIENT_EXIT user=%s", p->user);
        int rc = send_ok(p->fd, "\"op\":\"EXIT\"");
        if (rc < 0) {
            return -1;
        }
        return -1;
    }
    return send_error_response(p->fd, ERR_BADREQ, "unsupported type");
}

static int replicate_file_to_backup(struct nm_context *ctx, const char *file_name, const char *owner, int primary_index, int backup_index) {
    if (!file_name || !owner || primary_index < 0 || backup_index < 0 || primary_index == backup_index) {
        return -1;
    }
    struct storage_server *primary = nm_get_server(&ctx->state, primary_index);
    struct storage_server *backup = nm_get_server(&ctx->state, backup_index);
    if (!server_is_available(primary) || !server_is_available(backup)) {
        // log_event(ctx, "BACKUP sync skipped, unavailable server file=%s", file_name);
        return -1;
    }

    char ticket[64];
    if (issue_ticket(ctx, primary, primary_index, file_name, owner, "READ", ticket) < 0) {
        log_event(ctx, "BACKUP sync ticket failed file=%s", file_name);
        return -1;
    }

    char file_esc[NM_MAX_NAME * 2];
    char owner_esc[NM_MAX_USER * 2];
    char host_esc[256];
    char port_esc[64];
    char ticket_esc[64];
    if (json_escape_string(file_esc, sizeof(file_esc), file_name) < 0 ||
        json_escape_string(owner_esc, sizeof(owner_esc), owner) < 0 ||
        json_escape_string(host_esc, sizeof(host_esc), primary->host) < 0 ||
        json_escape_string(port_esc, sizeof(port_esc), primary->data_port) < 0 ||
        json_escape_string(ticket_esc, sizeof(ticket_esc), ticket) < 0) {
        return -1;
    }

    char payload[MAX_JSON];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"NM_SYNC\",\"file\":\"%s\",\"owner\":\"%s\","
                 "\"sourceHost\":\"%s\",\"sourcePort\":\"%s\",\"ticket\":\"%s\"}",
                 file_esc, owner_esc, host_esc, port_esc, ticket_esc) >= (int)sizeof(payload)) {
        return -1;
    }

    char *response = NULL;
    int rc = forward_command(ctx, backup, payload, &response);
    if (rc < 0) {
        log_event(ctx, "BACKUP sync unreachable file=%s server=%d", file_name, backup_index);
        free(response);
        return -1;
    }
    char status[16] = "ERR";
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 ||
        strcmp(status, "OK") != 0) {
        log_event(ctx, "BACKUP sync error file=%s server=%d status=%s",
                  file_name, backup_index, status);
        free(response);
        return -1;
    }

    log_event(ctx, "BACKUP sync succeeded file=%s server=%d", file_name, backup_index);
    free(response);
    return 0;
}

static void try_assign_backup(struct nm_context *ctx, const char *file_name) {
    if (!ctx || !file_name || !file_name[0]) {
        return;
    }
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file || file->backup_index >= 0 || file->ss_index < 0) {
        STATE_UNLOCK(ctx);
        return;
    }
    int primary_index = file->ss_index;
    char owner[NM_MAX_USER];
    snprintf(owner, sizeof(owner), "%s", file->owner);
    STATE_UNLOCK(ctx);
    schedule_replication(ctx, file_name, owner, primary_index, -1, 1);
}

static int schedule_replication(struct nm_context *ctx,
                                const char *file_name,
                                const char *owner,
                                int primary_index,
                                int backup_index,
                                int assign_mode) {
    if (!ctx || !file_name || !file_name[0] || !owner) {
        errno = EINVAL;
        return -1;
    }
    if (primary_index < 0) {
        errno = EINVAL;
        return -1;
    }
    if (!assign_mode && backup_index < 0) {
        errno = EINVAL;
        return -1;
    }
    struct replication_task task;
    memset(&task, 0, sizeof(task));
    snprintf(task.file, sizeof(task.file), "%s", file_name);
    snprintf(task.owner, sizeof(task.owner), "%s", owner);
    task.primary_index = primary_index;
    task.backup_index = backup_index;
    task.assign_mode = assign_mode ? 1 : 0;
    pthread_mutex_lock(&ctx->replication_lock);
    for (size_t i = 0; i < ctx->replication_queue.len; ++i) {
        struct replication_task *existing = array_get(&ctx->replication_queue, i);
        if (!existing) {
            continue;
        }
        if (strcmp(existing->file, task.file) != 0) {
            continue;
        }
        if (existing->assign_mode && task.assign_mode) {
            pthread_mutex_unlock(&ctx->replication_lock);
            return 0;
        }
        if (!existing->assign_mode && !task.assign_mode &&
            existing->primary_index == task.primary_index &&
            existing->backup_index == task.backup_index) {
            pthread_mutex_unlock(&ctx->replication_lock);
            return 0;
        }
    }
    int rc = array_push(&ctx->replication_queue, &task);
    if (rc == 0) {
        pthread_cond_signal(&ctx->replication_cond);
    }
    pthread_mutex_unlock(&ctx->replication_lock);
    return rc;
}

static void handle_replication_failure(struct nm_context *ctx,
                                       const struct replication_task *task,
                                       int attempted_backup) {
    if (!ctx || !task) {
        return;
    }
    int need_assign = task->assign_mode ? 1 : 0;
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, task->file);
    if (file && !task->assign_mode && file->backup_index == attempted_backup) {
        drop_file_backup(ctx, file, "backup sync error");
        if (file->backup_index < 0 && file->ss_index >= 0) {
            need_assign = 1;
        }
    }
    STATE_UNLOCK(ctx);
    if (need_assign) {
        try_assign_backup(ctx, task->file);
    }
}

static void *replication_worker(void *arg) {
    struct nm_context *ctx = arg;
    if (!ctx) {
        return NULL;
    }
    while (1) {
        struct replication_task task;
        int have_task = 0;
        pthread_mutex_lock(&ctx->replication_lock);
        while (!ctx->shutting_down && ctx->replication_queue.len == 0) {
            pthread_cond_wait(&ctx->replication_cond, &ctx->replication_lock);
        }
        if (ctx->shutting_down) {
            pthread_mutex_unlock(&ctx->replication_lock);
            break;
        }
        struct replication_task *entry = array_get(&ctx->replication_queue, 0);
        if (entry) {
            task = *entry;
            array_remove(&ctx->replication_queue, 0);
            have_task = 1;
        }
        pthread_mutex_unlock(&ctx->replication_lock);
        if (!have_task) {
            continue;
        }
        char owner[NM_MAX_USER];
        owner[0] = '\0';
        int current_primary = -1;
        STATE_LOCK(ctx);
        struct file_entry *file = nm_find_file(&ctx->state, task.file);
        if (file) {
            current_primary = file->ss_index;
            snprintf(owner, sizeof(owner), "%s", file->owner);
        }
        STATE_UNLOCK(ctx);
        if (current_primary < 0 || current_primary != task.primary_index) {
            continue;
        }
        if (!task.assign_mode) {
            STATE_LOCK(ctx);
            struct file_entry *check = nm_find_file(&ctx->state, task.file);
            if (!check || check->backup_index != task.backup_index) {
                STATE_UNLOCK(ctx);
                continue;
            }
            STATE_UNLOCK(ctx);
        }
        int target_backup = task.backup_index;
        if (task.assign_mode) {
            STATE_LOCK(ctx);
            target_backup = -1;
            for (size_t i = 0; i < ctx->state.server_count; ++i) {
                if ((int)i == current_primary) {
                    continue;
                }
                struct storage_server *candidate = nm_get_server(&ctx->state, (int)i);
                if (server_is_available(candidate)) {
                    target_backup = (int)i;
                    break;
                }
            }
            STATE_UNLOCK(ctx);
            if (target_backup < 0) {
                log_event(ctx, "no backup candidates for file=%s", task.file);
                continue;
            }
        }
        if (replicate_file_to_backup(ctx, task.file, owner, current_primary, target_backup) != 0) {
            handle_replication_failure(ctx, &task, target_backup);
            continue;
        }
        STATE_LOCK(ctx);
        struct file_entry *updated = nm_find_file(&ctx->state, task.file);
        if (updated && updated->ss_index == current_primary) {
            if (task.assign_mode) {
                updated->backup_index = target_backup;
                nm_state_save(&ctx->state);
                log_event(ctx, "assigned backup file=%s server=%d", task.file, target_backup);
            }
        }
        STATE_UNLOCK(ctx);
    }
    return NULL;
}

static void handle_ss_file_update(struct nm_context *ctx, const char *json) {
    char file_name[NM_MAX_NAME];
    char last_user[NM_MAX_USER];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0) {
        return;
    }
    size_t words = 0;
    size_t chars = 0;
    long modified = 0;
    long last_access = 0;
    int tmp = 0;
    json_get_string(json, "lastAccessUser", last_user, sizeof(last_user));
    if (json_get_int(json, "words", &tmp) == 0 && tmp >= 0) {
        words = (size_t)tmp;
    }
    if (json_get_int(json, "chars", &tmp) == 0 && tmp >= 0) {
        chars = (size_t)tmp;
    }
    if (json_get_int(json, "modified", &tmp) == 0) {
        modified = (long)tmp;
    }
    if (json_get_int(json, "lastAccess", &tmp) == 0) {
        last_access = (long)tmp;
    }
    int need_assign = 0;
    int need_sync = 0;
    int primary_index = -1;
    int backup_index = -1;
    char owner[NM_MAX_USER];
    owner[0] = '\0';
    STATE_LOCK(ctx);
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        STATE_UNLOCK(ctx);
        return;
    }
    time_t prev_modified = file->modified;
    nm_update_file_metadata(&ctx->state,
                            file_name,
                            words,
                            chars,
                            (time_t)modified,
                            (time_t)last_access,
                            last_user);
    nm_state_save(&ctx->state);
    snprintf(owner, sizeof(owner), "%s", file->owner);
    primary_index = file->ss_index;
    backup_index = file->backup_index;
    need_sync = (file->modified != prev_modified && backup_index >= 0);
    if (file->backup_index < 0 && file->ss_index >= 0) {
        need_assign = has_backup_candidate(ctx, file->ss_index);
    }
    STATE_UNLOCK(ctx);
    if (need_sync) {
        if (schedule_replication(ctx, file_name, owner, primary_index, backup_index, 0) < 0) {
            log_event(ctx, "failed to enqueue replication for file=%s", file_name);
            struct replication_task failure_task;
            memset(&failure_task, 0, sizeof(failure_task));
            snprintf(failure_task.file, sizeof(failure_task.file), "%s", file_name);
            snprintf(failure_task.owner, sizeof(failure_task.owner), "%s", owner);
            failure_task.primary_index = primary_index;
            failure_task.backup_index = backup_index;
            failure_task.assign_mode = 0;
            handle_replication_failure(ctx, &failure_task, backup_index);
        }
    } else if (need_assign) {
        schedule_replication(ctx, file_name, owner, primary_index, -1, 1);
    }
}

static int handle_server_message(struct nm_context *ctx, const char *json) {
    char type[64];
    if (json_get_string(json, "type", type, sizeof(type)) < 0) {
        return -1;
    }
    if (strcmp(type, "SS_FILE_UPDATE") == 0) {
        handle_ss_file_update(ctx, json);
        return 0;
    }
    return -1;
}

static int handle_ss_register(struct nm_context *ctx, struct peer *p, const char *json) {
    char id[64];
    char host[64];
    char ctrl_port[16];
    char data_port[16];
    if (json_get_string(json, "ssId", id, sizeof(id)) < 0 ||
        json_get_string(json, "host", host, sizeof(host)) < 0 ||
        json_get_string(json, "ctrlPort", ctrl_port, sizeof(ctrl_port)) < 0 ||
        json_get_string(json, "dataPort", data_port, sizeof(data_port)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "invalid register payload");
    }
    int idx = nm_register_server(&ctx->state, id, host, ctrl_port, data_port, p->fd);
    if (idx < 0) {
        return send_error_response(p->fd, ERR_INTERNAL, "too many servers");
    }
    p->type = PEER_SERVER;
    p->server_index = idx;
    log_event(ctx, "registered server %s (%s:%s data %s)", id, host, ctrl_port, data_port);
    int rc = send_ok(p->fd, "\"role\":\"SS\"");
    if (rc == 0) {
        for (size_t i = 0; i < ctx->state.file_count; ++i) {
            struct file_entry *file = &ctx->state.files[i];
            if (file->backup_index < 0) {
        try_assign_backup(ctx, file->name);
            }
        }
    }
    return rc;
}

static int handle_handshake(struct nm_context *ctx, struct peer *p, const char *json) {
    char type[64];
    if (json_get_string(json, "type", type, sizeof(type)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing type");
    }
    if (strcmp(type, "SS_REGISTER") == 0) {
        return handle_ss_register(ctx, p, json);
    }
    if (strcmp(type, "CLIENT_HELLO") == 0) {
        char requested_user[NM_MAX_USER];
        if (json_get_string(json, "user", requested_user, sizeof(requested_user)) < 0) {
            return send_error_response(p->fd, ERR_BADREQ, "missing user");
        }
        log_event(ctx, "CLIENT_HELLO requested_user=%s", requested_user);
        if (username_in_use(ctx, requested_user)) {
            log_event(ctx, "CLIENT_HELLO user in use=%s", requested_user);
            return send_error_response(p->fd, ERR_CONFLICT, "username already in use");
        }
        if (active_user_add(ctx, requested_user) < 0) {
            return send_error_response(p->fd, ERR_INTERNAL, "failed to register user");
        }
        snprintf(p->user, sizeof(p->user), "%s", requested_user);
        nm_add_user(&ctx->state, p->user);
        p->type = PEER_CLIENT;
        p->server_index = -1;
        log_event(ctx, "CLIENT_HELLO success user=%s", p->user);
        return send_ok(p->fd, "\"role\":\"CLIENT\"");
    }
    return send_error_response(p->fd, ERR_BADREQ, "unknown handshake");
}

static int dispatch_message(struct nm_context *ctx, struct peer *p, const char *json) {
    if (!ctx || !p || !json) {
        return -1;
    }
    if (p->type == PEER_UNKNOWN) {
        log_event(ctx, "DISPATCH peer=%d UNKNOWN json=%s", p->index, json);
        return handle_handshake(ctx, p, json);
    }
    if (p->type == PEER_CLIENT) {
        log_event(ctx, "DISPATCH peer=%d CLIENT json=%s", p->index, json);
        return handle_client_message(ctx, p, json);
    }
    if (p->type == PEER_SERVER) {
        log_event(ctx, "DISPATCH peer=%d SERVER json=%s", p->index, json);
        return handle_server_message(ctx, json);
    }
    log_event(ctx, "DISPATCH peer=%d invalid type=%d", p->index, p->type);
    return -1;
}

static void *peer_thread_main(void *arg) {
    struct peer_thread_arg *info = arg;
    if (!info) {
        return NULL;
    }
    struct nm_context *ctx = info->ctx;
    int index = info->index;
    free(info);
    if (!ctx || index < 0 || index >= MAX_PEERS) {
        return NULL;
    }
    struct peer *p = &ctx->peers[index];
    log_event(ctx, "PEER[%d] worker started thread=%lu", index, (unsigned long)pthread_self());
    while (!ctx->shutting_down) {
        char *json = NULL;
        if (net_recv_json(p->fd, &json) < 0) {
            log_event(ctx, "PEER[%d] net_recv failed", index);
            free(json);
            pthread_mutex_lock(&p->io_lock);
            if (p->rpc_waiting) {
                p->rpc_waiting = 0;
                if (p->rpc_response) {
                    free(p->rpc_response);
                    p->rpc_response = NULL;
                }
                pthread_cond_broadcast(&p->io_cond);
            }
            pthread_mutex_unlock(&p->io_lock);
            handle_server_disconnect(ctx, p);
            peer_close(ctx, p);
            break;
        }
        char type_buf[64];
        if (json_get_string(json, "type", type_buf, sizeof(type_buf)) == 0) {
            if (dispatch_message(ctx, p, json) < 0) {
                log_event(ctx, "PEER[%d] dispatch failed; closing", index);
                free(json);
                handle_server_disconnect(ctx, p);
                peer_close(ctx, p);
                break;
            }
            free(json);
        } else {
            pthread_mutex_lock(&p->io_lock);
            if (p->rpc_waiting) {
                p->rpc_response = json;
                p->rpc_waiting = 0;
                pthread_cond_signal(&p->io_cond);
                pthread_mutex_unlock(&p->io_lock);
            } else {
                pthread_mutex_unlock(&p->io_lock);
                free(json);
            }
        }
    }
    pthread_mutex_lock(&ctx->peer_lock);
    p->thread_active = 0;
    pthread_mutex_unlock(&ctx->peer_lock);
    log_event(ctx, "PEER[%d] worker exiting", index);
    peer_reset(ctx, p);
    return NULL;
}

static void *ticket_prune_worker(void *arg) {
    struct nm_context *ctx = arg;
    if (!ctx) {
        return NULL;
    }
    while (!ctx->shutting_down) {
        sleep(1);
        ticket_prune(ctx);
    }
    return NULL;
}

static struct peer *find_server_peer(struct nm_context *ctx, int ctrl_fd) {
    struct peer *result = NULL;
    pthread_mutex_lock(&ctx->peer_lock);
    for (int i = 0; i < MAX_PEERS; ++i) {
        struct peer *p = &ctx->peers[i];
        if (p->type == PEER_SERVER && p->fd == ctrl_fd && p->fd >= 0) {
            result = p;
            break;
        }
    }
    pthread_mutex_unlock(&ctx->peer_lock);
    return result;
}

static void close_context(struct nm_context *ctx) {
    if (!ctx) {
        return;
    }
    ctx->shutting_down = 1;
    if (ctx->locks_ready) {
        pthread_mutex_lock(&ctx->replication_lock);
        pthread_cond_broadcast(&ctx->replication_cond);
        pthread_mutex_unlock(&ctx->replication_lock);
    }
    if (ctx->listen_fd >= 0) {
        net_close(ctx->listen_fd);
        ctx->listen_fd = -1;
    }
    for (int i = 0; i < MAX_PEERS; ++i) {
        pthread_mutex_lock(&ctx->peer_lock);
        struct peer *p = &ctx->peers[i];
        pthread_t tid = p->thread;
        int join_needed = p->thread_active;
        if (p->fd >= 0) {
            net_close(p->fd);
            p->fd = -1;
        }
        pthread_mutex_unlock(&ctx->peer_lock);
        if (join_needed) {
            pthread_join(tid, NULL);
        }
        peer_reset(ctx, p);
    }
    if (ctx->prune_thread_running) {
        pthread_join(ctx->prune_thread, NULL);
        ctx->prune_thread_running = 0;
    }
    if (ctx->replication_thread_running) {
        pthread_join(ctx->replication_thread, NULL);
        ctx->replication_thread_running = 0;
    }
    array_free(&ctx->tickets);
    array_free(&ctx->active_users);
    array_free(&ctx->replication_queue);
    log_close(&ctx->log_general);
    log_close(&ctx->log_requests);
    nm_state_save(&ctx->state);
    nm_state_destroy(&ctx->state);
    destroy_context_locks(ctx);
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <listen_port> [state_file]\n", argv[0]);
        return 1;
    }
    const char *port = argv[1];
    const char *state_path = (argc == 3) ? argv[2] : DEFAULT_STATE_PATH;

    struct nm_context *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        perror("calloc");
        return 1;
    }
    ctx->listen_fd = -1;
    int exit_code = 0;

    nm_state_init(&ctx->state, state_path);
    array_init(&ctx->tickets, sizeof(struct ticket_entry));
    array_init(&ctx->active_users, sizeof(struct active_user));
    array_init(&ctx->replication_queue, sizeof(struct replication_task));

    if (init_context_locks(ctx) < 0) {
        fprintf(stderr, "Failed to initialize NM locks\n");
        exit_code = 1;
        goto cleanup;
    }

    if (log_open(&ctx->log_general, LOG_GENERAL_PATH) < 0 ||
        log_open(&ctx->log_requests, LOG_REQUESTS_PATH) < 0) {
        fprintf(stderr, "Failed to open log files\n");
        exit_code = 1;
        goto cleanup;
    }

    g_nm_ctx = ctx;

    if (init_context_locks(ctx) < 0) {
        fprintf(stderr, "Failed to initialize NM locks\n");
        exit_code = 1;
        goto cleanup;
    }

    ctx->listen_fd = net_listen(port, 64);
    if (ctx->listen_fd < 0) {
        perror("net_listen");
        exit_code = 1;
        goto cleanup;
    }

    for (int i = 0; i < MAX_PEERS; ++i) {
        if (peer_slot_setup(&ctx->peers[i]) < 0) {
            fprintf(stderr, "Failed to initialize peer slot\n");
            exit_code = 1;
            goto cleanup;
        }
    }
    ctx->shutting_down = 0;
    ctx->prune_thread_running = 0;
    log_event(ctx, "Name server listening on %s", port);

    if (pthread_create(&ctx->prune_thread, NULL, ticket_prune_worker, ctx) == 0) {
        ctx->prune_thread_running = 1;
    } else {
        log_event(ctx, "failed to start ticket prune thread");
    }
    if (pthread_create(&ctx->replication_thread, NULL, replication_worker, ctx) == 0) {
        ctx->replication_thread_running = 1;
    } else {
        log_event(ctx, "failed to start replication worker");
    }

    while (!ctx->shutting_down) {
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);
        int fd = accept(ctx->listen_fd, (struct sockaddr *)&addr, &addrlen);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EBADF || errno == EINVAL) {
                break;
            }
            perror("accept");
            continue;
        }
        int slot_index = -1;
        struct peer *slot = allocate_peer(ctx, &slot_index);
        if (!slot) {
            log_event(ctx, "too many connections");
            net_close(fd);
            continue;
        }
        slot->fd = fd;
        slot->type = PEER_UNKNOWN;
        slot->server_index = -1;
        slot->user[0] = '\0';
        slot->thread_active = 1;
        struct peer_thread_arg *arg = malloc(sizeof(*arg));
        if (!arg) {
            log_event(ctx, "failed to allocate peer thread arg");
            peer_close(ctx, slot);
            peer_reset(ctx, slot);
            continue;
        }
        arg->ctx = ctx;
        arg->index = slot_index;
        if (pthread_create(&slot->thread, NULL, peer_thread_main, arg) != 0) {
            log_event(ctx, "failed to start peer thread");
            peer_close(ctx, slot);
            peer_reset(ctx, slot);
            free(arg);
            continue;
        }
    }
cleanup:
    if (ctx) {
        close_context(ctx);
        free(ctx);
    }
    return exit_code;
}
