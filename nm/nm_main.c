#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
};

struct ticket_entry {
    char token[64];
    char file[NM_MAX_NAME];
    char user[NM_MAX_USER];
    char op[16];
    time_t expiry;
    int ss_index;
};

struct nm_context {
    int listen_fd;
    int max_fd;
    struct peer peers[MAX_PEERS];
    struct nm_state state;
    struct array tickets; /* struct ticket_entry */
    struct log_writer log_general;
    struct log_writer log_requests;
};

static void peer_init(struct peer *p) {
    p->fd = -1;
    p->type = PEER_UNUSED;
    p->server_index = -1;
    p->user[0] = '\0';
}

static void peer_close(struct peer *p) {
    if (p->fd >= 0) {
        net_close(p->fd);
    }
    peer_init(p);
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
    log_appendf(&ctx->log_general, "%s", message);
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
    log_appendf(&ctx->log_requests, "%s", message);
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
    if (!message) {
        message = error_code_message(code);
    }
    if (snprintf(buf, sizeof(buf),
                 "{\"status\":\"ERR\",\"code\":\"%s\",\"message\":\"%s\"}",
                 error_code_name(code), message) >= (int)sizeof(buf)) {
        return -1;
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
static struct storage_server *select_storage_server_with_ticket(struct nm_context *ctx,
                                                                struct file_entry *file,
                                                                const char *user,
                                                                const char *op,
                                                                int *server_index_out,
                                                                char *token_out);

static void update_max_fd(struct nm_context *ctx) {
    ctx->max_fd = ctx->listen_fd;
    for (int i = 0; i < MAX_PEERS; ++i) {
        if (ctx->peers[i].type != PEER_UNUSED && ctx->peers[i].fd >= 0) {
            if (ctx->peers[i].fd > ctx->max_fd) {
                ctx->max_fd = ctx->peers[i].fd;
            }
        }
    }
}

static void ticket_prune(struct nm_context *ctx) {
    time_t now = time(NULL);
    size_t i = 0;
    while (i < ctx->tickets.len) {
        struct ticket_entry *entry = array_get(&ctx->tickets, i);
        if (entry->expiry && entry->expiry < now) {
            array_remove(&ctx->tickets, i);
        } else {
            i++;
        }
    }
}

static int forward_command(struct storage_server *ss, const char *payload, char **response_out) {
    if (net_send_json(ss->ctrl_fd, payload) < 0) {
        return -1;
    }
    if (net_recv_json(ss->ctrl_fd, response_out) < 0) {
        return -1;
    }
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
    if (forward_command(ss, payload, &response) < 0) {
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

    if (array_push(&ctx->tickets, &entry) < 0) {
        return -1;
    }
    if (token_out) {
        snprintf(token_out, 64, "%s", entry.token);
    }
    return 0;
}

static struct peer *allocate_peer(struct nm_context *ctx) {
    for (int i = 0; i < MAX_PEERS; ++i) {
        if (ctx->peers[i].type == PEER_UNUSED) {
            return &ctx->peers[i];
        }
    }
    return NULL;
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

static int run_exec_commands(const char *script, char **output) {
    char template[] = "/tmp/docspp-exec-XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0) {
        return -1;
    }
    size_t len = strlen(script);
    if (len > 0) {
        if (write(fd, script, len) != (ssize_t)len) {
            close(fd);
            unlink(template);
            return -1;
        }
    }
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
    if (p->type == PEER_SERVER && p->server_index >= 0) {
        nm_mark_server_down(&ctx->state, p->server_index);
        log_event(ctx, "server %d disconnected", p->server_index);
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

static int handle_client_view(struct nm_context *ctx, struct peer *p, const char *json) {
    char flags[8] = "";
    json_get_string(json, "flags", flags, sizeof(flags));
    int show_all = strchr(flags, 'a') != NULL;
    int long_format = strchr(flags, 'l') != NULL;

    char extra[MAX_JSON];
    int offset = 0;
    json_append(extra, sizeof(extra), &offset, "\"files\":[");
    int first = 1;
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
        struct storage_server *primary = (file->ss_index >= 0)
                                           ? nm_get_server(&ctx->state, file->ss_index)
                                           : NULL;
        struct storage_server *backup = (file->backup_index >= 0)
                                          ? nm_get_server(&ctx->state, file->backup_index)
                                          : NULL;
        if (primary) {
            json_escape_string(primary_id, sizeof(primary_id), primary->id);
        }
        if (backup) {
            json_escape_string(backup_id, sizeof(backup_id), backup->id);
        }
        if (long_format) {
            json_append(extra, sizeof(extra), &offset,
                        "{\"name\":\"%s\",\"owner\":\"%s\",\"words\":%zu,",
                        name_esc, owner_esc, file->word_count);
            json_append(extra, sizeof(extra), &offset,
                        "\"chars\":%zu,\"lastAccess\":%ld,\"lastAccessUser\":\"%s\",",
                        file->char_count, (long)file->last_access, last_user_esc);
            json_append(extra, sizeof(extra), &offset,
                        "\"primaryServer\":\"%s\",\"backupServer\":\"%s\"}",
                        primary_id[0] ? primary_id : "",
                        backup_id[0] ? backup_id : "");
        } else {
            json_append(extra, sizeof(extra), &offset, "{\"name\":\"%s\"}", name_esc);
        }
    }
    json_append(extra, sizeof(extra), &offset, "]");
    if (offset < 0) {
        return send_error_response(p->fd, ERR_INTERNAL, "response too large");
    }
    log_request(ctx, "VIEW user=%s flags=%s", p->user, flags);
    return send_ok(p->fd, extra);
}

static int handle_client_list_users(struct nm_context *ctx, struct peer *p) {
    char extra[MAX_JSON];
    int offset = 0;
    json_append(extra, sizeof(extra), &offset, "\"users\":[");
    for (size_t i = 0; i < ctx->state.user_count; ++i) {
        char user_esc[256];
        if (json_escape_string(user_esc, sizeof(user_esc), ctx->state.users[i].name) < 0) {
            return send_error_response(p->fd, ERR_INTERNAL, "encoding error");
        }
        if (i > 0) {
            json_append(extra, sizeof(extra), &offset, ",");
        }
        json_append(extra, sizeof(extra), &offset, "\"%s\"", user_esc);
    }
    json_append(extra, sizeof(extra), &offset, "]");
    if (offset < 0) {
        return send_error_response(p->fd, ERR_INTERNAL, "response too large");
    }
    log_request(ctx, "LIST user=%s", p->user);
    return send_ok(p->fd, extra);
}

static int handle_client_info(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing file");
    }
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (file_has_access(file, p->user, NM_PERM_READ) != 0) {
        return send_error_response(p->fd, ERR_NOAUTH, "no read access");
    }
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
    struct storage_server *primary = (file->ss_index >= 0)
                                       ? nm_get_server(&ctx->state, file->ss_index)
                                       : NULL;
    struct storage_server *backup = (file->backup_index >= 0)
                                      ? nm_get_server(&ctx->state, file->backup_index)
                                      : NULL;
    if (primary) {
        json_escape_string(primary_id, sizeof(primary_id), primary->id);
    }
    if (backup) {
        json_escape_string(backup_id, sizeof(backup_id), backup->id);
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
    json_append(extra, sizeof(extra), &offset,
                "\"primaryServer\":\"%s\",\"backupServer\":\"%s\"}",
                primary_id[0] ? primary_id : "",
                backup_id[0] ? backup_id : "");
    if (offset < 0) {
        return send_error_response(p->fd, ERR_INTERNAL, "response too large");
    }
    log_request(ctx, "INFO user=%s file=%s", p->user, file->name);
    return send_ok(p->fd, extra);
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
    if (nm_find_file(&ctx->state, file_name)) {
        return send_error_response(p->fd, ERR_EXISTS, "file exists");
    }
    int ss_index = nm_pick_server(&ctx->state);
    if (ss_index < 0) {
        return send_error_response(p->fd, ERR_UNAVAILABLE, "no storage server");
    }
    struct storage_server *ss = nm_get_server(&ctx->state, ss_index);
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
    if (forward_command(ss, payload, &response) < 0) {
        free(response);
        nm_mark_server_down(&ctx->state, ss_index);
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
    int backup_index = nm_pick_backup_server(&ctx->state, ss_index);
    if (backup_index >= 0) {
        struct storage_server *backup = nm_get_server(&ctx->state, backup_index);
        char *backup_resp = NULL;
        if (!backup || backup->ctrl_fd < 0 ||
            forward_command(backup, payload, &backup_resp) < 0 ||
            parse_status(backup_resp, status, sizeof(status), NULL, 0) < 0 ||
            strcmp(status, "OK") != 0) {
            log_event(ctx, "BACKUP create failed file=%s server=%d", file_name, backup_index);
            backup_index = -1;
        }
        free(backup_resp);
    }
    if (nm_add_file(&ctx->state, file_name, p->user, ss_index, backup_index, now) < 0) {
        return send_error_response(p->fd, ERR_INTERNAL, "state update failed");
    }
    nm_grant_access(&ctx->state, file_name, p->user, NM_PERM_WRITE | NM_PERM_READ);
    nm_cache_put(&ctx->state, file_name, ss_index);
    nm_state_save(&ctx->state);
    log_request(ctx, "CREATE user=%s file=%s", p->user, file_name);
    return send_ok(p->fd, "\"op\":\"CREATE\"");
}

static int handle_client_delete(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing file");
    }
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (file_has_access(file, p->user, NM_PERM_WRITE) != 0) {
        return send_error_response(p->fd, ERR_NOAUTH, "no write access");
    }
    int ss_index = -1;
    struct storage_server *ss = select_storage_server(ctx, file, &ss_index);
    if (!ss) {
        return send_error_response(p->fd, ERR_UNAVAILABLE, "server offline");
    }
    char payload[256];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"NM_DELETE\",\"file\":\"%s\"}", file_name) >=
        (int)sizeof(payload)) {
        return send_error_response(p->fd, ERR_INTERNAL, "payload too large");
    }
    char *response = NULL;
    if (forward_command(ss, payload, &response) < 0) {
        free(response);
        nm_mark_server_down(&ctx->state, ss_index);
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
    if (backup_index >= 0) {
        struct storage_server *backup = nm_get_server(&ctx->state, backup_index);
        if (backup && backup->ctrl_fd >= 0) {
            char *backup_resp = NULL;
            if (forward_command(backup, payload, &backup_resp) < 0) {
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
                                 struct file_entry *file,
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
        json_escape_string(file_esc, sizeof(file_esc), file->name) < 0 ||
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

static struct storage_server *select_storage_server(struct nm_context *ctx,
                                                   struct file_entry *file,
                                                   int *server_index_out) {
    if (!file) {
        return NULL;
    }
    if (file->ss_index >= 0) {
        struct storage_server *ss = nm_get_server(&ctx->state, file->ss_index);
        if (ss && ss->ctrl_fd >= 0 && ss->online) {
            if (server_index_out) {
                *server_index_out = file->ss_index;
            }
            return ss;
        }
    }
    if (file->backup_index >= 0) {
        struct storage_server *backup = nm_get_server(&ctx->state, file->backup_index);
        if (backup && backup->ctrl_fd >= 0 && backup->online) {
            int prev = file->ss_index;
            file->ss_index = file->backup_index;
            file->backup_index = prev;
            nm_state_save(&ctx->state);
            log_event(ctx, "failover file=%s server=%s", file->name, backup->id);
            if (server_index_out) {
                *server_index_out = file->ss_index;
            }
            return backup;
        }
    }
    return NULL;
}

static struct storage_server *select_storage_server_with_ticket(struct nm_context *ctx,
                                                                struct file_entry *file,
                                                                const char *user,
                                                                const char *op,
                                                                int *server_index_out,
                                                                char *token_out) {
    if (token_out) {
        token_out[0] = '\0';
    }
    for (int attempt = 0; attempt < 2; ++attempt) {
        int ss_index = -1;
        struct storage_server *ss = select_storage_server(ctx, file, &ss_index);
        if (!ss) {
            return NULL;
        }
        if (issue_ticket(ctx, ss, ss_index, file->name, user, op, token_out) == 0) {
            if (server_index_out) {
                *server_index_out = ss_index;
            }
            return ss;
        }
        nm_mark_server_down(&ctx->state, ss_index);
        log_event(ctx, "ticket failure, retrying backup for file=%s", file->name);
    }
    return NULL;
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
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (file_has_access(file, p->user, required_perm) != 0) {
        return send_error_response(p->fd, ERR_NOAUTH, "access denied");
    }
    char token[64];
    int ss_index = -1;
    struct storage_server *ss = select_storage_server_with_ticket(ctx,
                                                                  file,
                                                                  p->user,
                                                                  op,
                                                                  &ss_index,
                                                                  token);
    if (!ss) {
        return send_error_response(p->fd, ERR_UNAVAILABLE, "server offline");
    }
    nm_cache_put(&ctx->state, file->name, ss_index);
    int sentence = -1;
    if (include_sentence) {
        if (json_get_int(json, "sentence", &sentence) < 0) {
            sentence = 0;
        }
    }
    log_request(ctx, "%s user=%s file=%s", op, p->user, file->name);
    return respond_with_endpoint(p, file, ss, op, token, sentence);
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
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (strcmp(file->owner, p->user) != 0) {
        return send_error_response(p->fd, ERR_NOAUTH, "only owner");
    }
    int perm = NM_PERM_READ;
    if (strchr(mode, 'W') || strchr(mode, 'w')) {
        perm |= NM_PERM_WRITE;
    }
    if (nm_grant_access(&ctx->state, file_name, target, perm) < 0) {
        return send_error_response(p->fd, ERR_INTERNAL, "grant failed");
    }
    nm_state_save(&ctx->state);
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
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (strcmp(file->owner, p->user) != 0) {
        return send_error_response(p->fd, ERR_NOAUTH, "only owner");
    }
    nm_remove_access(&ctx->state, file_name, target);
    nm_state_save(&ctx->state);
    log_request(ctx, "REMACCESS owner=%s file=%s user=%s", p->user, file_name, target);
    return send_ok(p->fd, "\"op\":\"REMACCESS\"");
}

static int handle_client_undo(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing file");
    }
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (file_has_access(file, p->user, NM_PERM_WRITE) != 0) {
        return send_error_response(p->fd, ERR_NOAUTH, "no write access");
    }
    int ss_index = -1;
    struct storage_server *ss = select_storage_server(ctx, file, &ss_index);
    if (!ss) {
        return send_error_response(p->fd, ERR_UNAVAILABLE, "server offline");
    }
    char payload[512];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"NM_UNDO\",\"file\":\"%s\",\"user\":\"%s\"}",
                 file_name, p->user) >= (int)sizeof(payload)) {
        return send_error_response(p->fd, ERR_INTERNAL, "payload too large");
    }
    char *response = NULL;
    if (forward_command(ss, payload, &response) < 0) {
        free(response);
        nm_mark_server_down(&ctx->state, ss_index);
        return send_error_response(p->fd, ERR_UNAVAILABLE, "server unreachable");
    }
    char status[16];
    int ok = (json_get_string(response, "status", status, sizeof(status)) == 0) &&
             strcmp(status, "OK") == 0;
    if (!ok) {
        log_event(ctx, "UNDO failure response: %s", response ? response : "<null>");
        send_error_response(p->fd, ERR_CONFLICT, "undo failed");
    } else {
        send_ok(p->fd, "\"op\":\"UNDO\"");
    }
    free(response);
    log_request(ctx, "UNDO user=%s file=%s", p->user, file_name);
    return ok ? 0 : -1;
}

static int handle_client_exec(struct nm_context *ctx, struct peer *p, const char *json) {
    char file_name[NM_MAX_NAME];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0) {
        return send_error_response(p->fd, ERR_BADREQ, "missing file");
    }
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
        return send_error_response(p->fd, ERR_NOTFOUND, "file not found");
    }
    if (file_has_access(file, p->user, NM_PERM_READ) != 0) {
        return send_error_response(p->fd, ERR_NOAUTH, "no read access");
    }
    char token[64];
    int ss_index = -1;
    struct storage_server *ss = select_storage_server_with_ticket(ctx,
                                                                  file,
                                                                  p->user,
                                                                  "READ",
                                                                  &ss_index,
                                                                  token);
    if (!ss) {
        return send_error_response(p->fd, ERR_UNAVAILABLE, "server offline");
    }

    char *content = NULL;
    if (ss_fetch_content(ss, file->name, p->user, token, &content) < 0) {
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
    log_request(ctx, "EXEC user=%s file=%s", p->user, file->name);
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
    if (strcmp(type, "ADDACCESS") == 0) {
        return handle_client_addaccess(ctx, p, json);
    }
    if (strcmp(type, "REMACCESS") == 0) {
        return handle_client_removeaccess(ctx, p, json);
    }
    if (strcmp(type, "UNDO") == 0) {
        return handle_client_undo(ctx, p, json);
    }
    if (strcmp(type, "EXEC") == 0) {
        return handle_client_exec(ctx, p, json);
    }
    return send_error_response(p->fd, ERR_BADREQ, "unsupported type");
}

static void replicate_file_to_backup(struct nm_context *ctx, struct file_entry *file) {
    if (!file || file->backup_index < 0 || file->ss_index < 0 || file->backup_index == file->ss_index) {
        return;
    }
    struct storage_server *primary = nm_get_server(&ctx->state, file->ss_index);
    struct storage_server *backup = nm_get_server(&ctx->state, file->backup_index);
    if (!primary || !backup) {
        return;
    }
    if (primary->ctrl_fd < 0 || !primary->online || backup->ctrl_fd < 0 || !backup->online) {
        return;
    }

    char ticket[64];
    if (issue_ticket(ctx, primary, file->ss_index, file->name, file->owner, "READ", ticket) < 0) {
        log_event(ctx, "BACKUP sync ticket failed file=%s", file->name);
        return;
    }

    char *content = NULL;
    if (ss_fetch_content(primary, file->name, file->owner, ticket, &content) < 0) {
        log_event(ctx, "BACKUP fetch failed file=%s", file->name);
        return;
    }

    char file_esc[NM_MAX_NAME * 2];
    char owner_esc[NM_MAX_USER * 2];
    char host_esc[256];
    char port_esc[64];
    char ticket_esc[64];
    if (json_escape_string(file_esc, sizeof(file_esc), file->name) < 0 ||
        json_escape_string(owner_esc, sizeof(owner_esc), file->owner) < 0 ||
        json_escape_string(host_esc, sizeof(host_esc), primary->host) < 0 ||
        json_escape_string(port_esc, sizeof(port_esc), primary->data_port) < 0 ||
        json_escape_string(ticket_esc, sizeof(ticket_esc), ticket) < 0) {
        free(content);
        return;
    }

    char payload[MAX_JSON];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"NM_SYNC\",\"file\":\"%s\",\"owner\":\"%s\","
                 "\"sourceHost\":\"%s\",\"sourcePort\":\"%s\",\"ticket\":\"%s\"}",
                 file_esc, owner_esc, host_esc, port_esc, ticket_esc) >= (int)sizeof(payload)) {
        free(content);
        return;
    }

    char *response = NULL;
    if (forward_command(backup, payload, &response) < 0) {
        log_event(ctx, "BACKUP sync command failed file=%s server=%d", file->name, file->backup_index);
    } else {
        char status[16];
        if (parse_status(response, status, sizeof(status), NULL, 0) == 0 &&
            strcmp(status, "OK") == 0) {
            log_event(ctx, "BACKUP sync succeeded file=%s server=%d", file->name, file->backup_index);
        } else {
            log_event(ctx, "BACKUP sync error file=%s server=%d status=%s",
                      file->name, file->backup_index, status);
        }
    }
    free(response);
    free(content);
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
    struct file_entry *file = nm_find_file(&ctx->state, file_name);
    if (!file) {
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
    if (file->modified != prev_modified) {
        replicate_file_to_backup(ctx, file);
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
    return send_ok(p->fd, "\"role\":\"SS\"");
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
        if (json_get_string(json, "user", p->user, sizeof(p->user)) < 0) {
            return send_error_response(p->fd, ERR_BADREQ, "missing user");
        }
        nm_add_user(&ctx->state, p->user);
        p->type = PEER_CLIENT;
        p->server_index = -1;
        return send_ok(p->fd, "\"role\":\"CLIENT\"");
    }
    return send_error_response(p->fd, ERR_BADREQ, "unknown handshake");
}

static void dispatch_message(struct nm_context *ctx, struct peer *p) {
    char *json = NULL;
    if (net_recv_json(p->fd, &json) < 0) {
        handle_server_disconnect(ctx, p);
        peer_close(p);
        free(json);
        update_max_fd(ctx);
        return;
    }
    int rc = 0;
    if (p->type == PEER_UNKNOWN) {
        rc = handle_handshake(ctx, p, json);
    } else if (p->type == PEER_CLIENT) {
        rc = handle_client_message(ctx, p, json);
    } else if (p->type == PEER_SERVER) {
        rc = handle_server_message(ctx, json);
    }
    if (rc < 0) {
        handle_server_disconnect(ctx, p);
        peer_close(p);
        update_max_fd(ctx);
    }
    free(json);
}

static void close_context(struct nm_context *ctx) {
    if (!ctx) {
        return;
    }
    if (ctx->listen_fd >= 0) {
        net_close(ctx->listen_fd);
        ctx->listen_fd = -1;
    }
    for (int i = 0; i < MAX_PEERS; ++i) {
        peer_close(&ctx->peers[i]);
    }
    array_free(&ctx->tickets);
    log_close(&ctx->log_general);
    log_close(&ctx->log_requests);
    nm_state_save(&ctx->state);
    nm_state_destroy(&ctx->state);
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <listen_port> [state_file]\n", argv[0]);
        return 1;
    }
    const char *port = argv[1];
    const char *state_path = (argc == 3) ? argv[2] : DEFAULT_STATE_PATH;

    struct nm_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.listen_fd = -1;
    ctx.max_fd = -1;

    nm_state_init(&ctx.state, state_path);
    array_init(&ctx.tickets, sizeof(struct ticket_entry));

    if (log_open(&ctx.log_general, LOG_GENERAL_PATH) < 0 ||
        log_open(&ctx.log_requests, LOG_REQUESTS_PATH) < 0) {
        fprintf(stderr, "Failed to open log files\n");
        close_context(&ctx);
        return 1;
    }

    ctx.listen_fd = net_listen(port, 64);
    if (ctx.listen_fd < 0) {
        perror("net_listen");
        close_context(&ctx);
        return 1;
    }

    for (int i = 0; i < MAX_PEERS; ++i) {
        peer_init(&ctx.peers[i]);
    }
    update_max_fd(&ctx);
    log_event(&ctx, "Name server listening on %s", port);

    while (1) {
        ticket_prune(&ctx);
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(ctx.listen_fd, &readfds);
        int max_fd = ctx.max_fd;
        for (int i = 0; i < MAX_PEERS; ++i) {
            if (ctx.peers[i].type != PEER_UNUSED && ctx.peers[i].fd >= 0) {
                FD_SET(ctx.peers[i].fd, &readfds);
                if (ctx.peers[i].fd > max_fd) {
                    max_fd = ctx.peers[i].fd;
                }
            }
        }
        int ready = select(max_fd + 1, &readfds, NULL, NULL, NULL);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            break;
        }
        if (FD_ISSET(ctx.listen_fd, &readfds)) {
            struct sockaddr_storage addr;
            socklen_t addrlen = sizeof(addr);
            int fd = accept(ctx.listen_fd, (struct sockaddr *)&addr, &addrlen);
            if (fd >= 0) {
                struct peer *slot = allocate_peer(&ctx);
                if (!slot) {
                    log_event(&ctx, "too many connections");
                    net_close(fd);
                } else {
                    peer_init(slot);
                    slot->fd = fd;
                    slot->type = PEER_UNKNOWN;
                    update_max_fd(&ctx);
                }
            }
        }
        for (int i = 0; i < MAX_PEERS; ++i) {
            if (ctx.peers[i].type != PEER_UNUSED && ctx.peers[i].fd >= 0 &&
                FD_ISSET(ctx.peers[i].fd, &readfds)) {
                dispatch_message(&ctx, &ctx.peers[i]);
            }
        }
    }

    close_context(&ctx);
    return 0;
}
