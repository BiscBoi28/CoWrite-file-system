#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "common/error.h"
#include "common/json_util.h"
#include "common/log.h"
#include "common/net_proto.h"
#include "common/randutil.h"
#include "ss_state.h"

#define MAX_CONTENT_CHUNK 4096
#define MAX_TOKEN_LEN 64
#define MAX_JSON 4096
#define STREAM_DELAY_MS 100

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct auth_ticket {
    char token[64];
    char file[SS_NAME_MAX];
    char user[SS_USER_MAX];
    char op[16];
    time_t expiry;
};

struct ticket_table {
    struct array entries; /* struct auth_ticket */
};

struct sentence_lock {
    char file[SS_NAME_MAX];
    int sentence;
    char user[SS_USER_MAX];
};

struct write_session {
    int active;
    int sentence_index;
    char user[SS_USER_MAX];
    char *original_text;
    char *sentence_text;
    char *baseline_sentence;
    struct array sentences; /* char* */
};

struct ss_context {
    char id[64];
    char public_host[64];
    char ctrl_port[16];
    char data_port[16];
    int nm_fd;
    int listen_fd;
    struct ss_state state;
    struct ticket_table tickets;
    struct array sentence_locks; /* struct sentence_lock */
    struct log_writer log_general;
    struct log_writer log_requests;
    pthread_rwlock_t state_lock;
    pthread_mutex_t sentence_lock_mutex;
    pthread_mutex_t ticket_lock;
};

struct client_task {
    struct ss_context *ctx;
    int client_fd;
};

/* Forward declarations for helpers */
static void string_array_init(struct array *arr);
static void string_array_clear(struct array *arr);
static int string_array_push(struct array *arr, const char *value);
static int string_array_insert(struct array *arr, size_t index, const char *value);
static char *string_array_get_value(struct array *arr, size_t index);
static void string_array_remove(struct array *arr, size_t index);
static int split_words(const char *sentence, struct array *out);
static int split_sentences(const char *text, struct array *out);
static char *join_words(struct array *words);
static char *join_sentences(struct array *sentences);
static char *load_text(const char *path, size_t *out_size);
static int store_text_atomic(const char *path, const char *content);
static size_t count_words_in_text(const char *text);
static int ss_fetch_remote_content(const char *host,
                                   const char *port,
                                   const char *file,
                                   const char *user,
                                   const char *ticket,
                                   char **out_content);
static int valid_filename(const char *name);
static void ticket_table_init(struct ticket_table *table);
static void ticket_table_destroy(struct ticket_table *table);
static int ticket_table_add(struct ticket_table *table,
                            const char *token,
                            const char *file,
                            const char *user,
                            const char *op,
                            time_t expiry);
static struct auth_ticket *ticket_table_take(struct ticket_table *table,
                                             const char *token,
                                             const char *user,
                                             const char *file,
                                             const char *op);
static void sentence_lock_table_init(struct ss_context *ctx);
static void sentence_lock_table_destroy(struct ss_context *ctx);
static int sentence_lock_acquire(struct ss_context *ctx,
                                 const char *file,
                                 int sentence,
                                 const char *user);
static void sentence_lock_release(struct ss_context *ctx,
                                  const char *file,
                                  const char *user,
                                  int sentence);
static int handle_nm_sync(struct ss_context *ctx, const char *json);
static int handle_nm_ticket_command(struct ss_context *ctx, const char *json);
static void sleep_ms(int ms);
static int ensure_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        }
        errno = ENOTDIR;
        return -1;
    }
    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int path_uses_temp_alias(const char *path) {
    if (!path) {
        return 0;
    }
    if (strncmp(path, "/temp", 5) != 0) {
        return 0;
    }
    return path[5] == '\0' || path[5] == '/';
}

static int get_workspace_root(char *out, size_t out_len) {
    if (!out || out_len == 0) {
        errno = EINVAL;
        return -1;
    }
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len < 0) {
        return -1;
    }
    if ((size_t)len >= sizeof(exe_path) - 1) {
        errno = ENAMETOOLONG;
        return -1;
    }
    exe_path[len] = '\0';
    if (!exe_path[0]) {
        return -1;
    }
    char bin_dir[PATH_MAX];
    if (snprintf(bin_dir, sizeof(bin_dir), "%s", exe_path) >= (int)sizeof(bin_dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    char *parent = dirname(bin_dir);
    if (!parent) {
        errno = EINVAL;
        return -1;
    }
    char repo_dir[PATH_MAX];
    if (snprintf(repo_dir, sizeof(repo_dir), "%s", parent) >= (int)sizeof(repo_dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    char *repo_root = dirname(repo_dir);
    if (!repo_root) {
        errno = EINVAL;
        return -1;
    }
    if (snprintf(out, out_len, "%s", repo_root) >= (int)out_len) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int resolve_storage_directory(const char *workspace_root,
                                     const char *requested,
                                     char *resolved,
                                     size_t resolved_len,
                                     int *used_workspace_base) {
    if (!requested || !resolved || resolved_len == 0) {
        errno = EINVAL;
        return -1;
    }
    if (used_workspace_base) {
        *used_workspace_base = 0;
    }
    if (requested[0] == '/') {
        if (path_uses_temp_alias(requested)) {
            if (!workspace_root || !workspace_root[0]) {
                errno = EINVAL;
                return -1;
            }
            const char *relative = requested + 1; /* trim leading slash */
            if (!relative[0]) {
                relative = "temp";
            }
            if (snprintf(resolved, resolved_len, "%s/%s", workspace_root, relative) >=
                (int)resolved_len) {
                errno = ENAMETOOLONG;
                return -1;
            }
            if (used_workspace_base) {
                *used_workspace_base = 1;
            }
            return 0;
        }
        if (snprintf(resolved, resolved_len, "%s", requested) >= (int)resolved_len) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return 0;
    }
    if (!workspace_root || !workspace_root[0]) {
        errno = EINVAL;
        return -1;
    }
    if (snprintf(resolved, resolved_len, "%s/%s", workspace_root, requested) >=
        (int)resolved_len) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (used_workspace_base) {
        *used_workspace_base = 1;
    }
    return 0;
}

static int join_path(char *dst, size_t dst_sz, const char *base, const char *suffix) {
    if (!dst || dst_sz == 0 || !base || !suffix) {
        errno = EINVAL;
        return -1;
    }
    size_t base_len = strlen(base);
    size_t suffix_len = strlen(suffix);
    if (base_len + suffix_len >= dst_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(dst, base, base_len);
    memcpy(dst + base_len, suffix, suffix_len + 1);
    return 0;
}
static void log_event(struct ss_context *ctx, const char *fmt, ...) {
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

static void log_request(struct ss_context *ctx, const char *fmt, ...) {
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
            errno = EMSGSIZE;
            return -1;
        }
    } else {
        if (snprintf(buf, sizeof(buf), "{\"status\":\"OK\"}") >= (int)sizeof(buf)) {
            errno = EMSGSIZE;
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
        errno = EMSGSIZE;
        return -1;
    }
    return net_send_json(fd, buf);
}
static void write_session_init(struct write_session *session) {
    memset(session, 0, sizeof(*session));
    session->sentence_index = -1;
    string_array_init(&session->sentences);
}

static void write_session_clear(struct write_session *session) {
    if (!session) {
        return;
    }
    free(session->original_text);
    free(session->sentence_text);
    free(session->baseline_sentence);
    session->original_text = NULL;
    session->sentence_text = NULL;
    session->baseline_sentence = NULL;
    string_array_clear(&session->sentences);
    session->active = 0;
    session->sentence_index = -1;
}

static int write_session_begin(struct write_session *session,
                               const struct ss_file *file,
                               const char *user,
                               int sentence_index) {
    write_session_clear(session);
    write_session_init(session);
    session->active = 1;
    session->sentence_index = sentence_index;
    snprintf(session->user, sizeof(session->user), "%s", user);

    char *text = load_text(file->data_path, NULL);
    if (!text) {
        text = strdup("");
        if (!text) {
            return -1;
        }
    }
    session->original_text = text;
    if (split_sentences(text, &session->sentences) < 0) {
        return -1;
    }

    if (sentence_index < 0 || sentence_index > (int)session->sentences.len) {
        errno = EINVAL;
        return -1;
    }

    char *existing = NULL;
    if (sentence_index < (int)session->sentences.len) {
        existing = string_array_get_value(&session->sentences, (size_t)sentence_index);
        session->sentence_text = strdup(existing ? existing : "");
        session->baseline_sentence = existing ? strdup(existing) : NULL;
    } else {
        session->sentence_text = strdup("");
        session->baseline_sentence = NULL;
    }
    if (!session->sentence_text) {
        return -1;
    }
    if (sentence_index < (int)session->sentences.len && existing && !session->baseline_sentence) {
        return -1;
    }
    return 0;
}

static int write_session_apply_insert(struct write_session *session, int index, const char *content) {
    if (!session->active) {
        return -1;
    }
    struct array words;
    if (split_words(session->sentence_text, &words) < 0) {
        return -1;
    }
    if (index < 0) {
        string_array_clear(&words);
        errno = EINVAL;
        return -1;
    }
    size_t idx = (size_t)index;
    if (idx > words.len) {
        string_array_clear(&words);
        errno = EINVAL;
        return -1;
    }
    struct array new_words;
    if (split_words(content, &new_words) < 0) {
        string_array_clear(&words);
        return -1;
    }
    for (size_t i = 0; i < new_words.len; ++i) {
        char *w = string_array_get_value(&new_words, i);
        if (string_array_insert(&words, (size_t)(index + i), w) < 0) {
            string_array_clear(&new_words);
            string_array_clear(&words);
            return -1;
        }
    }
    string_array_clear(&new_words);
    char *joined = join_words(&words);
    string_array_clear(&words);
    if (!joined) {
        return -1;
    }
    free(session->sentence_text);
    session->sentence_text = joined;
    return 0;
}

static int write_session_apply_replace(struct write_session *session,
                                       int index,
                                       const char *content) {
    if (!session->active) {
        return -1;
    }
    struct array words;
    if (split_words(session->sentence_text, &words) < 0) {
        return -1;
    }
    if (index < 0) {
        string_array_clear(&words);
        errno = EINVAL;
        return -1;
    }
    size_t idx = (size_t)index;
    if (idx >= words.len) {
        string_array_clear(&words);
        errno = EINVAL;
        return -1;
    }
    string_array_remove(&words, idx);
    struct array new_words;
    if (split_words(content, &new_words) < 0) {
        string_array_clear(&words);
        return -1;
    }
    for (size_t i = 0; i < new_words.len; ++i) {
        char *w = string_array_get_value(&new_words, i);
        if (string_array_insert(&words, (size_t)(index + i), w) < 0) {
            string_array_clear(&new_words);
            string_array_clear(&words);
            return -1;
        }
    }
    string_array_clear(&new_words);
    char *joined = join_words(&words);
    string_array_clear(&words);
    if (!joined) {
        return -1;
    }
    free(session->sentence_text);
    session->sentence_text = joined;
    return 0;
}

static int write_session_apply_delete(struct write_session *session, int index) {
    if (!session->active) {
        return -1;
    }
    struct array words;
    if (split_words(session->sentence_text, &words) < 0) {
        return -1;
    }
    if (index < 0) {
        string_array_clear(&words);
        errno = EINVAL;
        return -1;
    }
    size_t idx = (size_t)index;
    if (words.len == 0 || idx >= words.len) {
        string_array_clear(&words);
        errno = EINVAL;
        return -1;
    }
    string_array_remove(&words, idx);
    char *joined = join_words(&words);
    string_array_clear(&words);
    if (!joined) {
        joined = strdup("");
        if (!joined) {
            return -1;
        }
    }
    free(session->sentence_text);
    session->sentence_text = joined;
    return 0;
}

static int append_sentence_list(struct array *dest, struct array *src) {
    for (size_t i = 0; i < src->len; ++i) {
        char *value = string_array_get_value(src, i);
        if (string_array_push(dest, value) < 0) {
            return -1;
        }
    }
    return 0;
}

static int write_session_commit(struct write_session *session,
                                const struct ss_file *file,
                                char **out_text,
                                size_t *out_words,
                                size_t *out_chars) {
    char *current_text = load_text(file->data_path, NULL);
    if (!current_text) {
        current_text = strdup("");
        if (!current_text) {
            return -1;
        }
    }

    struct array latest_sentences;
    if (split_sentences(current_text, &latest_sentences) < 0) {
        free(current_text);
        return -1;
    }

    struct array new_parts;
    if (split_sentences(session->sentence_text, &new_parts) < 0) {
        string_array_clear(&latest_sentences);
        free(current_text);
        return -1;
    }

    int insert_index = session->sentence_index;
    if (insert_index < 0) {
        insert_index = 0;
    }
    if (insert_index > (int)latest_sentences.len) {
        insert_index = (int)latest_sentences.len;
    }

    int matched_index = -1;
    const int replacing_existing = (session->baseline_sentence && session->baseline_sentence[0]);
    if (replacing_existing) {
        for (size_t i = 0; i < latest_sentences.len; ++i) {
            char *candidate = string_array_get_value(&latest_sentences, i);
            if (strcmp(candidate, session->baseline_sentence) == 0) {
                matched_index = (int)i;
                if ((int)i >= session->sentence_index) {
                    insert_index = (int)i;
                    break;
                }
                insert_index = (int)i;
            }
        }
        if (matched_index >= 0) {
            insert_index = matched_index;
        }
    }
    if (insert_index > (int)latest_sentences.len) {
        insert_index = (int)latest_sentences.len;
    }

    struct array merged;
    string_array_init(&merged);
    int inserted = 0;
    int removed_original = 0;
    for (size_t i = 0; i < latest_sentences.len; ++i) {
        if (!inserted && (int)i == insert_index) {
            if (append_sentence_list(&merged, &new_parts) < 0) {
                goto commit_fail;
            }
            inserted = 1;
        }
        if (replacing_existing && !removed_original && (int)i == insert_index) {
            removed_original = 1;
            continue;
        }
        char *segment = string_array_get_value(&latest_sentences, i);
        if (string_array_push(&merged, segment) < 0) {
            goto commit_fail;
        }
    }
    if (!inserted) {
        if (append_sentence_list(&merged, &new_parts) < 0) {
            goto commit_fail;
        }
        inserted = 1;
    }

    char *text = join_sentences(&merged);
    string_array_clear(&merged);
    string_array_clear(&new_parts);
    string_array_clear(&latest_sentences);
    if (!text) {
        free(current_text);
        return -1;
    }

    if (store_text_atomic(file->undo_path, current_text) < 0) {
        free(text);
        free(current_text);
        return -1;
    }
    if (store_text_atomic(file->data_path, text) < 0) {
        free(text);
        free(current_text);
        return -1;
    }
    free(current_text);

    size_t new_char_count = strlen(text);
    size_t new_word_count = count_words_in_text(text);
    if (out_chars) {
        *out_chars = new_char_count;
    }
    if (out_words) {
        *out_words = new_word_count;
    }
    if (out_text) {
        *out_text = text;
    } else {
        free(text);
    }
    session->active = 0;
    return 0;

commit_fail:
    string_array_clear(&merged);
    string_array_clear(&new_parts);
    string_array_clear(&latest_sentences);
    free(current_text);
    return -1;
}

static void notify_nm_file_update(struct ss_context *ctx, const struct ss_file *file) {
    char escaped_name[SS_NAME_MAX * 2];
    char escaped_owner[SS_USER_MAX * 2];
    char escaped_last[SS_USER_MAX * 2];
    if (json_escape_string(escaped_name, sizeof(escaped_name), file->name) < 0 ||
        json_escape_string(escaped_owner, sizeof(escaped_owner), file->owner) < 0 ||
        json_escape_string(escaped_last, sizeof(escaped_last), file->last_access_user) < 0) {
        return;
    }
    char payload[MAX_JSON];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"SS_FILE_UPDATE\",\"file\":\"%s\",\"owner\":\"%s\","
                 "\"words\":%zu,\"chars\":%zu,\"modified\":%ld,"
                 "\"lastAccess\":%ld,\"lastAccessUser\":\"%s\"}",
                 escaped_name, escaped_owner,
                 file->word_count, file->char_count,
                 (long)file->modified, (long)file->last_access, escaped_last) >=
        (int)sizeof(payload)) {
        return;
    }
    net_send_json(ctx->nm_fd, payload);
}

static int snapshot_file(struct ss_context *ctx, const char *file_name, struct ss_file *out) {
    if (!ctx || !file_name || !out) {
        return -1;
    }
    if (pthread_rwlock_rdlock(&ctx->state_lock) != 0) {
        return -1;
    }
    size_t idx = 0;
    struct ss_file *file = ss_state_find(&ctx->state, file_name, &idx);
    if (file) {
        *out = *file;
    }
    pthread_rwlock_unlock(&ctx->state_lock);
    return file ? 0 : -1;
}

static void set_file_lock_state(struct ss_context *ctx,
                                const char *file_name,
                                int active,
                                int sentence,
                                const char *user) {
    if (pthread_rwlock_wrlock(&ctx->state_lock) != 0) {
        return;
    }
    size_t idx = 0;
    struct ss_file *file = ss_state_find(&ctx->state, file_name, &idx);
    if (file) {
        file->lock_active = active;
        file->lock_sentence = active ? sentence : -1;
        if (user && active) {
            snprintf(file->lock_user, sizeof(file->lock_user), "%s", user);
        } else {
            file->lock_user[0] = '\0';
        }
    }
    pthread_rwlock_unlock(&ctx->state_lock);
}

static int perform_undo(struct ss_context *ctx,
                        const char *file_name,
                        const char *user,
                        char **out_text,
                        size_t *words_out,
                        size_t *chars_out) {
    struct ss_file view;
    if (snapshot_file(ctx, file_name, &view) < 0) {
        errno = ENOENT;
        return -1;
    }
    char *undo_text = load_text(view.undo_path, NULL);
    if (!undo_text) {
        errno = ENOENT;
        return -1;
    }
    char *current_text = load_text(view.data_path, NULL);
    if (!current_text) {
        current_text = strdup("");
        if (!current_text) {
            free(undo_text);
            return -1;
        }
    }
    if (store_text_atomic(view.data_path, undo_text) < 0) {
        free(undo_text);
        free(current_text);
        return -1;
    }
    if (unlink(view.undo_path) < 0) {
        log_event(ctx, "Failed to delete undo file for %s: %s", file_name, strerror(errno));
    }
    size_t new_chars = strlen(undo_text);
    size_t new_words = count_words_in_text(undo_text);
    time_t now = time(NULL);
    struct ss_file notify_copy;
    int have_meta = 0;
    if (pthread_rwlock_wrlock(&ctx->state_lock) == 0) {
        size_t idx = 0;
        struct ss_file *file = ss_state_find(&ctx->state, file_name, &idx);
        if (file) {
            file->char_count = new_chars;
            file->word_count = new_words;
            file->modified = now;
            file->last_access = now;
            snprintf(file->last_access_user, sizeof(file->last_access_user), "%s", user);
            ss_state_save_meta(&ctx->state, file);
            notify_copy = *file;
            have_meta = 1;
        }
        pthread_rwlock_unlock(&ctx->state_lock);
    }
    if (!have_meta) {
        free(undo_text);
        free(current_text);
        errno = ENOENT;
        return -1;
    }
    notify_nm_file_update(ctx, &notify_copy);
    log_request(ctx, "UNDO user=%s file=%s words=%zu chars=%zu",
                user, notify_copy.name, notify_copy.word_count, notify_copy.char_count);
    if (words_out) {
        *words_out = new_words;
    }
    if (chars_out) {
        *chars_out = new_chars;
    }
    if (out_text) {
        *out_text = undo_text;
    } else {
        free(undo_text);
    }
    free(current_text);
    return 0;
}

static int validate_ticket(struct ss_context *ctx,
                           const char *token,
                           const char *user,
                           const char *file,
                           const char *op,
                           struct auth_ticket **out_ticket) {
    pthread_mutex_lock(&ctx->ticket_lock);
    struct auth_ticket *ticket = ticket_table_take(&ctx->tickets, token, user, file, op);
    pthread_mutex_unlock(&ctx->ticket_lock);
    if (!ticket) {
        errno = EACCES;
        return -1;
    }
    if (out_ticket) {
        *out_ticket = ticket;
    } else {
        free(ticket);
    }
    return 0;
}

static int handle_read(struct ss_context *ctx,
                       int client_fd,
                       const char *file_name,
                       const char *user) {
    struct ss_file view;
    if (snapshot_file(ctx, file_name, &view) < 0) {
        return send_error_response(client_fd, ERR_NOTFOUND, "file not found");
    }
    size_t size = 0;
    char *text = load_text(view.data_path, &size);
    if (!text) {
        text = strdup("");
        if (!text) {
            return send_error_response(client_fd, ERR_INTERNAL, "read failed");
        }
    }
    char *escaped = json_escape_dup(text);
    if (!escaped) {
        free(text);
        return send_error_response(client_fd, ERR_INTERNAL, "encode failed");
    }
    time_t now = time(NULL);
    struct ss_file meta_copy;
    int have_meta = 0;
    if (pthread_rwlock_wrlock(&ctx->state_lock) == 0) {
        size_t idx = 0;
        struct ss_file *file = ss_state_find(&ctx->state, file_name, &idx);
        if (file) {
            file->last_access = now;
            snprintf(file->last_access_user, sizeof(file->last_access_user), "%s", user);
            ss_state_save_meta(&ctx->state, file);
            meta_copy = *file;
            have_meta = 1;
        }
        pthread_rwlock_unlock(&ctx->state_lock);
    }
    if (have_meta) {
        notify_nm_file_update(ctx, &meta_copy);
    }
    log_request(ctx, "READ user=%s file=%s", user, file_name);
    char extra[MAX_JSON];
    size_t words = have_meta ? meta_copy.word_count : view.word_count;
    size_t chars = have_meta ? meta_copy.char_count : view.char_count;
    if (snprintf(extra, sizeof(extra),
                 "\"file\":\"%s\",\"content\":\"%s\",\"words\":%zu,\"chars\":%zu",
                 view.name, escaped, words, chars) >= (int)sizeof(extra)) {
        free(escaped);
        free(text);
        return send_error_response(client_fd, ERR_INTERNAL, "response too large");
    }
    free(escaped);
    free(text);
    return send_ok(client_fd, extra);
}

static int handle_stream(struct ss_context *ctx,
                         int client_fd,
                         const char *file_name,
                         const char *user) {
    struct ss_file view;
    if (snapshot_file(ctx, file_name, &view) < 0) {
        return send_error_response(client_fd, ERR_NOTFOUND, "file not found");
    }
    char *text = load_text(view.data_path, NULL);
    if (!text) {
        text = strdup("");
        if (!text) {
            return send_error_response(client_fd, ERR_INTERNAL, "stream failed");
        }
    }
    struct array words;
    if (split_words(text, &words) < 0) {
        free(text);
        return send_error_response(client_fd, ERR_INTERNAL, "tokenize failed");
    }
    char header[256];
    if (snprintf(header, sizeof(header),
                 "\"mode\":\"STREAM\",\"words\":%zu", words.len) >= (int)sizeof(header)) {
        string_array_clear(&words);
        free(text);
        return send_error_response(client_fd, ERR_INTERNAL, "response too large");
    }
    if (send_ok(client_fd, header) < 0) {
        string_array_clear(&words);
        free(text);
        return -1;
    }
    for (size_t i = 0; i < words.len; ++i) {
        char *w = string_array_get_value(&words, i);
        char *escaped = json_escape_dup(w);
        if (!escaped) {
            continue;
        }
        char msg[1024];
        if (snprintf(msg, sizeof(msg), "{\"status\":\"DATA\",\"word\":\"%s\"}", escaped) >=
            (int)sizeof(msg)) {
            free(escaped);
            continue;
        }
        free(escaped);
        if (net_send_json(client_fd, msg) < 0) {
            break;
        }
        sleep_ms(STREAM_DELAY_MS);
    }
    net_send_json(client_fd, "{\"status\":\"DONE\"}");
    string_array_clear(&words);
    free(text);
    time_t now = time(NULL);
    struct ss_file meta_copy;
    int have_meta = 0;
    if (pthread_rwlock_wrlock(&ctx->state_lock) == 0) {
        size_t idx = 0;
        struct ss_file *file = ss_state_find(&ctx->state, file_name, &idx);
        if (file) {
            file->last_access = now;
            snprintf(file->last_access_user, sizeof(file->last_access_user), "%s", user);
            ss_state_save_meta(&ctx->state, file);
            meta_copy = *file;
            have_meta = 1;
        }
        pthread_rwlock_unlock(&ctx->state_lock);
    }
    if (have_meta) {
        notify_nm_file_update(ctx, &meta_copy);
        log_request(ctx, "STREAM user=%s file=%s words=%zu", user, meta_copy.name, meta_copy.word_count);
    } else {
        log_request(ctx, "STREAM user=%s file=%s", user, file_name);
    }
    return 0;
}

static int handle_write(struct ss_context *ctx,
                        int client_fd,
                        const char *file_name,
                        const char *user,
                        int sentence_index) {
    struct ss_file view;
    if (snapshot_file(ctx, file_name, &view) < 0) {
        return send_error_response(client_fd, ERR_NOTFOUND, "file not found");
    }
    if (sentence_lock_acquire(ctx, file_name, sentence_index, user) < 0) {
        return send_error_response(client_fd, ERR_LOCKED, "sentence locked");
    }
    int have_sentence_lock = 1;
    set_file_lock_state(ctx, file_name, 1, sentence_index, user);

    struct write_session session;
    write_session_init(&session);
    if (write_session_begin(&session, &view, user, sentence_index) < 0) {
        int begin_err = errno;
        write_session_clear(&session);
        set_file_lock_state(ctx, file_name, 0, -1, NULL);
        if (have_sentence_lock) {
            sentence_lock_release(ctx, file_name, user, sentence_index);
            have_sentence_lock = 0;
        }
        if (begin_err == EINVAL) {
            return send_error_response(client_fd, ERR_BADREQ, "sentence index out of range");
        }
        return send_error_response(client_fd, ERR_INTERNAL, "write init failed");
    }

    char *escaped_text = json_escape_dup(session.sentence_text);
    if (!escaped_text) {
        write_session_clear(&session);
        set_file_lock_state(ctx, file_name, 0, -1, NULL);
        if (have_sentence_lock) {
            sentence_lock_release(ctx, file_name, user, sentence_index);
            have_sentence_lock = 0;
        }
        return send_error_response(client_fd, ERR_INTERNAL, "encode failed");
    }
    char extra[MAX_JSON];
    if (snprintf(extra, sizeof(extra),
                 "\"mode\":\"WRITE\",\"current\":\"%s\",\"sentence\":%d",
                 escaped_text, sentence_index) >= (int)sizeof(extra)) {
        free(escaped_text);
        write_session_clear(&session);
        set_file_lock_state(ctx, file_name, 0, -1, NULL);
        if (have_sentence_lock) {
            sentence_lock_release(ctx, file_name, user, sentence_index);
            have_sentence_lock = 0;
        }
        return send_error_response(client_fd, ERR_INTERNAL, "response too large");
    }
    free(escaped_text);
    if (send_ok(client_fd, extra) < 0) {
        write_session_clear(&session);
        set_file_lock_state(ctx, file_name, 0, -1, NULL);
        if (have_sentence_lock) {
            sentence_lock_release(ctx, file_name, user, sentence_index);
            have_sentence_lock = 0;
        }
        return -1;
    }
    log_request(ctx, "WRITE_BEGIN user=%s file=%s sentence=%d",
                user, file_name, sentence_index);

    int result = 0;
    while (1) {
        char *json = NULL;
        if (net_recv_json(client_fd, &json) < 0) {
            result = -1;
            break;
        }
        char type[64];
        if (json_get_string(json, "type", type, sizeof(type)) < 0) {
            send_error_response(client_fd, ERR_BADREQ, "missing type");
            free(json);
            continue;
        }
        if (strcmp(type, "WRITE_INSERT") == 0) {
            int index = 0;
            if (json_get_int(json, "index", &index) < 0) {
                send_error_response(client_fd, ERR_BADREQ, "missing index");
            } else {
                char *content = NULL;
                if (json_get_string_alloc(json, "content", &content) < 0) {
                    send_error_response(client_fd, ERR_BADREQ, "missing content");
                } else if (write_session_apply_insert(&session, index, content) < 0) {
                    int op_err = errno;
                    if (op_err == EINVAL) {
                        send_error_response(client_fd, ERR_BADREQ, "word index out of range");
                    } else {
                        send_error_response(client_fd, ERR_CONFLICT, "insert failed");
                    }
                } else {
                    send_ok(client_fd, "\"step\":\"INSERT\"");
                }
                free(content);
            }
        } else if (strcmp(type, "WRITE_REPLACE") == 0) {
            int index = 0;
            if (json_get_int(json, "index", &index) < 0) {
                send_error_response(client_fd, ERR_BADREQ, "missing index");
            } else {
                char *content = NULL;
                if (json_get_string_alloc(json, "content", &content) < 0) {
                    send_error_response(client_fd, ERR_BADREQ, "missing content");
                } else if (write_session_apply_replace(&session, index, content) < 0) {
                    int op_err = errno;
                    if (op_err == EINVAL) {
                        send_error_response(client_fd, ERR_BADREQ, "word index out of range");
                    } else {
                        send_error_response(client_fd, ERR_CONFLICT, "replace failed");
                    }
                } else {
                    send_ok(client_fd, "\"step\":\"REPLACE\"");
                }
                free(content);
            }
        } else if (strcmp(type, "WRITE_DELETE") == 0) {
            int index = 0;
            if (json_get_int(json, "index", &index) < 0) {
                send_error_response(client_fd, ERR_BADREQ, "missing index");
            } else if (write_session_apply_delete(&session, index) < 0) {
                int op_err = errno;
                if (op_err == EINVAL) {
                    send_error_response(client_fd, ERR_BADREQ, "word index out of range");
                } else {
                    send_error_response(client_fd, ERR_CONFLICT, "delete failed");
                }
            } else {
                send_ok(client_fd, "\"step\":\"DELETE\"");
            }
        } else if (strcmp(type, "WRITE_COMMIT") == 0) {
            char *final_text = NULL;
            size_t new_words = 0;
            size_t new_chars = 0;
            if (write_session_commit(&session, &view, &final_text, &new_words, &new_chars) < 0) {
                send_error_response(client_fd, ERR_INTERNAL, "commit failed");
            } else {
                char *escaped_final = json_escape_dup(final_text);
                if (escaped_final) {
                    char commit_extra[MAX_JSON];
                    if (snprintf(commit_extra, sizeof(commit_extra),
                                 "\"step\":\"COMMIT\",\"words\":%zu,\"chars\":%zu,\"content\":\"%s\"",
                                 new_words, new_chars, escaped_final) <
                        (int)sizeof(commit_extra)) {
                        send_ok(client_fd, commit_extra);
                    } else {
                        send_ok(client_fd, "\"step\":\"COMMIT\"");
                    }
                    free(escaped_final);
                } else {
                    send_ok(client_fd, "\"step\":\"COMMIT\"");
                }
                struct ss_file notify_copy;
                int have_meta = 0;
                time_t now = time(NULL);
                if (pthread_rwlock_wrlock(&ctx->state_lock) == 0) {
                    size_t idx = 0;
                    struct ss_file *state_file = ss_state_find(&ctx->state, file_name, &idx);
                    if (state_file) {
                        state_file->char_count = new_chars;
                        state_file->word_count = new_words;
                        state_file->modified = now;
                        state_file->last_access = now;
                        snprintf(state_file->last_access_user, sizeof(state_file->last_access_user), "%s", user);
                        state_file->lock_active = 0;
                        state_file->lock_sentence = -1;
                        ss_state_save_meta(&ctx->state, state_file);
                        notify_copy = *state_file;
                        have_meta = 1;
                    }
                    pthread_rwlock_unlock(&ctx->state_lock);
                }
                if (have_meta) {
                    notify_nm_file_update(ctx, &notify_copy);
                    log_request(ctx, "WRITE_COMMIT user=%s file=%s words=%zu chars=%zu",
                                user, notify_copy.name, notify_copy.word_count, notify_copy.char_count);
                } else {
                    log_request(ctx, "WRITE_COMMIT user=%s file=%s", user, file_name);
                }
                free(final_text);
            }
            write_session_clear(&session);
            result = 0;
            free(json);
            break;
        } else if (strcmp(type, "WRITE_ABORT") == 0) {
            send_ok(client_fd, "\"step\":\"ABORT\"");
            write_session_clear(&session);
            result = 0;
            log_request(ctx, "WRITE_ABORT user=%s file=%s", user, file_name);
            free(json);
            break;
        } else {
            send_error_response(client_fd, ERR_BADREQ, "unknown write command");
        }
        free(json);
    }

    if (session.active) {
        write_session_clear(&session);
    }
    if (have_sentence_lock) {
        sentence_lock_release(ctx, file_name, user, sentence_index);
        have_sentence_lock = 0;
    }
    set_file_lock_state(ctx, file_name, 0, -1, NULL);
    return result;
}

static void handle_data_client(struct ss_context *ctx, int client_fd) {
    char *json = NULL;
    if (net_recv_json(client_fd, &json) < 0) {
        free(json);
        net_close(client_fd);
        return;
    }
    char type[64];
    char file_name[SS_NAME_MAX];
    char user[SS_USER_MAX];
    char token[MAX_TOKEN_LEN];
    if (json_get_string(json, "type", type, sizeof(type)) < 0 ||
        json_get_string(json, "file", file_name, sizeof(file_name)) < 0 ||
        json_get_string(json, "user", user, sizeof(user)) < 0 ||
        json_get_string(json, "ticket", token, sizeof(token)) < 0) {
        send_error_response(client_fd, ERR_BADREQ, "missing fields");
        free(json);
        net_close(client_fd);
        return;
    }
    struct auth_ticket *ticket = NULL;
    if (strcmp(type, "READ") == 0) {
        if (validate_ticket(ctx, token, user, file_name, "READ", &ticket) < 0) {
            send_error_response(client_fd, ERR_NOAUTH, "invalid ticket");
        } else {
            handle_read(ctx, client_fd, file_name, user);
        }
    } else if (strcmp(type, "STREAM") == 0) {
        if (validate_ticket(ctx, token, user, file_name, "STREAM", &ticket) < 0) {
            send_error_response(client_fd, ERR_NOAUTH, "invalid ticket");
        } else {
            handle_stream(ctx, client_fd, file_name, user);
        }
    } else if (strcmp(type, "WRITE_BEGIN") == 0) {
        int sentence_index = 0;
        if (json_get_int(json, "sentence", &sentence_index) < 0) {
            send_error_response(client_fd, ERR_BADREQ, "missing sentence");
        } else if (validate_ticket(ctx, token, user, file_name, "WRITE", &ticket) < 0) {
            send_error_response(client_fd, ERR_NOAUTH, "invalid ticket");
        } else {
            handle_write(ctx, client_fd, file_name, user, sentence_index);
        }
    } else {
        send_error_response(client_fd, ERR_BADREQ, "unsupported operation");
    }
    free(ticket);
    free(json);
    net_close(client_fd);
}

static void *data_client_thread(void *arg) {
    struct client_task *task = arg;
    if (!task) {
        return NULL;
    }
    handle_data_client(task->ctx, task->client_fd);
    free(task);
    return NULL;
}

static int ss_fetch_remote_content(const char *host,
                                   const char *port,
                                   const char *file,
                                   const char *user,
                                   const char *ticket,
                                   char **out_content) {
    int fd = net_connect(host, port);
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

static int handle_nm_sync(struct ss_context *ctx, const char *json) {
    char file_name[SS_NAME_MAX];
    char owner[SS_USER_MAX];
    char source_host[64];
    char source_port[16];
    char ticket[MAX_TOKEN_LEN];
    if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0 ||
        json_get_string(json, "owner", owner, sizeof(owner)) < 0 ||
        json_get_string(json, "sourceHost", source_host, sizeof(source_host)) < 0 ||
        json_get_string(json, "sourcePort", source_port, sizeof(source_port)) < 0 ||
        json_get_string(json, "ticket", ticket, sizeof(ticket)) < 0) {
        return send_error_response(ctx->nm_fd, ERR_BADREQ, "invalid sync");
    }
    char *content = NULL;
    if (ss_fetch_remote_content(source_host, source_port, file_name, owner, ticket, &content) < 0) {
        return send_error_response(ctx->nm_fd, ERR_INTERNAL, "sync failed");
    }
    struct ss_file view;
    if (snapshot_file(ctx, file_name, &view) < 0) {
        int added = 0;
        if (pthread_rwlock_wrlock(&ctx->state_lock) == 0) {
            if (ss_state_add(&ctx->state, file_name, owner) == 0) {
                added = 1;
            }
            pthread_rwlock_unlock(&ctx->state_lock);
        }
        if (!added || snapshot_file(ctx, file_name, &view) < 0) {
            free(content);
            return send_error_response(ctx->nm_fd, ERR_INTERNAL, "sync failed");
        }
    }
    char *existing = load_text(view.data_path, NULL);
    if (!existing) {
        existing = strdup("");
        if (!existing) {
            free(content);
            return send_error_response(ctx->nm_fd, ERR_INTERNAL, "sync failed");
        }
    }
    if (store_text_atomic(view.undo_path, existing) < 0) {
        free(existing);
        free(content);
        return send_error_response(ctx->nm_fd, ERR_INTERNAL, "sync failed");
    }
    free(existing);
    if (store_text_atomic(view.data_path, content) < 0) {
        free(content);
        return send_error_response(ctx->nm_fd, ERR_INTERNAL, "sync failed");
    }
    size_t new_chars = strlen(content);
    size_t new_words = count_words_in_text(content);
    int updated = 0;
    if (pthread_rwlock_wrlock(&ctx->state_lock) == 0) {
        size_t idx = 0;
        struct ss_file *file = ss_state_find(&ctx->state, file_name, &idx);
        if (file) {
            file->char_count = new_chars;
            file->word_count = new_words;
            ss_state_save_meta(&ctx->state, file);
            updated = 1;
        }
        pthread_rwlock_unlock(&ctx->state_lock);
    }
    if (!updated) {
        free(content);
        return send_error_response(ctx->nm_fd, ERR_INTERNAL, "sync failed");
    }
    log_request(ctx, "SYNC file=%s owner=%s", file_name, owner);
    free(content);
    return send_ok(ctx->nm_fd, "\"op\":\"SYNC\"");
}

static int handle_nm_ticket_command(struct ss_context *ctx, const char *json) {
    char token[MAX_TOKEN_LEN];
    char file_name[SS_NAME_MAX];
    char user[SS_USER_MAX];
    char op[16];
    int expiry = 0;
    if (json_get_string(json, "token", token, sizeof(token)) < 0 ||
        json_get_string(json, "file", file_name, sizeof(file_name)) < 0 ||
        json_get_string(json, "user", user, sizeof(user)) < 0 ||
        json_get_string(json, "op", op, sizeof(op)) < 0 ||
        json_get_int(json, "expiry", &expiry) < 0) {
        return send_error_response(ctx->nm_fd, ERR_BADREQ, "invalid ticket");
    }
    pthread_mutex_lock(&ctx->ticket_lock);
    int rc = ticket_table_add(&ctx->tickets, token, file_name, user, op, (time_t)expiry);
    pthread_mutex_unlock(&ctx->ticket_lock);
    if (rc < 0) {
        return send_error_response(ctx->nm_fd, ERR_INTERNAL, "ticket failed");
    }
    return send_ok(ctx->nm_fd, "\"op\":\"TICKET\"");
}

static int process_nm_command(struct ss_context *ctx) {
    char *json = NULL;
    if (net_recv_json(ctx->nm_fd, &json) < 0) {
        free(json);
        return -1;
    }
    char type[64];
    if (json_get_string(json, "type", type, sizeof(type)) < 0) {
        send_error_response(ctx->nm_fd, ERR_BADREQ, "missing type");
        free(json);
        return 0;
    }
    if (strcmp(type, "NM_CREATE") == 0) {
        char name[SS_NAME_MAX];
        char owner[SS_USER_MAX];
        if (json_get_string(json, "file", name, sizeof(name)) < 0 ||
            json_get_string(json, "owner", owner, sizeof(owner)) < 0 ||
            !valid_filename(name)) {
            send_error_response(ctx->nm_fd, ERR_BADREQ, "invalid create");
        } else {
            int rc = -1;
            if (pthread_rwlock_wrlock(&ctx->state_lock) == 0) {
                rc = ss_state_add(&ctx->state, name, owner);
                pthread_rwlock_unlock(&ctx->state_lock);
            }
            if (rc < 0) {
                send_error_response(ctx->nm_fd, ERR_EXISTS, strerror(errno));
            } else {
                send_ok(ctx->nm_fd, "\"op\":\"CREATE\"");
            }
        }
    } else if (strcmp(type, "NM_DELETE") == 0) {
        char name[SS_NAME_MAX];
        if (json_get_string(json, "file", name, sizeof(name)) < 0 ||
            !valid_filename(name)) {
            send_error_response(ctx->nm_fd, ERR_BADREQ, "invalid delete");
        } else {
            int rc = -1;
            if (pthread_rwlock_wrlock(&ctx->state_lock) == 0) {
                rc = ss_state_remove(&ctx->state, name);
                pthread_rwlock_unlock(&ctx->state_lock);
            }
            if (rc < 0) {
                send_error_response(ctx->nm_fd, ERR_NOTFOUND, "file missing");
            } else {
                send_ok(ctx->nm_fd, "\"op\":\"DELETE\"");
            }
        }
    } else if (strcmp(type, "NM_TICKET") == 0) {
        handle_nm_ticket_command(ctx, json);
        } else if (strcmp(type, "NM_UNDO") == 0) {
        char file_name[SS_NAME_MAX];
        char user[SS_USER_MAX];
        if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0 ||
            json_get_string(json, "user", user, sizeof(user)) < 0) {
            send_error_response(ctx->nm_fd, ERR_BADREQ, "invalid undo");
        } else {
            char *text = NULL;
            size_t undo_words = 0;
            size_t undo_chars = 0;
            if (perform_undo(ctx, file_name, user, &text, &undo_words, &undo_chars) < 0) {
                send_error_response(ctx->nm_fd, ERR_CONFLICT, "undo not possible");
            } else {
                char *escaped = json_escape_dup(text);
                if (escaped) {
                    char extra[MAX_JSON];
                    if (snprintf(extra, sizeof(extra),
                                 "\"op\":\"UNDO\",\"words\":%zu,\"chars\":%zu,\"content\":\"%s\"",
                                 undo_words, undo_chars, escaped) <
                        (int)sizeof(extra)) {
                        send_ok(ctx->nm_fd, extra);
                    } else {
                        send_ok(ctx->nm_fd, "\"op\":\"UNDO\"");
                    }
                    free(escaped);
                } else {
                    send_ok(ctx->nm_fd, "\"op\":\"UNDO\"");
                }
                free(text);
            }
        }
    } else if (strcmp(type, "NM_SYNC") == 0) {
        return handle_nm_sync(ctx, json);
    } else if (strcmp(type, "PING") == 0) {
        send_ok(ctx->nm_fd, "\"op\":\"PING\"");
    } else {
        send_error_response(ctx->nm_fd, ERR_BADREQ, "unknown command");
    }
    free(json);
    return 0;
}

static void build_file_list(struct ss_context *ctx, char *out, size_t out_size) {
    size_t offset = 0;
    out[0] = '\0';
    if (pthread_rwlock_rdlock(&ctx->state_lock) != 0) {
        return;
    }
    for (size_t i = 0; i < ctx->state.files.len; ++i) {
        struct ss_file *file = array_get(&ctx->state.files, i);
        if (offset != 0) {
            if (offset + 1 >= out_size) {
                break;
            }
            out[offset++] = ',';
        }
        size_t len = strlen(file->name);
        if (offset + len >= out_size) {
            break;
        }
        memcpy(out + offset, file->name, len);
        offset += len;
        out[offset] = '\0';
    }
    pthread_rwlock_unlock(&ctx->state_lock);
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr,
                "Usage: %s <ss_id> <public_host> <data_port> <nm_host> <nm_port> <storage_dir>\n",
                argv[0]);
        return 1;
    }

    const char *ss_id = argv[1];
    const char *public_host = argv[2];
    const char *data_port = argv[3];
    const char *nm_host = argv[4];
    const char *nm_port = argv[5];
    const char *requested_storage_dir = argv[6];
    char workspace_root[PATH_MAX];
    if (get_workspace_root(workspace_root, sizeof(workspace_root)) < 0) {
        if (!getcwd(workspace_root, sizeof(workspace_root))) {
            workspace_root[0] = '\0';
        }
    }
    char storage_dir_buf[PATH_MAX];
    int used_workspace_base = 0;
    if (resolve_storage_directory(workspace_root,
                                  requested_storage_dir,
                                  storage_dir_buf,
                                  sizeof(storage_dir_buf),
                                  &used_workspace_base) < 0) {
        fprintf(stderr,
                "Invalid storage directory '%s': %s\n",
                requested_storage_dir,
                strerror(errno));
        return 1;
    }
    if (used_workspace_base && path_uses_temp_alias(requested_storage_dir)) {
        fprintf(stderr,
                "Redirected storage dir %s -> %s to keep data inside workspace\n",
                requested_storage_dir,
                storage_dir_buf);
    }
    const char *storage_dir = storage_dir_buf;

    struct ss_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.nm_fd = -1;
    ctx.listen_fd = -1;
    snprintf(ctx.id, sizeof(ctx.id), "%s", ss_id);
    snprintf(ctx.public_host, sizeof(ctx.public_host), "%s", public_host);
    snprintf(ctx.ctrl_port, sizeof(ctx.ctrl_port), "%s", "0");
    snprintf(ctx.data_port, sizeof(ctx.data_port), "%s", data_port);

    int exit_code = 0;
    bool logs_opened = false;

    if (pthread_rwlock_init(&ctx.state_lock, NULL) != 0 ||
        pthread_mutex_init(&ctx.sentence_lock_mutex, NULL) != 0 ||
        pthread_mutex_init(&ctx.ticket_lock, NULL) != 0) {
        fprintf(stderr, "Failed to initialise synchronization primitives\n");
        return 1;
    }

    if (ss_state_init(&ctx.state, storage_dir) < 0) {
        fprintf(stderr, "Failed to initialise storage state: %s\n", strerror(errno));
        pthread_rwlock_destroy(&ctx.state_lock);
        pthread_mutex_destroy(&ctx.sentence_lock_mutex);
        pthread_mutex_destroy(&ctx.ticket_lock);
        return 1;
    }

    char log_dir[PATH_MAX];
    if (join_path(log_dir, sizeof(log_dir), storage_dir, "/logs") < 0) {
        fprintf(stderr, "Failed to compose log directory: %s\n", strerror(errno));
        exit_code = 1;
        goto cleanup;
    }
    if (ensure_directory(log_dir) < 0) {
        fprintf(stderr, "Failed to create log directory: %s\n", strerror(errno));
        exit_code = 1;
        goto cleanup;
    }
    char general_log[PATH_MAX];
    char request_log[PATH_MAX];
    if (join_path(general_log, sizeof(general_log), log_dir, "/ss.log") < 0 ||
        join_path(request_log, sizeof(request_log), log_dir, "/requests.log") < 0) {
        fprintf(stderr, "Log path too long: %s\n", strerror(errno));
        exit_code = 1;
        goto cleanup;
    }
    if (log_open(&ctx.log_general, general_log) < 0 ||
        log_open(&ctx.log_requests, request_log) < 0) {
        fprintf(stderr, "Failed to open log files: %s\n", strerror(errno));
        exit_code = 1;
        goto cleanup;
    }
    logs_opened = true;

    ticket_table_init(&ctx.tickets);
    sentence_lock_table_init(&ctx);
    randutil_seed();

    ctx.nm_fd = net_connect(nm_host, nm_port);
    if (ctx.nm_fd < 0) {
        fprintf(stderr, "Failed to connect to NM %s:%s\n", nm_host, nm_port);
        exit_code = 1;
        goto cleanup;
    }

    char file_list[1024];
    build_file_list(&ctx, file_list, sizeof(file_list));
    char escaped_id[128];
    char escaped_host[128];
    char escaped_files[1024];
    if (json_escape_string(escaped_id, sizeof(escaped_id), ctx.id) < 0 ||
        json_escape_string(escaped_host, sizeof(escaped_host), ctx.public_host) < 0 ||
        json_escape_string(escaped_files, sizeof(escaped_files), file_list) < 0) {
        fprintf(stderr, "Failed to encode register payload\n");
        exit_code = 1;
        goto cleanup;
    }

    char register_payload[MAX_JSON];
    if (snprintf(register_payload, sizeof(register_payload),
                 "{\"type\":\"SS_REGISTER\",\"ssId\":\"%s\",\"host\":\"%s\","
                 "\"ctrlPort\":\"%s\",\"dataPort\":\"%s\",\"files\":\"%s\"}",
                 escaped_id, escaped_host, ctx.ctrl_port, ctx.data_port, escaped_files) >=
        (int)sizeof(register_payload)) {
        fprintf(stderr, "Register payload too large\n");
        exit_code = 1;
        goto cleanup;
    }
    if (net_send_json(ctx.nm_fd, register_payload) < 0) {
        fprintf(stderr, "Failed to send register payload\n");
        exit_code = 1;
        goto cleanup;
    }
    char *register_resp = NULL;
    char status[16];
    while (1) {
        if (net_recv_json(ctx.nm_fd, &register_resp) < 0) {
            fprintf(stderr, "Failed to receive register acknowledgement\n");
            exit_code = 1;
            goto cleanup;
        }
        if (json_get_string(register_resp, "status", status, sizeof(status)) == 0) {
            break;
        }
        char type[64];
        if (json_get_string(register_resp, "type", type, sizeof(type)) == 0 &&
            strcmp(type, "NM_TICKET") == 0) {
            if (handle_nm_ticket_command(&ctx, register_resp) < 0) {
                fprintf(stderr, "Failed to process ticket during register: %s\n", register_resp);
                free(register_resp);
                exit_code = 1;
                goto cleanup;
            }
            free(register_resp);
            register_resp = NULL;
            continue;
        }
        fprintf(stderr, "Unexpected NM message during register: %s\n", register_resp);
        free(register_resp);
        register_resp = NULL;
    }
    if (strcmp(status, "OK") != 0) {
        fprintf(stderr, "Register rejected by NM: %s\n", register_resp);
        free(register_resp);
        exit_code = 1;
        goto cleanup;
    }
    free(register_resp);

    ctx.listen_fd = net_listen(data_port, 64);
    if (ctx.listen_fd < 0) {
        fprintf(stderr, "Failed to listen on data port %s\n", data_port);
        exit_code = 1;
        goto cleanup;
    }

    fprintf(stderr, "Storage server %s listening on %s\n", ctx.id, data_port);

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(ctx.nm_fd, &readfds);
        FD_SET(ctx.listen_fd, &readfds);
        int maxfd = ctx.nm_fd > ctx.listen_fd ? ctx.nm_fd : ctx.listen_fd;
        int ready = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            exit_code = 1;
            break;
        }
        if (FD_ISSET(ctx.nm_fd, &readfds)) {
            if (process_nm_command(&ctx) < 0) {
                fprintf(stderr, "Lost NM connection\n");
                exit_code = 1;
                break;
            }
        }
        if (FD_ISSET(ctx.listen_fd, &readfds)) {
            struct sockaddr_storage addr;
            socklen_t addrlen = sizeof(addr);
            int client_fd = accept(ctx.listen_fd, (struct sockaddr *)&addr, &addrlen);
            if (client_fd >= 0) {
                struct client_task *task = malloc(sizeof(*task));
                if (!task) {
                    net_close(client_fd);
                } else {
                    task->ctx = &ctx;
                    task->client_fd = client_fd;
                    pthread_t tid;
                    if (pthread_create(&tid, NULL, data_client_thread, task) != 0) {
                        net_close(client_fd);
                        free(task);
                    } else {
                        pthread_detach(tid);
                    }
                }
            }
        }
    }

cleanup:
    if (ctx.listen_fd >= 0) {
        net_close(ctx.listen_fd);
    }
    if (ctx.nm_fd >= 0) {
        net_close(ctx.nm_fd);
    }
    ticket_table_destroy(&ctx.tickets);
    sentence_lock_table_destroy(&ctx);
    pthread_rwlock_destroy(&ctx.state_lock);
    pthread_mutex_destroy(&ctx.sentence_lock_mutex);
    pthread_mutex_destroy(&ctx.ticket_lock);
    if (logs_opened) {
        log_close(&ctx.log_general);
        log_close(&ctx.log_requests);
    }
    ss_state_destroy(&ctx.state);
    return exit_code;
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

static void ticket_table_init(struct ticket_table *table) {
    array_init(&table->entries, sizeof(struct auth_ticket));
}

static void ticket_table_destroy(struct ticket_table *table) {
    array_free(&table->entries);
}

static void ticket_table_prune(struct ticket_table *table) {
    time_t now = time(NULL);
    size_t i = 0;
    while (i < table->entries.len) {
        struct auth_ticket *t = array_get(&table->entries, i);
        if (t->expiry && t->expiry < now) {
            array_remove(&table->entries, i);
        } else {
            i++;
        }
    }
}

static int ticket_table_add(struct ticket_table *table,
                            const char *token,
                            const char *file,
                            const char *user,
                            const char *op,
                            time_t expiry) {
    struct auth_ticket ticket;
    memset(&ticket, 0, sizeof(ticket));
    snprintf(ticket.token, sizeof(ticket.token), "%s", token);
    snprintf(ticket.file, sizeof(ticket.file), "%s", file);
    snprintf(ticket.user, sizeof(ticket.user), "%s", user);
    snprintf(ticket.op, sizeof(ticket.op), "%s", op);
    ticket.expiry = expiry;
    return array_push(&table->entries, &ticket);
}

static struct auth_ticket *ticket_table_take(struct ticket_table *table,
                                             const char *token,
                                             const char *user,
                                             const char *file,
                                             const char *op) {
    ticket_table_prune(table);
    for (size_t i = 0; i < table->entries.len; ++i) {
        struct auth_ticket *t = array_get(&table->entries, i);
        if (strcmp(t->token, token) == 0 &&
            strcmp(t->user, user) == 0 &&
            strcmp(t->file, file) == 0 &&
            strcmp(t->op, op) == 0) {
            struct auth_ticket *copy = malloc(sizeof(struct auth_ticket));
            if (!copy) {
                return NULL;
            }
            *copy = *t;
            array_remove(&table->entries, i);
            return copy;
        }
    }
    return NULL;
}

static void sentence_lock_table_init(struct ss_context *ctx) {
    array_init(&ctx->sentence_locks, sizeof(struct sentence_lock));
}

static void sentence_lock_table_destroy(struct ss_context *ctx) {
    array_free(&ctx->sentence_locks);
}

static struct sentence_lock *sentence_lock_find(struct ss_context *ctx,
                                                const char *file,
                                                int sentence) {
    for (size_t i = 0; i < ctx->sentence_locks.len; ++i) {
        struct sentence_lock *entry = array_get(&ctx->sentence_locks, i);
        if (entry && entry->sentence == sentence && strcmp(entry->file, file) == 0) {
            return entry;
        }
    }
    return NULL;
}

static int sentence_lock_acquire(struct ss_context *ctx,
                                 const char *file,
                                 int sentence,
                                 const char *user) {
    pthread_mutex_lock(&ctx->sentence_lock_mutex);
    struct sentence_lock *existing = sentence_lock_find(ctx, file, sentence);
    if (existing) {
        pthread_mutex_unlock(&ctx->sentence_lock_mutex);
        errno = EBUSY;
        return -1;
    }
    struct sentence_lock entry;
    memset(&entry, 0, sizeof(entry));
    snprintf(entry.file, sizeof(entry.file), "%s", file);
    snprintf(entry.user, sizeof(entry.user), "%s", user);
    entry.sentence = sentence;
    int rc = array_push(&ctx->sentence_locks, &entry);
    pthread_mutex_unlock(&ctx->sentence_lock_mutex);
    return rc;
}

static void sentence_lock_release(struct ss_context *ctx,
                                  const char *file,
                                  const char *user,
                                  int sentence) {
    (void)user;
    pthread_mutex_lock(&ctx->sentence_lock_mutex);
    for (size_t i = 0; i < ctx->sentence_locks.len; ++i) {
        struct sentence_lock *entry = array_get(&ctx->sentence_locks, i);
        if (entry && entry->sentence == sentence && strcmp(entry->file, file) == 0) {
            array_remove(&ctx->sentence_locks, i);
            break;
        }
    }
    pthread_mutex_unlock(&ctx->sentence_lock_mutex);
}

static void string_array_init(struct array *arr) {
    array_init(arr, sizeof(char *));
}

static void string_array_clear(struct array *arr) {
    if (!arr) {
        return;
    }
    for (size_t i = 0; i < arr->len; ++i) {
        char **slot = array_get(arr, i);
        free(*slot);
    }
    array_free(arr);
}

static int string_array_push(struct array *arr, const char *value) {
    char *copy = strdup(value ? value : "");
    if (!copy) {
        return -1;
    }
    if (array_push(arr, &copy) < 0) {
        free(copy);
        return -1;
    }
    return 0;
}

static int string_array_insert(struct array *arr, size_t index, const char *value) {
    char *copy = strdup(value ? value : "");
    if (!copy) {
        return -1;
    }
    if (array_insert(arr, index, &copy) < 0) {
        free(copy);
        return -1;
    }
    return 0;
}

static char *string_array_get_value(struct array *arr, size_t index) {
    if (!arr) {
        return NULL;
    }
    char **slot = array_get(arr, index);
    return slot ? *slot : NULL;
}

static void string_array_remove(struct array *arr, size_t index) {
    if (!arr || index >= arr->len) {
        return;
    }
    char **slot = array_get(arr, index);
    free(*slot);
    array_remove(arr, index);
}

static void trim_spaces(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (unsigned char)s[len - 1] <= ' ') {
        s[len - 1] = '\0';
        len--;
    }
    size_t start = 0;
    while (s[start] && (unsigned char)s[start] <= ' ') {
        start++;
    }
    if (start > 0) {
        memmove(s, s + start, strlen(s + start) + 1);
    }
}

static int split_words(const char *sentence, struct array *out) {
    string_array_init(out);
    const char *p = sentence;
    while (*p) {
        while (*p && (unsigned char)*p <= ' ') {
            p++;
        }
        if (!*p) {
            break;
        }
        const char *start = p;
        while (*p && (unsigned char)*p > ' ') {
            p++;
        }
        size_t len = (size_t)(p - start);
        char *word = malloc(len + 1);
        if (!word) {
            string_array_clear(out);
            return -1;
        }
        memcpy(word, start, len);
        word[len] = '\0';
        if (array_push(out, &word) < 0) {
            free(word);
            string_array_clear(out);
            return -1;
        }
    }
    return 0;
}

static int split_sentences(const char *text, struct array *out) {
    string_array_init(out);
    size_t cap = strlen(text) + 1;
    char *buffer = malloc(cap);
    if (!buffer) {
        return -1;
    }
    size_t pos = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        char c = (char)*p;
        if (c == '\n' || c == '\r') {
            c = ' ';
        }
        buffer[pos++] = c;
        if (c == '.' || c == '!' || c == '?') {
            buffer[pos] = '\0';
            trim_spaces(buffer);
            if (buffer[0]) {
                if (string_array_push(out, buffer) < 0) {
                    free(buffer);
                    string_array_clear(out);
                    return -1;
                }
            }
            pos = 0;
        }
    }
    if (pos > 0) {
        buffer[pos] = '\0';
        trim_spaces(buffer);
        if (buffer[0]) {
            if (string_array_push(out, buffer) < 0) {
                free(buffer);
                string_array_clear(out);
                return -1;
            }
        }
    }
    free(buffer);
    return 0;
}

static char *join_words(struct array *words) {
    size_t total = 0;
    for (size_t i = 0; i < words->len; ++i) {
        char *w = string_array_get_value(words, i);
        total += strlen(w);
        if (i + 1 < words->len) {
            total += 1;
        }
    }
    char *result = malloc(total + 1);
    if (!result) {
        return NULL;
    }
    size_t offset = 0;
    for (size_t i = 0; i < words->len; ++i) {
        char *w = string_array_get_value(words, i);
        size_t len = strlen(w);
        memcpy(result + offset, w, len);
        offset += len;
        if (i + 1 < words->len) {
            result[offset++] = ' ';
        }
    }
    result[offset] = '\0';
    return result;
}

static char *join_sentences(struct array *sentences) {
    size_t total = 0;
    for (size_t i = 0; i < sentences->len; ++i) {
        char *s = string_array_get_value(sentences, i);
        total += strlen(s);
        if (i + 1 < sentences->len) {
            total += 1;
        }
    }
    char *result = malloc(total + 1);
    if (!result) {
        return NULL;
    }
    size_t offset = 0;
    for (size_t i = 0; i < sentences->len; ++i) {
        char *s = string_array_get_value(sentences, i);
        size_t len = strlen(s);
        memcpy(result + offset, s, len);
        offset += len;
        if (i + 1 < sentences->len) {
            result[offset++] = '\n';
        }
    }
    result[offset] = '\0';
    return result;
}

static char *load_text(const char *path, size_t *out_size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    size_t read = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[read] = '\0';
    if (out_size) {
        *out_size = read;
    }
    return buf;
}

static int store_text_atomic(const char *path, const char *content) {
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        return -1;
    }
    size_t len = strlen(content);
    if (fwrite(content, 1, len, fp) != len) {
        fclose(fp);
        unlink(tmp_path);
        return -1;
    }
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        fclose(fp);
        unlink(tmp_path);
        return -1;
    }
    fclose(fp);
    if (rename(tmp_path, path) < 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

static size_t count_words_in_text(const char *text) {
    size_t count = 0;
    int in_word = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p <= ' ') {
            in_word = 0;
        } else if (!in_word) {
            in_word = 1;
            count++;
        }
    }
    return count;
}

static void sleep_ms(int ms) {
    if (ms <= 0) {
        return;
    }
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}
