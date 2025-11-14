#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
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

struct write_session {
    int active;
    int sentence_index;
    char user[SS_USER_MAX];
    char *original_text;
    char *sentence_text;
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
    struct log_writer log_general;
    struct log_writer log_requests;
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
    session->original_text = NULL;
    session->sentence_text = NULL;
    string_array_clear(&session->sentences);
    session->active = 0;
    session->sentence_index = -1;
}

static int write_session_begin(struct write_session *session,
                               struct ss_file *file,
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

    if (sentence_index < (int)session->sentences.len) {
        char *existing = string_array_get_value(&session->sentences, (size_t)sentence_index);
        session->sentence_text = strdup(existing);
    } else {
        session->sentence_text = strdup("");
    }
    if (!session->sentence_text) {
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
    if (index < 0 || index > (int)words.len) {
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
    if (index < 0 || index >= (int)words.len) {
        string_array_clear(&words);
        errno = EINVAL;
        return -1;
    }
    string_array_remove(&words, (size_t)index);
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
    if (index < 0 || index >= (int)words.len) {
        string_array_clear(&words);
        errno = EINVAL;
        return -1;
    }
    string_array_remove(&words, (size_t)index);
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

static int write_session_commit(struct write_session *session,
                                struct ss_context *ctx,
                                struct ss_file *file,
                                char **out_text) {
    (void)ctx;
    struct array final_sentences;
    string_array_init(&final_sentences);

    for (size_t i = 0; i < session->sentences.len; ++i) {
        char *s = string_array_get_value(&session->sentences, i);
        if ((int)i == session->sentence_index) {
            struct array parts;
            if (split_sentences(session->sentence_text, &parts) < 0) {
                string_array_clear(&final_sentences);
                return -1;
            }
            if (parts.len == 0) {
                /* Sentence removed */
            } else {
                for (size_t k = 0; k < parts.len; ++k) {
                    char *part = string_array_get_value(&parts, k);
                    if (string_array_push(&final_sentences, part) < 0) {
                        string_array_clear(&parts);
                        string_array_clear(&final_sentences);
                        return -1;
                    }
                }
            }
            string_array_clear(&parts);
        } else {
            if (string_array_push(&final_sentences, s) < 0) {
                string_array_clear(&final_sentences);
                return -1;
            }
        }
    }

    if (session->sentence_index == (int)session->sentences.len) {
        struct array parts;
        if (split_sentences(session->sentence_text, &parts) < 0) {
            string_array_clear(&final_sentences);
            return -1;
        }
        for (size_t k = 0; k < parts.len; ++k) {
            char *part = string_array_get_value(&parts, k);
            if (string_array_push(&final_sentences, part) < 0) {
                string_array_clear(&parts);
                string_array_clear(&final_sentences);
                return -1;
            }
        }
        string_array_clear(&parts);
    }

    char *text = join_sentences(&final_sentences);
    string_array_clear(&final_sentences);
    if (!text) {
        text = strdup("");
        if (!text) {
            return -1;
        }
    }

    if (store_text_atomic(file->undo_path, session->original_text) < 0) {
        free(text);
        return -1;
    }
    if (store_text_atomic(file->data_path, text) < 0) {
        free(text);
        return -1;
    }

    file->char_count = strlen(text);
    file->word_count = count_words_in_text(text);
    time_t now = time(NULL);
    file->modified = now;
    file->last_access = now;
    snprintf(file->last_access_user, sizeof(file->last_access_user), "%s", session->user);
    file->lock_active = 0;
    file->lock_sentence = -1;
    ss_state_save_meta(&ctx->state, file);

    if (out_text) {
        *out_text = text;
    } else {
        free(text);
    }
    session->active = 0;
    return 0;
}

static void notify_nm_file_update(struct ss_context *ctx, struct ss_file *file) {
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

static int perform_undo(struct ss_context *ctx,
                        struct ss_file *file,
                        const char *user,
                        char **out_text) {
    char *undo_text = load_text(file->undo_path, NULL);
    if (!undo_text) {
        errno = ENOENT;
        return -1;
    }
    char *current_text = load_text(file->data_path, NULL);
    if (!current_text) {
        current_text = strdup("");
        if (!current_text) {
            free(undo_text);
            return -1;
        }
    }
    if (store_text_atomic(file->data_path, undo_text) < 0) {
        free(undo_text);
        free(current_text);
        return -1;
    }
    if (store_text_atomic(file->undo_path, current_text) < 0) {
        /* Not fatal, but log */
        log_event(ctx, "Failed to update undo file for %s: %s", file->name, strerror(errno));
    }
    file->char_count = strlen(undo_text);
    file->word_count = count_words_in_text(undo_text);
    time_t now = time(NULL);
    file->modified = now;
    file->last_access = now;
    snprintf(file->last_access_user, sizeof(file->last_access_user), "%s", user);
    ss_state_save_meta(&ctx->state, file);
    log_request(ctx, "UNDO user=%s file=%s words=%zu chars=%zu",
                user, file->name, file->word_count, file->char_count);
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
    struct auth_ticket *ticket = ticket_table_take(&ctx->tickets, token, user, file, op);
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
                       struct ss_file *file,
                       const char *user) {
    size_t size = 0;
    char *text = load_text(file->data_path, &size);
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
    file->last_access = now;
    snprintf(file->last_access_user, sizeof(file->last_access_user), "%s", user);
    ss_state_save_meta(&ctx->state, file);
    notify_nm_file_update(ctx, file);
    log_request(ctx, "READ user=%s file=%s", user, file->name);
    char extra[MAX_JSON];
    if (snprintf(extra, sizeof(extra),
                 "\"file\":\"%s\",\"content\":\"%s\",\"words\":%zu,\"chars\":%zu",
                 file->name, escaped, file->word_count, file->char_count) >= (int)sizeof(extra)) {
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
                         struct ss_file *file,
                         const char *user) {
    char *text = load_text(file->data_path, NULL);
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
    file->last_access = now;
    snprintf(file->last_access_user, sizeof(file->last_access_user), "%s", user);
    ss_state_save_meta(&ctx->state, file);
    notify_nm_file_update(ctx, file);
    log_request(ctx, "STREAM user=%s file=%s words=%zu", user, file->name, file->word_count);
    return 0;
}

static int handle_write(struct ss_context *ctx,
                        int client_fd,
                        struct ss_file *file,
                        const char *user,
                        int sentence_index) {
    if (file->lock_active && strcmp(file->lock_user, user) != 0) {
        return send_error_response(client_fd, ERR_LOCKED, "sentence locked");
    }
    file->lock_active = 1;
    file->lock_sentence = sentence_index;
    snprintf(file->lock_user, sizeof(file->lock_user), "%s", user);

    struct write_session session;
    write_session_init(&session);
    if (write_session_begin(&session, file, user, sentence_index) < 0) {
        file->lock_active = 0;
        file->lock_sentence = -1;
        return send_error_response(client_fd, ERR_INTERNAL, "write init failed");
    }

    char *escaped_text = json_escape_dup(session.sentence_text);
    if (!escaped_text) {
        write_session_clear(&session);
        file->lock_active = 0;
        file->lock_sentence = -1;
        return send_error_response(client_fd, ERR_INTERNAL, "encode failed");
    }
    char extra[MAX_JSON];
    if (snprintf(extra, sizeof(extra),
                 "\"mode\":\"WRITE\",\"current\":\"%s\",\"sentence\":%d",
                 escaped_text, sentence_index) >= (int)sizeof(extra)) {
        free(escaped_text);
        write_session_clear(&session);
        file->lock_active = 0;
        file->lock_sentence = -1;
        return send_error_response(client_fd, ERR_INTERNAL, "response too large");
    }
    free(escaped_text);
    if (send_ok(client_fd, extra) < 0) {
        write_session_clear(&session);
        file->lock_active = 0;
        file->lock_sentence = -1;
        return -1;
    }
    log_request(ctx, "WRITE_BEGIN user=%s file=%s sentence=%d",
                user, file->name, sentence_index);

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
                    send_error_response(client_fd, ERR_CONFLICT, "insert failed");
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
                    send_error_response(client_fd, ERR_CONFLICT, "replace failed");
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
                send_error_response(client_fd, ERR_CONFLICT, "delete failed");
            } else {
                send_ok(client_fd, "\"step\":\"DELETE\"");
            }
        } else if (strcmp(type, "WRITE_COMMIT") == 0) {
            char *final_text = NULL;
            if (write_session_commit(&session, ctx, file, &final_text) < 0) {
                send_error_response(client_fd, ERR_INTERNAL, "commit failed");
            } else {
                char *escaped_final = json_escape_dup(final_text);
                if (escaped_final) {
                    char commit_extra[MAX_JSON];
                    if (snprintf(commit_extra, sizeof(commit_extra),
                                 "\"step\":\"COMMIT\",\"words\":%zu,\"chars\":%zu,\"content\":\"%s\"",
                                 file->word_count, file->char_count, escaped_final) <
                        (int)sizeof(commit_extra)) {
                        send_ok(client_fd, commit_extra);
                    } else {
                        send_ok(client_fd, "\"step\":\"COMMIT\"");
                    }
                    free(escaped_final);
                } else {
                    send_ok(client_fd, "\"step\":\"COMMIT\"");
                }
                log_request(ctx, "WRITE_COMMIT user=%s file=%s words=%zu chars=%zu",
                            user, file->name, file->word_count, file->char_count);
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
            log_request(ctx, "WRITE_ABORT user=%s file=%s", user, file->name);
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
    file->lock_active = 0;
    file->lock_sentence = -1;
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
    size_t index = 0;
    struct ss_file *file = ss_state_find(&ctx->state, file_name, &index);
    if (!file) {
        send_error_response(client_fd, ERR_NOTFOUND, "file not found");
        free(json);
        net_close(client_fd);
        return;
    }
    struct auth_ticket *ticket = NULL;
    if (strcmp(type, "READ") == 0) {
        if (validate_ticket(ctx, token, user, file_name, "READ", &ticket) < 0) {
            send_error_response(client_fd, ERR_NOAUTH, "invalid ticket");
        } else {
            handle_read(ctx, client_fd, file, user);
        }
    } else if (strcmp(type, "STREAM") == 0) {
        if (validate_ticket(ctx, token, user, file_name, "STREAM", &ticket) < 0) {
            send_error_response(client_fd, ERR_NOAUTH, "invalid ticket");
        } else {
            handle_stream(ctx, client_fd, file, user);
        }
    } else if (strcmp(type, "WRITE_BEGIN") == 0) {
        int sentence_index = 0;
        if (json_get_int(json, "sentence", &sentence_index) < 0) {
            send_error_response(client_fd, ERR_BADREQ, "missing sentence");
        } else if (validate_ticket(ctx, token, user, file_name, "WRITE", &ticket) < 0) {
            send_error_response(client_fd, ERR_NOAUTH, "invalid ticket");
        } else {
            handle_write(ctx, client_fd, file, user, sentence_index);
        }
    } else {
        send_error_response(client_fd, ERR_BADREQ, "unsupported operation");
    }
    free(ticket);
    free(json);
    net_close(client_fd);
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
        } else if (ss_state_add(&ctx->state, name, owner) < 0) {
            send_error_response(ctx->nm_fd, ERR_EXISTS, strerror(errno));
        } else {
            send_ok(ctx->nm_fd, "\"op\":\"CREATE\"");
        }
    } else if (strcmp(type, "NM_DELETE") == 0) {
        char name[SS_NAME_MAX];
        if (json_get_string(json, "file", name, sizeof(name)) < 0 ||
            !valid_filename(name)) {
            send_error_response(ctx->nm_fd, ERR_BADREQ, "invalid delete");
        } else if (ss_state_remove(&ctx->state, name) < 0) {
            send_error_response(ctx->nm_fd, ERR_NOTFOUND, "file missing");
        } else {
            send_ok(ctx->nm_fd, "\"op\":\"DELETE\"");
        }
    } else if (strcmp(type, "NM_TICKET") == 0) {
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
            send_error_response(ctx->nm_fd, ERR_BADREQ, "invalid ticket");
        } else {
            ticket_table_add(&ctx->tickets, token, file_name, user, op, (time_t)expiry);
            send_ok(ctx->nm_fd, "\"op\":\"TICKET\"");
        }
    } else if (strcmp(type, "NM_UNDO") == 0) {
        char file_name[SS_NAME_MAX];
        char user[SS_USER_MAX];
        if (json_get_string(json, "file", file_name, sizeof(file_name)) < 0 ||
            json_get_string(json, "user", user, sizeof(user)) < 0) {
            send_error_response(ctx->nm_fd, ERR_BADREQ, "invalid undo");
        } else {
            size_t idx = 0;
            struct ss_file *file = ss_state_find(&ctx->state, file_name, &idx);
            if (!file) {
                send_error_response(ctx->nm_fd, ERR_NOTFOUND, "file missing");
            } else {
                char *text = NULL;
                if (perform_undo(ctx, file, user, &text) < 0) {
                    send_error_response(ctx->nm_fd, ERR_CONFLICT, "undo failed");
                } else {
                    char *escaped = json_escape_dup(text);
                    if (escaped) {
                        char extra[MAX_JSON];
                        if (snprintf(extra, sizeof(extra),
                                     "\"op\":\"UNDO\",\"words\":%zu,\"chars\":%zu,\"content\":\"%s\"",
                                     file->word_count, file->char_count, escaped) <
                            (int)sizeof(extra)) {
                            send_ok(ctx->nm_fd, extra);
                        } else {
                            send_ok(ctx->nm_fd, "\"op\":\"UNDO\"");
                        }
                        free(escaped);
                    } else {
                        send_ok(ctx->nm_fd, "\"op\":\"UNDO\"");
                    }
                    notify_nm_file_update(ctx, file);
                    free(text);
                }
            }
        }
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
    const char *storage_dir = argv[6];

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

    if (ss_state_init(&ctx.state, storage_dir) < 0) {
        fprintf(stderr, "Failed to initialise storage state: %s\n", strerror(errno));
        return 1;
    }

    char log_dir[512];
    snprintf(log_dir, sizeof(log_dir), "%s/logs", storage_dir);
    if (ensure_directory(log_dir) < 0) {
        fprintf(stderr, "Failed to create log directory: %s\n", strerror(errno));
        exit_code = 1;
        goto cleanup;
    }
    char general_log[512];
    char request_log[512];
    if (snprintf(general_log, sizeof(general_log), "%s/ss.log", log_dir) >=
            (int)sizeof(general_log) ||
        snprintf(request_log, sizeof(request_log), "%s/requests.log", log_dir) >=
            (int)sizeof(request_log)) {
        fprintf(stderr, "Log path too long\n");
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
    if (net_recv_json(ctx.nm_fd, &register_resp) < 0) {
        fprintf(stderr, "Failed to receive register acknowledgement\n");
        exit_code = 1;
        goto cleanup;
    }
    char status[16];
    if (json_get_string(register_resp, "status", status, sizeof(status)) < 0 ||
        strcmp(status, "OK") != 0) {
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
                handle_data_client(&ctx, client_fd);
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
