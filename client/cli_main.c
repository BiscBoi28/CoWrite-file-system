#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ctype.h>

#include "common/json_util.h"
#include "common/net_proto.h"

#define INPUT_BUF 512
#define MAX_JSON 4096

static char g_username[64];

static void trim_newline(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[--len] = '\0';
    }
}

static int socket_local_ip(int fd, char *buf, size_t buf_size) {
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) < 0) {
        return -1;
    }
    void *src = NULL;
    if (addr.ss_family == AF_INET) {
        src = &((struct sockaddr_in *)&addr)->sin_addr;
    } else if (addr.ss_family == AF_INET6) {
        src = &((struct sockaddr_in6 *)&addr)->sin6_addr;
    } else {
        return -1;
    }
    if (!inet_ntop(addr.ss_family, src, buf, buf_size)) {
        return -1;
    }
    return 0;
}

static int send_request(int fd, const char *payload, char **response_out) {
    if (response_out) {
        *response_out = NULL;
    }
    if (net_send_json(fd, payload) < 0) {
        return -1;
    }
    if (net_recv_json(fd, response_out) < 0) {
        return -1;
    }
    return 0;
}

static int parse_status(const char *response, char *status_buf, size_t status_len, char *msg_buf, size_t msg_len) {
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

static void print_error_response(const char *response) {
    char status[16];
    char message[256];
    if (parse_status(response, status, sizeof(status), message, sizeof(message)) < 0) {
        fprintf(stderr, "Error: unexpected response %s\n", response);
        return;
    }
    char code[32];
    if (json_get_string(response, "code", code, sizeof(code)) < 0) {
        code[0] = '\0';
    }
    if (code[0]) {
        fprintf(stderr, "%s (%s): %s\n", status, code, message[0] ? message : "");
    } else {
        fprintf(stderr, "%s: %s\n", status, message[0] ? message : "");
    }
}

static int nm_call(int nm_fd, char **response_out, const char *type, const char *body_fmt, ...) {
    char payload[MAX_JSON];
    if (body_fmt && body_fmt[0]) {
        char body[MAX_JSON];
        va_list ap;
        va_start(ap, body_fmt);
        int body_len = vsnprintf(body, sizeof(body), body_fmt, ap);
        va_end(ap);
        if (body_len < 0 || (size_t)body_len >= sizeof(body)) {
            return -1;
        }
        if (snprintf(payload, sizeof(payload), "{\"type\":\"%s\",%s}", type, body) >=
            (int)sizeof(payload)) {
            return -1;
        }
    } else {
        if (snprintf(payload, sizeof(payload), "{\"type\":\"%s\"}", type) >= (int)sizeof(payload)) {
            return -1;
        }
    }
    return send_request(nm_fd, payload, response_out);
}

static int ss_read(const char *host, const char *port, const char *file, const char *user, const char *ticket) {
    int fd = net_connect(host, port);
    if (fd < 0) {
        perror("connect storage");
        return -1;
    }
    char *file_esc = json_escape_dup(file);
    char *user_esc = json_escape_dup(user);
    char *ticket_esc = json_escape_dup(ticket);
    if (!file_esc || !user_esc || !ticket_esc) {
        fprintf(stderr, "Out of memory\n");
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
        fprintf(stderr, "Payload too large\n");
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
    if (send_request(fd, payload, &response) < 0) {
        fprintf(stderr, "READ failed\n");
        net_close(fd);
        return -1;
    }
    net_close(fd);
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        return -1;
    }
    char *content = NULL;
    if (json_get_string_alloc(response, "content", &content) < 0) {
        fprintf(stderr, "Missing content\n");
        free(response);
        return -1;
    }
    printf("--- %s ---\n%s\n-----------\n", file, content);
    free(content);
    free(response);
    return 0;
}

static int ss_stream(const char *host, const char *port, const char *file, const char *user, const char *ticket) {
    int fd = net_connect(host, port);
    if (fd < 0) {
        perror("connect storage");
        return -1;
    }
    char *file_esc = json_escape_dup(file);
    char *user_esc = json_escape_dup(user);
    char *ticket_esc = json_escape_dup(ticket);
    if (!file_esc || !user_esc || !ticket_esc) {
        fprintf(stderr, "Out of memory\n");
        free(file_esc);
        free(user_esc);
        free(ticket_esc);
        net_close(fd);
        return -1;
    }
    char payload[MAX_JSON];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"STREAM\",\"file\":\"%s\",\"user\":\"%s\",\"ticket\":\"%s\"}",
                 file_esc, user_esc, ticket_esc) >= (int)sizeof(payload)) {
        fprintf(stderr, "Payload too large\n");
        free(file_esc);
        free(user_esc);
        free(ticket_esc);
        net_close(fd);
        return -1;
    }
    free(file_esc);
    free(user_esc);
    free(ticket_esc);

    if (net_send_json(fd, payload) < 0) {
        fprintf(stderr, "STREAM start failed\n");
        net_close(fd);
        return -1;
    }
    char *response = NULL;
    if (net_recv_json(fd, &response) < 0) {
        fprintf(stderr, "STREAM handshake failed\n");
        net_close(fd);
        return -1;
    }
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        net_close(fd);
        return -1;
    }
    free(response);
    printf("Streaming %s...\n", file);
    while (1) {
        char *chunk = NULL;
        if (net_recv_json(fd, &chunk) < 0) {
            fprintf(stderr, "Stream interrupted\n");
            net_close(fd);
            return -1;
        }
        char chunk_status[16];
        if (json_get_string(chunk, "status", chunk_status, sizeof(chunk_status)) < 0) {
            free(chunk);
            continue;
        }
        if (strcmp(chunk_status, "DATA") == 0) {
            char word[256];
            if (json_get_string(chunk, "word", word, sizeof(word)) == 0) {
                printf("%s ", word);
                fflush(stdout);
            }
        } else if (strcmp(chunk_status, "DONE") == 0) {
            free(chunk);
            break;
        } else {
            print_error_response(chunk);
            free(chunk);
            break;
        }
        free(chunk);
    }
    printf("\n");
    net_close(fd);
    return 0;
}

static int ss_write_session(const char *host,
                            const char *port,
                            const char *file,
                            const char *user,
                            const char *ticket,
                            int sentence) {
    int fd = net_connect(host, port);
    if (fd < 0) {
        perror("connect storage");
        return -1;
    }
    char *file_esc = json_escape_dup(file);
    char *user_esc = json_escape_dup(user);
    char *ticket_esc = json_escape_dup(ticket);
    if (!file_esc || !user_esc || !ticket_esc) {
        fprintf(stderr, "Out of memory\n");
        free(file_esc);
        free(user_esc);
        free(ticket_esc);
        net_close(fd);
        return -1;
    }
    char payload[MAX_JSON];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"WRITE_BEGIN\",\"file\":\"%s\",\"user\":\"%s\",\"ticket\":\"%s\",\"sentence\":%d}",
                 file_esc, user_esc, ticket_esc, sentence) >= (int)sizeof(payload)) {
        fprintf(stderr, "Payload too large\n");
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
    if (send_request(fd, payload, &response) < 0) {
        fprintf(stderr, "WRITE_BEGIN failed\n");
        net_close(fd);
        return -1;
    }
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        net_close(fd);
        return -1;
    }
    char *current = NULL;
    if (json_get_string_alloc(response, "current", &current) < 0) {
        current = strdup("");
    }
    free(response);
    printf("Current sentence (%d): %s\n", sentence, current);
    printf("Enter edits as '<word_index> <content>' (use 0 for beginning). Finish with ETIRW.\n");

    int commit_requested = 0;
    int commit_success = 0;
    char line[INPUT_BUF];
    while (1) {
        printf("write> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) {
            printf("\n");
            break;
        }
        trim_newline(line);
        char *ptr = line;
        while (*ptr && isspace((unsigned char)*ptr)) {
            ptr++;
        }
        if (*ptr == '\0') {
            continue;
        }
        if (strcasecmp(ptr, "ETIRW") == 0) {
            commit_requested = 1;
            break;
        }
        char *save_ptr = NULL;
        char *idx_token = strtok_r(ptr, " 	", &save_ptr);
        if (!idx_token) {
            continue;
        }
        char *content = save_ptr;
        while (content && *content && isspace((unsigned char)*content)) {
            content++;
        }
        if (!content || !*content) {
            printf("Usage: <word_index> <content>\n");
            continue;
        }
        errno = 0;
        char *endptr = NULL;
        long user_index = strtol(idx_token, &endptr, 10);
        if (*endptr != '\0' || errno == ERANGE) {
            printf("Invalid index: %s\n", idx_token);
            continue;
        }
        if (user_index < 0) {
            printf("Index must be non-negative\n");
            continue;
        }
        int server_index = (int)user_index;
        if (user_index > 0) {
            server_index = (int)(user_index - 1);
        }
        char *escaped = json_escape_dup(content);
        if (!escaped) {
            fprintf(stderr, "Out of memory\n");
            break;
        }
        char cmd[MAX_JSON];
        if (snprintf(cmd, sizeof(cmd),
                     "{\"type\":\"WRITE_INSERT\",\"index\":%d,\"content\":\"%s\"}",
                     server_index, escaped) >= (int)sizeof(cmd)) {
            fprintf(stderr, "Command too large\n");
            free(escaped);
            continue;
        }
        free(escaped);
        char *insert_resp = NULL;
        if (send_request(fd, cmd, &insert_resp) < 0) {
            fprintf(stderr, "WRITE_INSERT failed\n");
            free(insert_resp);
            break;
        }
        if (parse_status(insert_resp, status, sizeof(status), NULL, 0) < 0 ||
            strcmp(status, "OK") != 0) {
            print_error_response(insert_resp);
        }
        free(insert_resp);
    }

    if (commit_requested) {
        char commit_cmd[] = "{\"type\":\"WRITE_COMMIT\"}";
        char *commit_resp = NULL;
        if (send_request(fd, commit_cmd, &commit_resp) < 0 ||
            parse_status(commit_resp, status, sizeof(status), NULL, 0) < 0 ||
            strcmp(status, "OK") != 0) {
            print_error_response(commit_resp ? commit_resp : "WRITE_COMMIT failed");
        } else {
            printf("Write committed.\n");
            commit_success = 1;
        }
        free(commit_resp);
    }

    if (!commit_success) {
        char abort_cmd[] = "{\"type\":\"WRITE_ABORT\"}";
        char *abort_resp = NULL;
        send_request(fd, abort_cmd, &abort_resp);
        free(abort_resp);
    }
    free(current);
    net_close(fd);
    return commit_success ? 0 : -1;
}

static int handle_view(int nm_fd, const char *flags) {
    char *response = NULL;
    if (nm_call(nm_fd, &response, "VIEW", flags && flags[0] ? "\"flags\":\"%s\"" : NULL, flags) < 0) {
        fprintf(stderr, "Failed to contact NM\n");
        return -1;
    }
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        return -1;
    }
    const char *pos = strstr(response, "\"files\":[");
    if (!pos) {
        printf("(no files)\n");
        free(response);
        return 0;
    }
    pos += strlen("\"files\":[");
    if (*pos == ']') {
        printf("(no files)\n");
        free(response);
        return 0;
    }
    printf("Files:\n");
    while (*pos) {
        if (*pos == '{') {
            const char *end = strchr(pos, '}');
            if (!end) {
                break;
            }
            size_t len = (size_t)(end - pos + 1);
            char chunk[512];
            if (len >= sizeof(chunk)) {
                len = sizeof(chunk) - 1;
            }
            memcpy(chunk, pos, len);
            chunk[len] = '\0';
            char name[128];
            char owner[128];
            char last_user[128];
            char primary[128] = "";
            char backup[128] = "";
            int words = -1;
            int chars = -1;
            int have_owner = json_get_string(chunk, "owner", owner, sizeof(owner)) == 0;
            if (json_get_string(chunk, "name", name, sizeof(name)) == 0) {
                if (have_owner && json_get_int(chunk, "words", &words) == 0 &&
                    json_get_int(chunk, "chars", &chars) == 0 &&
                    json_get_string(chunk, "lastAccessUser", last_user, sizeof(last_user)) == 0) {
                    json_get_string(chunk, "primaryServer", primary, sizeof(primary));
                    json_get_string(chunk, "backupServer", backup, sizeof(backup));
                    printf("  %s (owner: %s, words: %d, chars: %d, last user: %s)\n",
                           name, owner, words, chars, last_user);
                    printf("    primary: %s, backup: %s\n",
                           primary[0] ? primary : "none",
                           backup[0] ? backup : "none");
                } else {
                    printf("  %s\n", name);
                }
            }
            pos = end + 1;
        } else if (*pos == ']') {
            break;
        } else {
            pos++;
        }
    }
    free(response);
    return 0;
}

static int handle_list_users(int nm_fd) {
    char *response = NULL;
    if (nm_call(nm_fd, &response, "LIST", NULL) < 0) {
        fprintf(stderr, "Failed to contact NM\n");
        return -1;
    }
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        return -1;
    }
    const char *pos = strstr(response, "\"users\":[");
    if (!pos) {
        printf("No users.\n");
        free(response);
        return 0;
    }
    pos += strlen("\"users\":[");
    if (*pos == ']') {
        printf("No users.\n");
        free(response);
        return 0;
    }
    printf("Users:\n");
    while (*pos && *pos != ']') {
        if (*pos == '"') {
            pos++;
            const char *end = strchr(pos, '"');
            if (!end) {
                break;
            }
            printf("  %.*s\n", (int)(end - pos), pos);
            pos = end + 1;
        } else {
            pos++;
        }
    }
    free(response);
    return 0;
}

static int handle_info_cmd(int nm_fd, const char *file) {
    char *file_esc = json_escape_dup(file);
    if (!file_esc) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }
    char *response = NULL;
    if (nm_call(nm_fd, &response, "INFO", "\"file\":\"%s\"", file_esc) < 0) {
        fprintf(stderr, "Failed to contact NM\n");
        free(file_esc);
        return -1;
    }
    free(file_esc);
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        return -1;
    }
    const char *pos = strstr(response, "\"file\":{");
    if (!pos) {
        printf("No metadata available.\n");
        free(response);
        return 0;
    }
    pos += strlen("\"file\":{");
    const char *end = strchr(pos, '}');
    if (!end) {
        free(response);
        return 0;
    }
    size_t len = (size_t)(end - pos + 1);
    char chunk[512];
    if (len >= sizeof(chunk)) {
        len = sizeof(chunk) - 1;
    }
    memcpy(chunk, pos, len);
    chunk[len] = '\0';
    char name[128] = "";
    char owner[128] = "";
    char last_user[128] = "";
    char primary[128] = "";
    char backup[128] = "";
    int words = -1;
    int chars = -1;
    int created = 0;
    int modified = 0;
    int last_access = 0;
    json_get_string(chunk, "name", name, sizeof(name));
    json_get_string(chunk, "owner", owner, sizeof(owner));
    json_get_int(chunk, "words", &words);
    json_get_int(chunk, "chars", &chars);
    json_get_int(chunk, "created", &created);
    json_get_int(chunk, "modified", &modified);
    json_get_int(chunk, "lastAccess", &last_access);
    json_get_string(chunk, "lastAccessUser", last_user, sizeof(last_user));
    json_get_string(chunk, "primaryServer", primary, sizeof(primary));
    json_get_string(chunk, "backupServer", backup, sizeof(backup));
    printf("File: %s\n", name[0] ? name : file);
    printf("  Owner: %s\n", owner);
    printf("  Words: %d\n", words);
    printf("  Chars: %d\n", chars);
    printf("  Created: %d\n", created);
    printf("  Modified: %d\n", modified);
    printf("  Last Access: %d by %s\n", last_access, last_user);
    printf("  Primary Server: %s\n", primary[0] ? primary : "unknown");
    printf("  Backup Server: %s\n", backup[0] ? backup : "none");
    free(response);
    return 0;
}

static int parse_nm_endpoint(const char *response, char *host, size_t host_sz, char *port, size_t port_sz, char *ticket, size_t ticket_sz, int *sentence_out) {
    if (json_get_string(response, "host", host, host_sz) < 0 ||
        json_get_string(response, "port", port, port_sz) < 0 ||
        json_get_string(response, "ticket", ticket, ticket_sz) < 0) {
        return -1;
    }
    if (sentence_out) {
        if (json_get_int(response, "sentence", sentence_out) < 0) {
            *sentence_out = 0;
        }
    }
    return 0;
}

static int handle_create_cmd(int nm_fd, const char *file) {
    char *file_esc = json_escape_dup(file);
    if (!file_esc) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }
    char *response = NULL;
    int rc = nm_call(nm_fd, &response, "CREATE", "\"file\":\"%s\"", file_esc);
    free(file_esc);
    if (rc < 0) {
        fprintf(stderr, "Failed to contact NM\n");
        return -1;
    }
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        return -1;
    }
    printf("Created %s.\n", file);
    free(response);
    return 0;
}

static int handle_delete_cmd(int nm_fd, const char *file) {
    char *file_esc = json_escape_dup(file);
    if (!file_esc) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }
    char *response = NULL;
    int rc = nm_call(nm_fd, &response, "DELETE", "\"file\":\"%s\"", file_esc);
    free(file_esc);
    if (rc < 0) {
        fprintf(stderr, "Failed to contact NM\n");
        return -1;
    }
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        return -1;
    }
    printf("Deleted %s.\n", file);
    free(response);
    return 0;
}

static int handle_read_cmd(int nm_fd, const char *file) {
    char *file_esc = json_escape_dup(file);
    if (!file_esc) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }
    char *response = NULL;
    if (nm_call(nm_fd, &response, "READ", "\"file\":\"%s\"", file_esc) < 0) {
        fprintf(stderr, "Failed to contact NM\n");
        free(file_esc);
        return -1;
    }
    free(file_esc);
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        return -1;
    }
    char host[128];
    char port[32];
    char ticket[128];
    if (parse_nm_endpoint(response, host, sizeof(host), port, sizeof(port), ticket, sizeof(ticket), NULL) < 0) {
        fprintf(stderr, "Malformed response\n");
        free(response);
        return -1;
    }
    int rc = ss_read(host, port, file, g_username, ticket);
    free(response);
    return rc;
}

static int handle_stream_cmd(int nm_fd, const char *file) {
    char *file_esc = json_escape_dup(file);
    if (!file_esc) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }
    char *response = NULL;
    if (nm_call(nm_fd, &response, "STREAM", "\"file\":\"%s\"", file_esc) < 0) {
        fprintf(stderr, "Failed to contact NM\n");
        free(file_esc);
        return -1;
    }
    free(file_esc);
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        return -1;
    }
    char host[128];
    char port[32];
    char ticket[128];
    if (parse_nm_endpoint(response, host, sizeof(host), port, sizeof(port), ticket, sizeof(ticket), NULL) < 0) {
        fprintf(stderr, "Malformed response\n");
        free(response);
        return -1;
    }
    int rc = ss_stream(host, port, file, g_username, ticket);
    free(response);
    return rc;
}

static int handle_write_cmd(int nm_fd, const char *file, int sentence) {
    char *file_esc = json_escape_dup(file);
    if (!file_esc) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }
    char *response = NULL;
    if (nm_call(nm_fd, &response, "WRITE", "\"file\":\"%s\",\"sentence\":%d", file_esc, sentence) < 0) {
        fprintf(stderr, "Failed to contact NM\n");
        free(file_esc);
        return -1;
    }
    free(file_esc);
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        return -1;
    }
    char host[128];
    char port[32];
    char ticket[128];
    int sentence_idx = sentence;
    if (parse_nm_endpoint(response, host, sizeof(host), port, sizeof(port), ticket, sizeof(ticket), &sentence_idx) < 0) {
        fprintf(stderr, "Malformed response\n");
        free(response);
        return -1;
    }
    free(response);
    return ss_write_session(host, port, file, g_username, ticket, sentence_idx);
}

static int handle_addaccess_cmd(int nm_fd, const char *file, const char *user, int write_perm) {
    char *file_esc = json_escape_dup(file);
    char *user_esc = json_escape_dup(user);
    if (!file_esc || !user_esc) {
        fprintf(stderr, "Out of memory\n");
        free(file_esc);
        free(user_esc);
        return -1;
    }
    const char *mode = write_perm ? "RW" : "R";
    char *response = NULL;
    if (nm_call(nm_fd, &response, "ADDACCESS",
                "\"file\":\"%s\",\"user\":\"%s\",\"mode\":\"%s\"",
                file_esc, user_esc, mode) < 0) {
        fprintf(stderr, "Failed to contact NM\n");
        free(file_esc);
        free(user_esc);
        return -1;
    }
    free(file_esc);
    free(user_esc);
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        return -1;
    }
    printf("Access granted.\n");
    free(response);
    return 0;
}

static int handle_remaccess_cmd(int nm_fd, const char *file, const char *user) {
    char *file_esc = json_escape_dup(file);
    char *user_esc = json_escape_dup(user);
    if (!file_esc || !user_esc) {
        fprintf(stderr, "Out of memory\n");
        free(file_esc);
        free(user_esc);
        return -1;
    }
    char *response = NULL;
    if (nm_call(nm_fd, &response, "REMACCESS",
                "\"file\":\"%s\",\"user\":\"%s\"",
                file_esc, user_esc) < 0) {
        fprintf(stderr, "Failed to contact NM\n");
        free(file_esc);
        free(user_esc);
        return -1;
    }
    free(file_esc);
    free(user_esc);
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        return -1;
    }
    printf("Access removed.\n");
    free(response);
    return 0;
}

static int handle_undo_cmd(int nm_fd, const char *file) {
    char *file_esc = json_escape_dup(file);
    if (!file_esc) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }
    char *response = NULL;
    if (nm_call(nm_fd, &response, "UNDO", "\"file\":\"%s\"", file_esc) < 0) {
        fprintf(stderr, "Failed to contact NM\n");
        free(file_esc);
        return -1;
    }
    free(file_esc);
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        return -1;
    }
    printf("Undo successful.\n");
    free(response);
    return 0;
}

static int handle_exec_cmd(int nm_fd, const char *file) {
    char *file_esc = json_escape_dup(file);
    if (!file_esc) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }
    char *response = NULL;
    if (nm_call(nm_fd, &response, "EXEC", "\"file\":\"%s\"", file_esc) < 0) {
        fprintf(stderr, "Failed to contact NM\n");
        free(file_esc);
        return -1;
    }
    free(file_esc);
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) == 0 && strcmp(status, "OK") == 0) {
        char *output = NULL;
        if (json_get_string_alloc(response, "output", &output) == 0) {
            printf("%s\n", output);
            free(output);
        } else {
            printf("EXEC succeeded.\n");
        }
    } else {
        print_error_response(response);
        free(response);
        return -1;
    }
    free(response);
    return 0;
}

static void print_help(void) {
    printf("Commands:\n");
    printf("  VIEW [-a] [-l]\n");
    printf("  LIST\n");
    printf("  INFO <file>\n");
    printf("  CREATE <file>\n");
    printf("  DELETE <file>\n");
    printf("  READ <file>\n");
    printf("  WRITE <file> [sentence]\n");
    printf("    After WRITE, enter '<word_index> <content>' lines and finish with ETIRW.\n");
    printf("  STREAM <file>\n");
    printf("  ADDACCESS <file> <user> [rw]\n");
    printf("  REMACCESS <file> <user>\n");
    printf("  UNDO <file>\n");
    printf("  EXEC <file>\n");
    printf("  HELP\n");
    printf("  QUIT\n");
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <nm_host> <nm_port> [preferred_ss_port]\n", argv[0]);
        return 1;
    }

    const char *nm_host = argv[1];
    const char *nm_port = argv[2];
    const char *preferred_ss_port = (argc == 4) ? argv[3] : "0";

    int nm_fd = net_connect(nm_host, nm_port);
    if (nm_fd < 0) {
        perror("net_connect");
        return 1;
    }

    printf("Username: ");
    fflush(stdout);
    if (!fgets(g_username, sizeof(g_username), stdin)) {
        fprintf(stderr, "Failed to read username\n");
        net_close(nm_fd);
        return 1;
    }
    trim_newline(g_username);

    char client_ip[INET6_ADDRSTRLEN];
    if (socket_local_ip(nm_fd, client_ip, sizeof(client_ip)) < 0) {
        snprintf(client_ip, sizeof(client_ip), "unknown");
    }

    char *user_esc = json_escape_dup(g_username);
    char *ip_esc = json_escape_dup(client_ip);
    char *nm_port_esc = json_escape_dup(nm_port);
    char *ss_port_esc = json_escape_dup(preferred_ss_port);
    if (!user_esc || !ip_esc || !nm_port_esc || !ss_port_esc) {
        fprintf(stderr, "Out of memory\n");
        free(user_esc);
        free(ip_esc);
        free(nm_port_esc);
        free(ss_port_esc);
        net_close(nm_fd);
        return 1;
    }

    char payload[MAX_JSON];
    if (snprintf(payload, sizeof(payload),
                 "{\"type\":\"CLIENT_HELLO\",\"user\":\"%s\",\"clientIp\":\"%s\","
                 "\"nmPort\":\"%s\",\"ssPort\":\"%s\"}",
                 user_esc, ip_esc, nm_port_esc, ss_port_esc) >= (int)sizeof(payload)) {
        fprintf(stderr, "Handshake payload too large\n");
        free(user_esc);
        free(ip_esc);
        free(nm_port_esc);
        free(ss_port_esc);
        net_close(nm_fd);
        return 1;
    }
    free(user_esc);
    free(ip_esc);
    free(nm_port_esc);
    free(ss_port_esc);

    char *response = NULL;
    if (send_request(nm_fd, payload, &response) < 0) {
        fprintf(stderr, "Handshake failed\n");
        net_close(nm_fd);
        return 1;
    }
    char status[16];
    if (parse_status(response, status, sizeof(status), NULL, 0) < 0 || strcmp(status, "OK") != 0) {
        print_error_response(response);
        free(response);
        net_close(nm_fd);
        return 1;
    }
    free(response);
    printf("Connected as %s. Type 'help' for commands.\n", g_username);

    char input[INPUT_BUF];
    char *save = NULL;
    while (1) {
        printf("docs> ");
        fflush(stdout);
        if (!fgets(input, sizeof(input), stdin)) {
            printf("\n");
            break;
        }
        trim_newline(input);
        if (input[0] == '\0') {
            continue;
        }
        save = NULL;
        char *cmd = strtok_r(input, " ", &save);
        if (!cmd) {
            continue;
        }
        for (char *p = cmd; *p; ++p) {
            *p = toupper((unsigned char)*p);
        }
        if (strcmp(cmd, "HELP") == 0) {
            print_help();
            continue;
        }
        if (strcmp(cmd, "VIEW") == 0) {
            char flags[4] = "";
            char *token = strtok_r(NULL, " ", &save);
            while (token) {
                if (token[0] == '-') {
                    for (size_t i = 1; token[i]; ++i) {
                        char flag = (char)tolower((unsigned char)token[i]);
                        if (flag == 'a' && !strchr(flags, 'a')) {
                            strcat(flags, "a");
                        } else if (flag == 'l' && !strchr(flags, 'l')) {
                            strcat(flags, "l");
                        }
                    }
                }
                token = strtok_r(NULL, " ", &save);
            }
            handle_view(nm_fd, flags);
            continue;
        }
        if (strcmp(cmd, "LIST") == 0) {
            handle_list_users(nm_fd);
            continue;
        }
        if (strcmp(cmd, "INFO") == 0) {
            char *file = strtok_r(NULL, "", &save);
            if (!file) {
                printf("usage: INFO <file>\n");
                continue;
            }
            while (*file && isspace((unsigned char)*file)) file++;
            handle_info_cmd(nm_fd, file);
            continue;
        }
        if (strcmp(cmd, "CREATE") == 0) {
            char *file = strtok_r(NULL, "", &save);
            if (!file) {
                printf("usage: CREATE <file>\n");
                continue;
            }
            while (*file && isspace((unsigned char)*file)) file++;
            handle_create_cmd(nm_fd, file);
            continue;
        }
        if (strcmp(cmd, "DELETE") == 0) {
            char *file = strtok_r(NULL, "", &save);
            if (!file) {
                printf("usage: DELETE <file>\n");
                continue;
            }
            while (*file && isspace((unsigned char)*file)) file++;
            handle_delete_cmd(nm_fd, file);
            continue;
        }
        if (strcmp(cmd, "READ") == 0) {
            char *file = strtok_r(NULL, "", &save);
            if (!file) {
                printf("usage: READ <file>\n");
                continue;
            }
            while (*file && isspace((unsigned char)*file)) file++;
            handle_read_cmd(nm_fd, file);
            continue;
        }
        if (strcmp(cmd, "STREAM") == 0) {
            char *file = strtok_r(NULL, "", &save);
            if (!file) {
                printf("usage: STREAM <file>\n");
                continue;
            }
            while (*file && isspace((unsigned char)*file)) file++;
            handle_stream_cmd(nm_fd, file);
            continue;
        }
        if (strcmp(cmd, "WRITE") == 0) {
            char *file = strtok_r(NULL, " ", &save);
            if (!file) {
                printf("usage: WRITE <file> [sentence]\n");
                continue;
            }
            char *sentence_tok = strtok_r(NULL, "", &save);
            int sentence = 0;
            if (sentence_tok) {
                while (*sentence_tok && isspace((unsigned char)*sentence_tok)) sentence_tok++;
                if (*sentence_tok) {
                    char *endptr = NULL;
                    long val = strtol(sentence_tok, &endptr, 10);
                    if (endptr && *endptr != '\0') {
                        printf("Invalid sentence index\n");
                        continue;
                    }
                    sentence = (int)val;
                }
            }
            handle_write_cmd(nm_fd, file, sentence);
            continue;
        }
        if (strcmp(cmd, "ADDACCESS") == 0) {
            char *file = strtok_r(NULL, " ", &save);
            char *user = strtok_r(NULL, " ", &save);
            char *mode = strtok_r(NULL, "", &save);
            if (!file || !user) {
                printf("usage: ADDACCESS <file> <user> [rw]\n");
                continue;
            }
            int write_perm = 0;
            if (mode) {
                while (*mode && isspace((unsigned char)*mode)) mode++;
                if (*mode == 'r' || *mode == 'R') {
                    if (strchr(mode, 'w') || strchr(mode, 'W')) {
                        write_perm = 1;
                    }
                } else if (*mode == 'w' || *mode == 'W') {
                    write_perm = 1;
                }
            }
            handle_addaccess_cmd(nm_fd, file, user, write_perm);
            continue;
        }
        if (strcmp(cmd, "REMACCESS") == 0) {
            char *file = strtok_r(NULL, " ", &save);
            char *user = strtok_r(NULL, "", &save);
            if (!file || !user) {
                printf("usage: REMACCESS <file> <user>\n");
                continue;
            }
            while (*user && isspace((unsigned char)*user)) user++;
            handle_remaccess_cmd(nm_fd, file, user);
            continue;
        }
        if (strcmp(cmd, "UNDO") == 0) {
            char *file = strtok_r(NULL, "", &save);
            if (!file) {
                printf("usage: UNDO <file>\n");
                continue;
            }
            while (*file && isspace((unsigned char)*file)) file++;
            handle_undo_cmd(nm_fd, file);
            continue;
        }
        if (strcmp(cmd, "EXEC") == 0) {
            char *file = strtok_r(NULL, "", &save);
            if (!file) {
                printf("usage: EXEC <file>\n");
                continue;
            }
            while (*file && isspace((unsigned char)*file)) file++;
            handle_exec_cmd(nm_fd, file);
            continue;
        }
        if (strcmp(cmd, "QUIT") == 0) {
            break;
        }
        printf("Unknown command. Type 'help'.\n");
    }

    net_close(nm_fd);
    printf("Bye.\n");
    return 0;
}
