#define _POSIX_C_SOURCE 200809L

#include "nm_state.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void clear_state(struct nm_state *state) {
    state->server_count = 0;
    state->file_count = 0;
    state->user_count = 0;
    state->cache_count = 0;
}

void nm_state_init(struct nm_state *state, const char *persist_path) {
    memset(state, 0, sizeof(*state));
    if (persist_path) {
        snprintf(state->persist_path, sizeof(state->persist_path), "%s", persist_path);
    }
    clear_state(state);
    if (state->persist_path[0]) {
        nm_state_load(state);
    }
}

void nm_state_destroy(struct nm_state *state) {
    (void)state;
}

static struct storage_server *find_server(struct nm_state *state, const char *id) {
    for (size_t i = 0; i < state->server_count; ++i) {
        if (strcmp(state->servers[i].id, id) == 0) {
            return &state->servers[i];
        }
    }
    return NULL;
}

int nm_find_server_by_id(const struct nm_state *state, const char *id) {
    for (size_t i = 0; i < state->server_count; ++i) {
        if (strcmp(state->servers[i].id, id) == 0) {
            return (int)i;
        }
    }
    return -1;
}

struct storage_server *nm_get_server(struct nm_state *state, int index) {
    if (index < 0 || (size_t)index >= state->server_count) {
        return NULL;
    }
    return &state->servers[index];
}

int nm_register_server(struct nm_state *state,
                       const char *id,
                       const char *host,
                       const char *ctrl_port,
                       const char *data_port,
                       int ctrl_fd) {
    struct storage_server *existing = find_server(state, id);
    if (existing) {
        snprintf(existing->host, sizeof(existing->host), "%s", host);
        snprintf(existing->ctrl_port, sizeof(existing->ctrl_port), "%s", ctrl_port);
        snprintf(existing->data_port, sizeof(existing->data_port), "%s", data_port);
        existing->ctrl_fd = ctrl_fd;
        existing->online = 1;
        return (int)(existing - state->servers);
    }
    if (state->server_count >= NM_MAX_SERVERS) {
        return -1;
    }
    struct storage_server *ss = &state->servers[state->server_count];
    memset(ss, 0, sizeof(*ss));
    snprintf(ss->id, sizeof(ss->id), "%s", id);
    snprintf(ss->host, sizeof(ss->host), "%s", host);
    snprintf(ss->ctrl_port, sizeof(ss->ctrl_port), "%s", ctrl_port);
    snprintf(ss->data_port, sizeof(ss->data_port), "%s", data_port);
    ss->ctrl_fd = ctrl_fd;
    ss->online = 1;
    state->server_count++;
    return (int)(state->server_count - 1);
}

void nm_mark_server_down(struct nm_state *state, int index) {
    if (index < 0 || (size_t)index >= state->server_count) {
        return;
    }
    state->servers[index].ctrl_fd = -1;
    state->servers[index].online = 0;
}

int nm_pick_server(const struct nm_state *state) {
    for (size_t i = 0; i < state->server_count; ++i) {
        if (state->servers[i].ctrl_fd >= 0 && state->servers[i].online) {
            return (int)i;
        }
    }
    return -1;
}

int nm_pick_backup_server(const struct nm_state *state, int exclude) {
    for (size_t i = 0; i < state->server_count; ++i) {
        if ((int)i == exclude) {
            continue;
        }
        if (state->servers[i].ctrl_fd >= 0 && state->servers[i].online) {
            return (int)i;
        }
    }
    return -1;
}

static int find_file_index(struct nm_state *state, const char *name) {
    for (size_t i = 0; i < state->file_count; ++i) {
        if (strcmp(state->files[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

struct file_entry *nm_find_file(struct nm_state *state, const char *name) {
    int idx = find_file_index(state, name);
    if (idx < 0) {
        return NULL;
    }
    return &state->files[idx];
}

int nm_add_file(struct nm_state *state,
                const char *name,
                const char *owner,
                int ss_index,
                int backup_index,
                time_t now) {
    if (state->file_count >= NM_MAX_FILES) {
        errno = ENOSPC;
        return -1;
    }
    if (find_file_index(state, name) >= 0) {
        errno = EEXIST;
        return -1;
    }
    struct file_entry *file = &state->files[state->file_count];
    memset(file, 0, sizeof(*file));
    snprintf(file->name, sizeof(file->name), "%s", name);
    snprintf(file->owner, sizeof(file->owner), "%s", owner);
    file->ss_index = ss_index;
    file->backup_index = backup_index;
    file->created = now;
    file->modified = now;
    file->last_access = now;
    snprintf(file->last_access_user, sizeof(file->last_access_user), "%s", owner);
    file->acl_count = 0;
    state->file_count++;
    return 0;
}

int nm_remove_file(struct nm_state *state, const char *name) {
    int idx = find_file_index(state, name);
    if (idx < 0) {
        errno = ENOENT;
        return -1;
    }
    if ((size_t)idx != state->file_count - 1) {
        state->files[idx] = state->files[state->file_count - 1];
    }
    state->file_count--;
    return 0;
}

int nm_update_file_location(struct nm_state *state, const char *name, int ss_index) {
    struct file_entry *file = nm_find_file(state, name);
    if (!file) {
        return -1;
    }
    file->ss_index = ss_index;
    return 0;
}

int nm_update_file_metadata(struct nm_state *state,
                            const char *name,
                            size_t words,
                            size_t chars,
                            time_t modified,
                            time_t last_access,
                            const char *last_user) {
    struct file_entry *file = nm_find_file(state, name);
    if (!file) {
        return -1;
    }
    file->word_count = words;
    file->char_count = chars;
    if (modified) {
        file->modified = modified;
    }
    if (last_access) {
        file->last_access = last_access;
    }
    if (last_user && last_user[0]) {
        snprintf(file->last_access_user, sizeof(file->last_access_user), "%s", last_user);
    }
    return 0;
}

static struct file_acl_entry *find_acl(struct file_entry *file, const char *user) {
    for (size_t i = 0; i < file->acl_count; ++i) {
        if (strcmp(file->acl[i].user, user) == 0) {
            return &file->acl[i];
        }
    }
    return NULL;
}

int nm_grant_access(struct nm_state *state, const char *name, const char *user, int perm) {
    struct file_entry *file = nm_find_file(state, name);
    if (!file) {
        return -1;
    }
    if (strcmp(file->owner, user) == 0) {
        return 0;
    }
    struct file_acl_entry *entry = find_acl(file, user);
    if (entry) {
        entry->perm |= perm;
        return 0;
    }
    if (file->acl_count >= NM_MAX_ACL) {
        errno = ENOSPC;
        return -1;
    }
    struct file_acl_entry *slot = &file->acl[file->acl_count++];
    memset(slot, 0, sizeof(*slot));
    snprintf(slot->user, sizeof(slot->user), "%s", user);
    slot->perm = perm | NM_PERM_READ;
    return 0;
}

int nm_remove_access(struct nm_state *state, const char *name, const char *user) {
    struct file_entry *file = nm_find_file(state, name);
    if (!file) {
        return -1;
    }
    for (size_t i = 0; i < file->acl_count; ++i) {
        if (strcmp(file->acl[i].user, user) == 0) {
            if (i != file->acl_count - 1) {
                file->acl[i] = file->acl[file->acl_count - 1];
            }
            file->acl_count--;
            return 0;
        }
    }
    return 0;
}

int nm_check_access(struct nm_state *state, const char *name, const char *user, int perm) {
    struct file_entry *file = nm_find_file(state, name);
    if (!file) {
        return -1;
    }
    if (strcmp(file->owner, user) == 0) {
        return 0;
    }
    struct file_acl_entry *entry = find_acl(file, user);
    if (!entry) {
        errno = EACCES;
        return -1;
    }
    if ((entry->perm & perm) != perm) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

static struct user_entry *find_user(struct nm_state *state, const char *user) {
    for (size_t i = 0; i < state->user_count; ++i) {
        if (strcmp(state->users[i].name, user) == 0) {
            return &state->users[i];
        }
    }
    return NULL;
}

int nm_add_user(struct nm_state *state, const char *user) {
    struct user_entry *existing = find_user(state, user);
    if (existing) {
        existing->last_seen = time(NULL);
        return 0;
    }
    if (state->user_count >= NM_MAX_USERS) {
        errno = ENOSPC;
        return -1;
    }
    struct user_entry *entry = &state->users[state->user_count++];
    memset(entry, 0, sizeof(*entry));
    snprintf(entry->name, sizeof(entry->name), "%s", user);
    entry->last_seen = time(NULL);
    return 0;
}

struct user_entry *nm_get_user(struct nm_state *state, const char *user) {
    return find_user(state, user);
}

int nm_cache_lookup(struct nm_state *state, const char *name, int *ss_index) {
    time_t now = time(NULL);
    for (size_t i = 0; i < state->cache_count; ++i) {
        if (strcmp(state->cache[i].name, name) == 0) {
            state->cache[i].last_used = now;
            if (ss_index) {
                *ss_index = state->cache[i].ss_index;
            }
            return 0;
        }
    }
    return -1;
}

void nm_cache_put(struct nm_state *state, const char *name, int ss_index) {
    time_t now = time(NULL);
    for (size_t i = 0; i < state->cache_count; ++i) {
        if (strcmp(state->cache[i].name, name) == 0) {
            state->cache[i].ss_index = ss_index;
            state->cache[i].last_used = now;
            return;
        }
    }
    if (state->cache_count >= NM_MAX_CACHE) {
        size_t oldest = 0;
        time_t oldest_ts = state->cache[0].last_used;
        for (size_t i = 1; i < state->cache_count; ++i) {
            if (state->cache[i].last_used < oldest_ts) {
                oldest = i;
                oldest_ts = state->cache[i].last_used;
            }
        }
        state->cache[oldest] = state->cache[state->cache_count - 1];
        state->cache_count--;
    }
    struct cache_entry *entry = &state->cache[state->cache_count++];
    memset(entry, 0, sizeof(*entry));
    snprintf(entry->name, sizeof(entry->name), "%s", name);
    entry->ss_index = ss_index;
    entry->last_used = now;
}

static int write_line(FILE *fp, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = vfprintf(fp, fmt, ap);
    va_end(ap);
    if (rc < 0) {
        return -1;
    }
    if (fputc('\n', fp) == EOF) {
        return -1;
    }
    return 0;
}

int nm_state_save(struct nm_state *state) {
    if (!state->persist_path[0]) {
        return 0;
    }
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", state->persist_path);
    FILE *fp = fopen(tmp_path, "w");
    if (!fp) {
        return -1;
    }
    write_line(fp, "VERSION 1");
    for (size_t i = 0; i < state->server_count; ++i) {
        struct storage_server *ss = &state->servers[i];
        write_line(fp, "SERVER %s %s %s %s %d",
                   ss->id, ss->host, ss->ctrl_port, ss->data_port, ss->online);
    }
    for (size_t i = 0; i < state->file_count; ++i) {
        struct file_entry *file = &state->files[i];
        write_line(fp, "FILE %s %s %d %d %zu %zu %ld %ld %ld %s %zu",
                   file->name,
                   file->owner,
                   file->ss_index,
                   file->backup_index,
                   file->word_count,
                   file->char_count,
                   (long)file->created,
                   (long)file->modified,
                   (long)file->last_access,
                   file->last_access_user,
                   file->acl_count);
        for (size_t j = 0; j < file->acl_count; ++j) {
            struct file_acl_entry *acl = &file->acl[j];
            write_line(fp, "ACL %s %d", acl->user, acl->perm);
        }
    }
    for (size_t i = 0; i < state->user_count; ++i) {
        struct user_entry *user = &state->users[i];
        write_line(fp, "USER %s %ld", user->name, (long)user->last_seen);
    }
    write_line(fp, "END");
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    if (rename(tmp_path, state->persist_path) < 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

int nm_state_load(struct nm_state *state) {
    if (!state->persist_path[0]) {
        return 0;
    }
    FILE *fp = fopen(state->persist_path, "r");
    if (!fp) {
        return -1;
    }
    clear_state(state);
    char line[512];
    struct file_entry *current_file = NULL;
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) {
            *nl = '\0';
        }
        if (strncmp(line, "SERVER ", 7) == 0) {
            struct storage_server ss;
            memset(&ss, 0, sizeof(ss));
            int online = 0;
            if (sscanf(line + 7, "%127s %127s %15s %15s %d",
                       ss.id, ss.host, ss.ctrl_port, ss.data_port, &online) == 5) {
                ss.ctrl_fd = -1;
                ss.online = online;
                if (state->server_count < NM_MAX_SERVERS) {
                    state->servers[state->server_count++] = ss;
                }
            }
            current_file = NULL;
        } else if (strncmp(line, "FILE ", 5) == 0) {
            if (state->file_count >= NM_MAX_FILES) {
                continue;
            }
            struct file_entry file;
            memset(&file, 0, sizeof(file));
            char buffer[512];
            strncpy(buffer, line + 5, sizeof(buffer) - 1);
            buffer[sizeof(buffer) - 1] = '\0';
            char *save = NULL;
            char *tokens[12];
            int tok_count = 0;
            char *tok = strtok_r(buffer, " ", &save);
            while (tok && tok_count < 12) {
                tokens[tok_count++] = tok;
                tok = strtok_r(NULL, " ", &save);
            }
            if (tok_count < 10) {
                current_file = NULL;
                continue;
            }
            strncpy(file.name, tokens[0], sizeof(file.name) - 1);
            strncpy(file.owner, tokens[1], sizeof(file.owner) - 1);
            int idx = 2;
            if (tok_count == 11) {
                file.ss_index = atoi(tokens[idx++]);
                file.backup_index = atoi(tokens[idx++]);
            } else {
                file.ss_index = atoi(tokens[idx++]);
                file.backup_index = -1;
            }
            long created = 0;
            long modified = 0;
            long last_access = 0;
            if (idx + 7 <= tok_count) {
                file.word_count = (size_t)strtoull(tokens[idx++], NULL, 10);
                file.char_count = (size_t)strtoull(tokens[idx++], NULL, 10);
                created = atol(tokens[idx++]);
                modified = atol(tokens[idx++]);
                last_access = atol(tokens[idx++]);
                strncpy(file.last_access_user, tokens[idx++], sizeof(file.last_access_user) - 1);
                (void)strtoull(tokens[idx++], NULL, 10);
            } else {
                current_file = NULL;
                continue;
            }
            file.created = (time_t)created;
            file.modified = (time_t)modified;
            file.last_access = (time_t)last_access;
            file.acl_count = 0;
            state->files[state->file_count++] = file;
            current_file = &state->files[state->file_count - 1];
        } else if (strncmp(line, "ACL ", 4) == 0) {
            if (current_file && current_file->acl_count < NM_MAX_ACL) {
                struct file_acl_entry *acl = &current_file->acl[current_file->acl_count++];
                memset(acl, 0, sizeof(*acl));
                sscanf(line + 4, "%63s %d", acl->user, &acl->perm);
            }
        } else if (strncmp(line, "USER ", 5) == 0) {
            if (state->user_count < NM_MAX_USERS) {
                struct user_entry *user = &state->users[state->user_count++];
                memset(user, 0, sizeof(*user));
                long last_seen = 0;
                if (sscanf(line + 5, "%63s %ld", user->name, &last_seen) == 2) {
                    user->last_seen = (time_t)last_seen;
                }
            }
            current_file = NULL;
        } else {
            current_file = NULL;
        }
    }
    fclose(fp);
    return 0;
}
