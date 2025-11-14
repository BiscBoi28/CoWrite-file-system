#define _POSIX_C_SOURCE 200809L

#include "ss_state.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/array.h"

static int ensure_dir(const char *path) {
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

static int compare_names(const char *a, const char *b) {
    return strcmp(a, b);
}

static int insert_sorted(struct ss_state *state, struct ss_file *file) {
    size_t lo = 0;
    size_t hi = state->files.len;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        struct ss_file *candidate = array_get(&state->files, mid);
        int cmp = compare_names(candidate->name, file->name);
        if (cmp < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return array_insert(&state->files, lo, file);
}

static void fill_paths(struct ss_state *state, const char *name, struct ss_file *file) {
    snprintf(file->data_path, sizeof(file->data_path), "%s/%s", state->files_dir, name);
    snprintf(file->meta_path, sizeof(file->meta_path), "%s/%s.meta", state->meta_dir, name);
    snprintf(file->undo_path, sizeof(file->undo_path), "%s/%s.undo", state->undo_dir, name);
}

static size_t count_words(const char *text) {
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

int ss_state_init(struct ss_state *state, const char *storage_dir) {
    if (!state || !storage_dir) {
        return -1;
    }
    memset(state, 0, sizeof(*state));
    snprintf(state->storage_dir, sizeof(state->storage_dir), "%s", storage_dir);
    snprintf(state->files_dir, sizeof(state->files_dir), "%s/files", storage_dir);
    snprintf(state->meta_dir, sizeof(state->meta_dir), "%s/meta", storage_dir);
    snprintf(state->undo_dir, sizeof(state->undo_dir), "%s/undo", storage_dir);

    if (ensure_dir(storage_dir) < 0 ||
        ensure_dir(state->files_dir) < 0 ||
        ensure_dir(state->meta_dir) < 0 ||
        ensure_dir(state->undo_dir) < 0) {
        return -1;
    }

    array_init(&state->files, sizeof(struct ss_file));
    return ss_state_load(state);
}

void ss_state_destroy(struct ss_state *state) {
    if (!state) {
        return;
    }
    array_free(&state->files);
}

struct ss_file *ss_state_find(struct ss_state *state, const char *name, size_t *index_out) {
    if (!state || !name) {
        return NULL;
    }
    size_t lo = 0;
    size_t hi = state->files.len;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        struct ss_file *candidate = array_get(&state->files, mid);
        int cmp = compare_names(candidate->name, name);
        if (cmp == 0) {
            if (index_out) {
                *index_out = mid;
            }
            return candidate;
        }
        if (cmp < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (index_out) {
        *index_out = lo;
    }
    return NULL;
}

static int write_meta_file(struct ss_file *file) {
    FILE *fp = fopen(file->meta_path, "w");
    if (!fp) {
        return -1;
    }
    fprintf(fp, "owner:%s\n", file->owner);
    fprintf(fp, "created:%ld\n", (long)file->created);
    fprintf(fp, "modified:%ld\n", (long)file->modified);
    fprintf(fp, "last_access:%ld\n", (long)file->last_access);
    fprintf(fp, "last_access_user:%s\n", file->last_access_user);
    fprintf(fp, "word_count:%zu\n", file->word_count);
    fprintf(fp, "char_count:%zu\n", file->char_count);
    fclose(fp);
    return 0;
}

int ss_state_save_meta(struct ss_state *state, struct ss_file *file) {
    (void)state;
    return write_meta_file(file);
}

int ss_state_add(struct ss_state *state, const char *name, const char *owner) {
    if (!state || !name || !owner) {
        return -1;
    }
    size_t idx = 0;
    if (ss_state_find(state, name, &idx)) {
        errno = EEXIST;
        return -1;
    }
    struct ss_file file;
    memset(&file, 0, sizeof(file));
    snprintf(file.name, sizeof(file.name), "%s", name);
    snprintf(file.owner, sizeof(file.owner), "%s", owner);
    fill_paths(state, name, &file);
    file.created = file.modified = file.last_access = time(NULL);
    snprintf(file.last_access_user, sizeof(file.last_access_user), "%s", owner);
    file.word_count = 0;
    file.char_count = 0;
    file.lock_active = 0;
    file.lock_sentence = -1;

    int rc = insert_sorted(state, &file);
    if (rc < 0) {
        return -1;
    }
    /* Create empty data file */
    FILE *fp = fopen(file.data_path, "w");
    if (!fp) {
        array_remove(&state->files, idx);
        return -1;
    }
    fclose(fp);
    if (write_meta_file(array_get(&state->files, idx)) < 0) {
        array_remove(&state->files, idx);
        unlink(file.data_path);
        return -1;
    }
    return 0;
}

int ss_state_remove(struct ss_state *state, const char *name) {
    if (!state || !name) {
        return -1;
    }
    size_t idx = 0;
    struct ss_file *file = ss_state_find(state, name, &idx);
    if (!file) {
        errno = ENOENT;
        return -1;
    }
    unlink(file->data_path);
    unlink(file->meta_path);
    unlink(file->undo_path);
    array_remove(&state->files, idx);
    return 0;
}

static int load_meta_file(struct ss_file *file) {
    FILE *fp = fopen(file->meta_path, "r");
    if (!fp) {
        return -1;
    }
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char *newline = strchr(line, '\n');
        if (newline) {
            *newline = '\0';
        }
        char *colon = strchr(line, ':');
        if (!colon) {
            continue;
        }
        *colon = '\0';
        const char *key = line;
        const char *value = colon + 1;
        if (strcmp(key, "owner") == 0) {
            snprintf(file->owner, sizeof(file->owner), "%s", value);
        } else if (strcmp(key, "created") == 0) {
            file->created = (time_t)atol(value);
        } else if (strcmp(key, "modified") == 0) {
            file->modified = (time_t)atol(value);
        } else if (strcmp(key, "last_access") == 0) {
            file->last_access = (time_t)atol(value);
        } else if (strcmp(key, "last_access_user") == 0) {
            snprintf(file->last_access_user, sizeof(file->last_access_user), "%s", value);
        } else if (strcmp(key, "word_count") == 0) {
            file->word_count = (size_t)strtoull(value, NULL, 10);
        } else if (strcmp(key, "char_count") == 0) {
            file->char_count = (size_t)strtoull(value, NULL, 10);
        }
    }
    fclose(fp);
    return 0;
}

int ss_state_load(struct ss_state *state) {
    DIR *dir = opendir(state->meta_dir);
    if (!dir) {
        return -1;
    }
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        const char *dot = strrchr(ent->d_name, '.');
        if (!dot || strcmp(dot, ".meta") != 0) {
            continue;
        }
        char name[SS_NAME_MAX];
        size_t len = (size_t)(dot - ent->d_name);
        if (len >= sizeof(name)) {
            len = sizeof(name) - 1;
        }
        memcpy(name, ent->d_name, len);
        name[len] = '\0';

        struct ss_file file;
        memset(&file, 0, sizeof(file));
        snprintf(file.name, sizeof(file.name), "%s", name);
        fill_paths(state, name, &file);
        if (load_meta_file(&file) < 0) {
            continue;
        }
        if (file.word_count == 0 || file.char_count == 0) {
            FILE *fp = fopen(file.data_path, "r");
            if (fp) {
                fseek(fp, 0, SEEK_END);
                long sz = ftell(fp);
                fseek(fp, 0, SEEK_SET);
                char *buf = malloc((size_t)sz + 1);
                if (buf) {
                    size_t read = fread(buf, 1, (size_t)sz, fp);
                    buf[read] = '\0';
                    file.char_count = read;
                    file.word_count = count_words(buf);
                    free(buf);
                }
                fclose(fp);
            }
        }
        file.lock_active = 0;
        file.lock_sentence = -1;
        insert_sorted(state, &file);
    }
    closedir(dir);
    return 0;
}
