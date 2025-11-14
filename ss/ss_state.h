#ifndef SS_STATE_H
#define SS_STATE_H

#include <stddef.h>
#include <time.h>

#include "common/array.h"

#define SS_NAME_MAX 128
#define SS_USER_MAX 64

struct ss_file {
    char name[SS_NAME_MAX];
    char owner[SS_USER_MAX];
    char data_path[512];
    char meta_path[512];
    char undo_path[512];
    time_t created;
    time_t modified;
    time_t last_access;
    char last_access_user[SS_USER_MAX];
    size_t word_count;
    size_t char_count;
    int lock_active;
    char lock_user[SS_USER_MAX];
    int lock_sentence;
};

struct ss_state {
    char storage_dir[256];
    char files_dir[256];
    char meta_dir[256];
    char undo_dir[256];
    struct array files; /* struct ss_file */
};

int ss_state_init(struct ss_state *state, const char *storage_dir);
void ss_state_destroy(struct ss_state *state);
struct ss_file *ss_state_find(struct ss_state *state, const char *name, size_t *index_out);
int ss_state_add(struct ss_state *state, const char *name, const char *owner);
int ss_state_remove(struct ss_state *state, const char *name);
int ss_state_load(struct ss_state *state);
int ss_state_save_meta(struct ss_state *state, struct ss_file *file);

#endif /* SS_STATE_H */
