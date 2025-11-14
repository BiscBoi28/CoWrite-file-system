#ifndef NM_STATE_H
#define NM_STATE_H

#include <stddef.h>
#include <time.h>

#define NM_MAX_SERVERS 32
#define NM_MAX_FILES 512
#define NM_MAX_USERS 512
#define NM_MAX_ACL 64
#define NM_MAX_CACHE 128
#define NM_MAX_NAME 128
#define NM_MAX_USER 64

#define NM_PERM_READ 0x1
#define NM_PERM_WRITE 0x2

struct storage_server {
    char id[NM_MAX_NAME];
    char host[NM_MAX_NAME];
    char ctrl_port[16];
    char data_port[16];
    int ctrl_fd;
    int online;
};

struct file_acl_entry {
    char user[NM_MAX_USER];
    int perm;
};

struct file_entry {
    char name[NM_MAX_NAME];
    char owner[NM_MAX_USER];
    int ss_index;
    int backup_index;
    size_t word_count;
    size_t char_count;
    time_t created;
    time_t modified;
    time_t last_access;
    char last_access_user[NM_MAX_USER];
    struct file_acl_entry acl[NM_MAX_ACL];
    size_t acl_count;
};

struct user_entry {
    char name[NM_MAX_USER];
    time_t last_seen;
};

struct cache_entry {
    char name[NM_MAX_NAME];
    int ss_index;
    time_t last_used;
};

struct nm_state {
    struct storage_server servers[NM_MAX_SERVERS];
    size_t server_count;
    struct file_entry files[NM_MAX_FILES];
    size_t file_count;
    struct user_entry users[NM_MAX_USERS];
    size_t user_count;
    struct cache_entry cache[NM_MAX_CACHE];
    size_t cache_count;
    char persist_path[256];
};

void nm_state_init(struct nm_state *state, const char *persist_path);
void nm_state_destroy(struct nm_state *state);
int nm_state_load(struct nm_state *state);
int nm_state_save(struct nm_state *state);

int nm_register_server(struct nm_state *state,
                       const char *id,
                       const char *host,
                       const char *ctrl_port,
                       const char *data_port,
                       int ctrl_fd);
int nm_find_server_by_id(const struct nm_state *state, const char *id);
struct storage_server *nm_get_server(struct nm_state *state, int index);
void nm_mark_server_down(struct nm_state *state, int index);
int nm_pick_server(const struct nm_state *state);
int nm_pick_backup_server(const struct nm_state *state, int exclude);

struct file_entry *nm_find_file(struct nm_state *state, const char *name);
int nm_add_file(struct nm_state *state,
                const char *name,
                const char *owner,
                int ss_index,
                int backup_index,
                time_t now);
int nm_remove_file(struct nm_state *state, const char *name);
int nm_update_file_location(struct nm_state *state, const char *name, int ss_index);
int nm_update_file_metadata(struct nm_state *state,
                            const char *name,
                            size_t words,
                            size_t chars,
                            time_t modified,
                            time_t last_access,
                            const char *last_user);
int nm_grant_access(struct nm_state *state, const char *name, const char *user, int perm);
int nm_remove_access(struct nm_state *state, const char *name, const char *user);
int nm_check_access(struct nm_state *state, const char *name, const char *user, int perm);

int nm_add_user(struct nm_state *state, const char *user);
struct user_entry *nm_get_user(struct nm_state *state, const char *user);

int nm_cache_lookup(struct nm_state *state, const char *name, int *ss_index);
void nm_cache_put(struct nm_state *state, const char *name, int ss_index);

#endif /* NM_STATE_H */
