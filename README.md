[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/0ek2UV58)

# Biscuit Collaborative Docs

This project implements a small distributed document store:

- **NM** (Name Manager) tracks users, files, ACLs, tickets, replication, and logs every request.
- **SS** (Storage Server) stores file contents, handles checkpointing, and enforces per-sentence write locks.
- **docs_client** provides an interactive CLI for users to read, write, and administer documents.

All binaries live under `bin/` after building.

---

## Build & Setup

1. **Requirements**: GCC (or Clang), POSIX environment, `make`, and Python 3 for the optional tests.
2. **Build** everything:
   ```sh
   make
   ```
   This produces `bin/nm`, `bin/ss`, and `bin/docs_client`.

---

## Running the Components

Start components in this order so that each service can register with the previous one.

### 1. Name Manager (NM)

```
bin/nm <listen_port> [state_file]
```

- Default state file: `nm_state.db` in the working directory.
- Logs: `nm.log` (general) and `nm_requests.log` (per-request summaries).
- Every error reply is mirrored in `nm.log` as `ERROR_RESP fd=<fd> code=<ERR_CODE> message=<msg>`.

### 2. Storage Server (SS)

```
bin/ss <ss_id> <public_host> <data_port> <nm_host> <nm_port> <storage_dir>
```

- `storage_dir` is where file, meta, undo, and checkpoint data live (directories are created automatically).
- Each SS registers with NM and advertises its data port to clients.
- Multiple SS instances can run; NM assigns primaries/backups and drives replication.

### 3. Client CLI

```
bin/docs_client <nm_host> <nm_port> [preferred_ss_port]
```

- Prompts for a username; NM rejects duplicates and logs conflicts.
- Built-in `HELP` lists all commands and syntax.

---

## Core CLI Commands & Behavior

| Command | Purpose & Notes |
|---------|-----------------|
| `VIEW [-a] [-l]` | List accessible files (`-a` shows all, `-l` includes metadata). |
| `LIST`, `INFO <file>` | List users or inspect a single file’s metadata and server placement. |
| `CREATE/DELETE <file>` | Create empty files or delete them (deletes are blocked while a WRITE lock is active). |
| `READ <file>` | Fetch full document contents. |
| `WRITE <file> [sentence]` | Opens a sentence-scoped editor. Each insert line is `<word_index> <content>` and you finish with `ETIRW`. Sentences are locked while the session is active. |
| `STREAM <file>` | Streams words with periodic `DATA` packets and finishes with `DONE`. |
| `CHECKPOINT <file> <tag>` | Snapshot current content; tags must be valid filenames. |
| `VIEWCHECKPOINT`, `REVERT <file> <tag>` | View or restore checkpoints. Revert/undo/delete respect WRITE locks – if someone is editing, the operation returns `ERR_LOCKED` and the SS logs the block. |
| `UNDO <file>` | Restores the previous version using the SS undo file (also blocked by active locks). |
| `LISTCHECKPOINTS`, `ADDACCESS`, `REMACCESS`, `REQACCESS`, `VIEWREQS`, `HANDLEREQ` | Manage ACLs and access requests. |
| `EXEC <file>` | Runs the file on the SS host (used for tests). |
| `QUIT/EXIT` | Disconnect the client.

### Writing Sessions
- Sentence indexes are lock-scoped; multiple writers can edit different sentences concurrently.
- Each WRITE session tracks the baseline sentence. On commit the SS merges into the latest file:
  - If someone else edited the sentence, the SS replays the sentence at the correct delimiter.
  - If the baseline vanished or another writer already replaced it, the commit fails with `ERR_CONFLICT`.
- Lock owners are recorded in `ss_state.lock_user`. Undo/Revert/Delete commands first check this state and refuse the operation (with logging) when the file is locked.

### Replication & Tickets
- NM issues short-lived WRITE/READ tickets and logs each grant.
- When the SS notifies NM of updates (`SS_FILE_UPDATE`), NM updates metadata and enqueues replication work if backups exist or need to be assigned.

---

## Logs & Troubleshooting

- `nm.log` – lifecycle events, peer connections, replication scheduling, and every `ERROR_RESP`.
- `nm_requests.log` – one line per client request (e.g., `WRITE_COMMIT user=alice file=r1`).
- `ss.log` (inside the SS storage directory) – storage-server events, sentence locks, undo/revert blocks.
- If clients see `ERR_*` responses, look for the same code in `nm.log` or the SS log to understand why.

---

## Error Codes

| Error Code | Short Description |
|------------|-------------------|
| `ERR_OK` | Operation succeeded (not emitted in error responses). |
| `ERR_NOAUTH` | Authentication or authorization failure, e.g., missing write access. |
| `ERR_NOTFOUND` | Resource (file, user, checkpoint, etc.) could not be located. |
| `ERR_LOCKED` | Resource is locked for WRITE (including undo/revert/delete protections). |
| `ERR_BADREQ` | Request malformed: missing fields, invalid filenames/tags, bad indexes. |
| `ERR_CONFLICT` | Operation conflicts with another change (e.g., stale WRITE_COMMIT). |
| `ERR_UNAVAILABLE` | Dependent service is offline/unreachable. |
| `ERR_INTERNAL` | Unexpected internal error (encoding, persistence, etc.). |
| `ERR_EXISTS` | Resource already exists. |
| `ERR_PERM` | Operation violates server policy despite valid authentication. |
| `ERR_TIMEOUT` | Ticket expired or operation timed out.

These identifiers match the `code` field in every JSON error reply and what NM logs under `ERROR_RESP`, so you can trace failures end-to-end.
