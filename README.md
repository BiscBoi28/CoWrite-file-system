# CoWrite — Distributed Collaborative Document Store

CoWrite is a terminal-based collaborative document system, built from scratch in C, that lets many users concurrently edit shared documents over the network without conflicts. It tackles the core distributed-systems problems directly: **sentence-granular write locking** so writers don't block each other unnecessarily, **per-user access control**, **primary/backup replication with automatic failover** so documents stay available when a storage server dies, and **checkpoint / undo rollback**.

It is organized as three programs that talk over TCP with a small length-prefixed JSON protocol.

## Architecture

```
                +---------------------------+
                |     Name Manager (NM)     |   metadata, ACLs, tickets,
                |  - file -> primary/backup |   replication, failover
                |  - access control         |
                |  - issues capability      |
                |    tickets (30s TTL)      |
                +-------------+-------------+
                  ^           |  control RPCs (NM_TICKET, NM_CREATE,
   register /     |           |  NM_SYNC, NM_CHECKPOINT_*, ...)
   SS_FILE_UPDATE |           v
        +---------+----+   +--+-----------+        replication (NM_SYNC:
        | Storage Srv  |   | Storage Srv  |        backup pulls from primary)
        |  (primary)   |<--|  (backup)    |
        |  file data,  |   |  file data   |
        |  locks, undo |   +--------------+
        +------+-------+
               ^
   ticket +    |  direct data-plane connection (READ / WRITE / STREAM)
   endpoint    |
        +------+-------+
        | docs_client  |   interactive REPL
        +--------------+
```

- **Name Manager (NM)** — the coordinator. It owns all file metadata, maps each file to a **primary** and one **backup** storage server, enforces ACLs, and brokers every client I/O through short-lived **capability tickets** (30s TTL). It is multithreaded (a thread per connection, plus background workers for replication and ticket expiry). Clients never read or write file content through the NM — they get an endpoint + ticket and connect to the storage server directly.
- **Storage Server (SS)** — stores file contents on disk, enforces sentence-level write locks, performs commit-time merges, and maintains per-file undo snapshots and named checkpoints. Multiple SS instances register with the NM; the NM assigns primary/backup roles across them.
- **docs_client** — an interactive CLI (REPL) that authenticates with a username, then drives all the commands below.

### Primary/backup replication and failover

- On `CREATE`, the NM assigns a **primary** SS (round-robin) and, if a second server is available, a **backup**; otherwise a backup is assigned later by an asynchronous replication worker.
- After every mutating operation the SS sends `SS_FILE_UPDATE` to the NM, which enqueues a replication task. The backup is brought up to date by pulling the authoritative content from the primary (the NM hands the backup a read ticket via `NM_SYNC`).
- **Failover:** the NM detects an SS going down when its control connection drops. On disconnect it walks every file whose primary was that server and, where a healthy backup exists, **promotes the backup to primary in place**, then asynchronously re-replicates to restore a backup. Clients re-resolve the endpoint per operation, so subsequent requests transparently land on the promoted server.

> **Honest scope:** failure detection is connection-drop / RPC-failure based (there is no active heartbeat, so a hung-but-connected SS isn't detected). Replication is asynchronous and each file keeps a single backup, so a freshly promoted backup may lag the primary's most recent writes. This is a learning implementation of failover, not a production HA system.

### Concurrency, conflict handling, and rollback

- **Sentence-level locking:** writes are scoped to a sentence index, so two users editing *different* sentences of the same file proceed concurrently; only same-sentence writers serialize.
- **Commit-time merge:** a `WRITE` session records a baseline sentence; on `WRITE_COMMIT` the SS re-reads the current file, relocates the target sentence by content + surrounding context, and merges the edit. If the baseline can no longer be found (someone changed it underneath the writer), the commit returns `ERR_CONFLICT`. (Detection is heuristic/string-based rather than version-numbered.)
- **Rollback:** `UNDO` restores the immediately previous version (single-level), and `CHECKPOINT` / `REVERT` snapshot and restore named tags. `UNDO`, `REVERT`, and `DELETE` are refused with `ERR_LOCKED` while a write is in progress.

## Build

Requirements: GCC (or Clang), a POSIX environment, `make`, and OpenSSL headers (`-lcrypto`, used by the SS).

```sh
make
```

This produces `bin/nm`, `bin/ss`, and `bin/docs_client`.

## Running

Start the components in this order so each can register with the previous one.

```sh
# 1) Name Manager:  bin/nm <listen_port> [state_file]
bin/nm 9000

# 2) Storage Server: bin/ss <ss_id> <public_host> <data_port> <nm_host> <nm_port> <storage_dir>
bin/ss ss1 127.0.0.1 9100 127.0.0.1 9000 ./ss_data
#   (start a second SS on another data_port/dir to exercise replication + failover)

# 3) Client:  bin/docs_client <nm_host> <nm_port> [preferred_ss_port]
bin/docs_client 127.0.0.1 9000
```

### Example session

```
$ bin/docs_client 127.0.0.1 9000
Username: alice
Connected as alice. Type 'help' for commands.

docs> CREATE notes
Created notes

docs> WRITE notes 0
Current sentence (0):
Enter edits as '<word_index> <content>' (use 0 for beginning). Finish with ETIRW.
write> 0 hello world
write> ETIRW
Write committed.

docs> READ notes
--- notes ---
hello world
-------------

docs> CHECKPOINT notes v1
Checkpoint 'v1' saved for notes.

docs> REVERT notes v1
Reverted notes to checkpoint 'v1'.

docs> QUIT
Bye.
```

In a `WRITE` session, each edit line is `<word_index> <content>` and the session is finished with the literal terminator `ETIRW` (or aborted to discard). The sentence is locked for the duration of the session.

## Commands

| Command | Purpose |
|---------|---------|
| `VIEW [-a] [-l]` | List accessible files (`-a` all, `-l` with metadata). |
| `LIST` / `INFO <file>` | List users / inspect one file's metadata and server placement. |
| `CREATE <file>` / `DELETE <file>` | Create or delete a file (delete blocked while a write lock is held). |
| `READ <file>` | Fetch the full document. |
| `WRITE <file> [sentence]` | Open a sentence-scoped editor; commit with `ETIRW`. |
| `STREAM <file>` | Stream the document in `DATA` packets, ending with `DONE`. |
| `CHECKPOINT <file> <tag>` | Snapshot current content under a tag. |
| `VIEWCHECKPOINT <file> <tag>` / `REVERT <file> <tag>` / `LISTCHECKPOINTS <file>` | View / restore / list checkpoints. |
| `UNDO <file>` | Restore the immediately previous version. |
| `ADDACCESS -R\|-W <file> <user>` / `REMACCESS <file> <user>` | Owner grants/revokes access. |
| `REQACCESS <file> -R\|-W` / `VIEWREQS <SENT\|RECEIVED>` / `HANDLEREQ <file> <user> <APPROVE\|DENY>` | Access-request workflow. |
| `EXEC <file>` | Run the file on the SS host (test utility — see note below). |
| `HELP` / `QUIT` / `EXIT` | Help / disconnect. |

> Note: `EXEC` runs document content as a shell script on the storage host. It exists as a test hook; treat it as trusted-input only — it is not a sandboxed feature.

## Error codes

Every JSON error reply carries a `code` field, mirrored in the NM log as `ERROR_RESP`, so failures can be traced end-to-end.

| Code | Meaning |
|------|---------|
| `ERR_NOAUTH` | Authentication / authorization failure (e.g. missing write access). |
| `ERR_NOTFOUND` | File, user, or checkpoint not found. |
| `ERR_LOCKED` | Resource locked for WRITE (also guards undo/revert/delete). |
| `ERR_BADREQ` | Malformed request (missing fields, invalid filename/tag/index). |
| `ERR_CONFLICT` | Commit conflicts with a concurrent change. |
| `ERR_UNAVAILABLE` | A dependent service is offline/unreachable. |
| `ERR_INTERNAL` | Unexpected internal error. |
| `ERR_EXISTS` | Resource already exists. |

## Logs

- `nm.log` — lifecycle events, peer connections, replication scheduling, failover, and every `ERROR_RESP`.
- `nm_requests.log` — one line per client request.
- `ss.log` (inside the SS storage dir) — storage events, sentence locks, undo/revert blocks.

## Tested limits

These are scenarios the design targets; concrete numbers still need to be measured and recorded.

| Dimension | Status |
|-----------|--------|
| Max concurrent clients sustained | TODO: measure (run N clients against 1 NM + 2 SS, record point of degradation) |
| Max concurrent writers on one file (distinct sentences) | TODO: measure |
| Failover time (primary kill → promoted backup serving) | TODO: measure end-to-end latency |
| Replication lag under sustained writes | TODO: measure |
| Largest document / longest sentence handled | TODO: measure |

> There is no automated test harness committed in this repo (the `make test` target references a `tests/` directory that is not included). The numbers above are intended to be filled in from manual multi-terminal runs.
