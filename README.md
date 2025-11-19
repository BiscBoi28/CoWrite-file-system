[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/0ek2UV58)

Accessing [existing string index] + 1 is going to append to the end of the file and not show error like in example.

## NM Error Logging

- The NM daemon writes general diagnostics to `nm.log` and request summaries to `nm_requests.log`.
- Every error response now emits an `ERROR_RESP fd=<fd> code=<ERR_CODE> message=<msg>` entry in `nm.log`, so you can correlate a failed request with the exact error code that was sent back to the client.

## Error Codes

| Error Code | Short Description |
|------------|-------------------|
| `ERR_OK` | Operation succeeded (not emitted in error responses). |
| `ERR_NOAUTH` | Authentication or authorization failure, e.g., missing write access. |
| `ERR_NOTFOUND` | Resource (file, user, checkpoint, etc.) could not be located. |
| `ERR_LOCKED` | The requested sentence or file is currently locked. |
| `ERR_BADREQ` | The request was malformed (missing/invalid fields or payload). |
| `ERR_CONFLICT` | The requested change conflicted with another operation. |
| `ERR_UNAVAILABLE` | A dependent service (storage server, backup) is unavailable. |
| `ERR_INTERNAL` | An unexpected internal error occurred (encoding, persistence, etc.). |
| `ERR_EXISTS` | The resource already exists (create operation conflict). |
| `ERR_PERM` | The operation is not permitted despite a valid request (policy enforcement). |
| `ERR_TIMEOUT` | The operation timed out (ticket expiry, replication, etc.). |

Each logged error code matches the `code` field that is sent back in JSON responses so you can quickly look up both the client-side message and the server-side reason.
