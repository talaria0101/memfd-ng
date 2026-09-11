/* C header for the memfd-ng FFI layer (memfd-ng-ffi crate).
 * Hand-written for the v1 ABI; memfd_ng_abi_version() reports it. */
#ifndef MEMFD_NG_H
#define MEMFD_NG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct memfd_ng_child memfd_ng_child;

/* 1 for this ABI. */
int32_t memfd_ng_abi_version(void);

/* Crate version, static NUL-terminated string. */
const char *memfd_ng_version(void);

/*
 * Spawn the image in a child process with inherited stdio.
 * - code/code_len: the executable image; must stay valid and unmodified
 *   until the child is waited on or freed.
 * - name: memfd/program name; NULL means "memfd-ng".
 * - argv: NULL-terminated; NULL means [name]; argv[0] is the program name.
 * - envp: NULL-terminated KEY=VALUE strings; NULL inherits the environment,
 *   non-NULL replaces it (execve semantics, not an overlay).
 * Returns a handle, or NULL with *err_out = -errno.
 */
memfd_ng_child *memfd_ng_spawn(const uint8_t *code, size_t code_len,
                               const char *name,
                               const char *const *argv,
                               const char *const *envp,
                               int32_t *err_out);

/* The child's pid (> 0), or -errno for a bad handle. */
int32_t memfd_ng_pid(memfd_ng_child *child);

/* SIGKILL the child. 0 or -errno. */
int32_t memfd_ng_kill(memfd_ng_child *child);

/* Reap the child, write the raw wait(2) status to *status_out, release the
 * handle. 0 or -errno. The handle is consumed either way. */
int32_t memfd_ng_wait(memfd_ng_child *child, int32_t *status_out);

/* Release the handle without waiting (documented zombie, std parity). */
void memfd_ng_free(memfd_ng_child *child);

#ifdef __cplusplus
}
#endif

#endif /* MEMFD_NG_H */
