/* Smoke test: link the memfd-ng cdylib from real C and drive the ABI.
 * Built and run by scripts/ffi-smoke.sh; exits 0 on success. */
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>

#include "memfd-ng.h"

int main(void) {
    if (memfd_ng_abi_version() != 1) {
        fprintf(stderr, "smoke: unexpected ABI version\n");
        return 1;
    }
    printf("smoke: linked against memfd-ng %s\n", memfd_ng_version());

    /* image: read a tiny shell script... no — read /bin/sh itself */
    FILE *f = fopen("/bin/sh", "rb");
    if (!f) { perror("fopen /bin/sh"); return 1; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    static unsigned char code[8 << 20];
    if (len < 0 || (size_t)len > sizeof code || fread(code, 1, (size_t)len, f) != (size_t)len) {
        fprintf(stderr, "smoke: read failed\n");
        return 1;
    }
    fclose(f);

    const char *argv[] = {"sh", "-c", "echo in-memory-from-C; exit 5", NULL};
    int32_t err = 0;
    memfd_ng_child *child = memfd_ng_spawn(code, (size_t)len, "smoke-sh", argv, NULL, &err);
    if (!child) {
        fprintf(stderr, "smoke: spawn failed: %s (%d)\n", strerror(-err), -err);
        return 1;
    }
    printf("smoke: child pid %d\n", memfd_ng_pid(child));

    int32_t status = 0;
    int rc = memfd_ng_wait(child, &status);
    if (rc != 0) {
        fprintf(stderr, "smoke: wait failed: %s\n", strerror(-rc));
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 5) {
        fprintf(stderr, "smoke: unexpected wait status %d\n", status);
        return 1;
    }
    printf("smoke: child exited 5 as instructed\n");

    /* error path: corrupt image must surface -ENOEXEC through err_out */
    const unsigned char bogus[] = {0x7f, 'E', 'L', 'F', 'n', 'o', 'p', 'e'};
    memfd_ng_child *bad = memfd_ng_spawn(bogus, sizeof bogus, "smoke-bogus", argv, NULL, &err);
    if (bad != NULL || err != -ENOEXEC) {
        fprintf(stderr, "smoke: expected NULL/-ENOEXEC, got %p/%d\n", (void *)bad, err);
        return 1;
    }
    printf("smoke: corrupt image surfaced ENOEXEC\n");

    printf("smoke: all ok\n");
    return 0;
}
