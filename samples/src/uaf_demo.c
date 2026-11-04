/* Minimal UAF demo used as the eh_frame_patch example target.
 *
 * The bug: obj_free() calls free(o->buf) but never clears the slot, so the
 * caller keeps a dangling pointer.  Everything else in this file is already
 * defensive (obj_write / obj_dump check for NULL), so the *only* fix needed is
 * "clear the pointer right after free()".
 *
 * Why this file is a good plugin demo: at the free() call site there are only
 * a handful of bytes left before the next function starts.  A 5-byte
 * `jmp rel32` fits, but there is no room for the
 * `mov qword ptr [rbp-8], 0` that has to run first -- exactly the situation
 * that forces the stub into .eh_frame.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *buf;
    unsigned int len;
    unsigned int used;
} obj_t;

__attribute__((noinline))
static void obj_free(obj_t *o)
{
    if (o == NULL || o->buf == NULL)
        return;
    free(o->buf);            /* <-- BUG: o->buf is not set to NULL */
}

__attribute__((noinline))
static int obj_write(obj_t *o, const char *s)
{
    unsigned int n = (unsigned int)strlen(s);
    if (o->buf == NULL)      /* defensive: handles the fixed (NULL) state */
        return -1;
    if (o->used + n > o->len)
        return -1;
    memcpy(o->buf + o->used, s, n);
    o->used += n;
    return 0;
}

__attribute__((noinline))
static void obj_dump(obj_t *o)
{
    printf("[dump] len=%u used=%u data=%.*s\n", o->len, o->used,
           (int)o->used, o->buf ? o->buf : "(null)");
}

int main(int argc, char **argv)
{
    obj_t o;
    int rc;

    o.len = 0x40;
    o.used = 0;
    o.buf = (char *)malloc(o.len);
    if (!o.buf)
        return 1;

    obj_write(&o, "hello");
    obj_dump(&o);

    obj_free(&o);

    /* UAF: o.buf still points at freed memory unless the fix ran. */
    rc = obj_write(&o, "-after-free");
    printf("[main] post-free write returned %d\n", rc);
    obj_dump(&o);
    return 0;
}
