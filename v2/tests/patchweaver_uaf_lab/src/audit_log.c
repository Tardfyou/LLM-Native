#include "request_router.h"

#include <stdio.h>

int append_request_audit(const RequestContext *ctx, char *out, size_t out_size) {
    int written;

    if (!ctx || !out || out_size == 0) {
        return -1;
    }

    if (!ctx->session) {
        return -1;
    }

    written = snprintf(
        out,
        out_size,
        "audit:%d:%s:%s",
        ctx->request_id,
        ctx->session->user,
        ctx->route
    );
    return (written < 0 || (size_t)written >= out_size) ? -1 : 0;
}
