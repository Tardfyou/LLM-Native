#include "request_router.h"

#include <stdio.h>
#include <string.h>

static void copy_text(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0) {
        return;
    }

    if (!src) {
        dst[0] = '\0';
        return;
    }

    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

void request_context_init(RequestContext *ctx, int request_id, const char *route) {
    if (!ctx) {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->request_id = request_id;
    ctx->session_id = -1;
    copy_text(ctx->route, sizeof(ctx->route), route);
}

int bind_request_session(RequestContext *ctx, int session_id) {
    Session *session;

    if (!ctx) {
        return -1;
    }

    session = find_session(session_id);
    if (!session) {
        return -1;
    }

    ctx->session_id = session_id;
    ctx->session = session;
    return 0;
}

void release_request_session(RequestContext *ctx) {
    if (!ctx || !ctx->session) {
        return;
    }

    destroy_session(ctx->session);
}

int handle_admin_export(const RequestContext *ctx, char *out, size_t out_size) {
    int written;

    if (!ctx || !out || out_size == 0) {
        return -1;
    }

    if (!ctx->session) {
        return -1;
    }

    if (strncmp(ctx->route, "/admin", 6) != 0) {
        return -1;
    }

    if (strcmp(ctx->session->role, "admin") != 0) {
        return -1;
    }

    written = snprintf(out, out_size, "export:%s:%s", ctx->session->user, ctx->route);
    return (written < 0 || (size_t)written >= out_size) ? -1 : 0;
}
