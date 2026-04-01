#ifndef REQUEST_ROUTER_H
#define REQUEST_ROUTER_H

#include <stddef.h>

#include "session_store.h"

typedef struct {
    int request_id;
    int session_id;
    Session *session;
    char route[64];
} RequestContext;

void request_context_init(RequestContext *ctx, int request_id, const char *route);
int bind_request_session(RequestContext *ctx, int session_id);
void release_request_session(RequestContext *ctx);
int handle_admin_export(const RequestContext *ctx, char *out, size_t out_size);
int append_request_audit(const RequestContext *ctx, char *out, size_t out_size);
int build_cached_summary(const RequestContext *ctx, char *out, size_t out_size);

#endif
