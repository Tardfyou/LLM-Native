#include "request_router.h"
#include "session_store.h"

#include <stdio.h>

int main(void) {
    RequestContext ctx;
    char export_line[128] = {0};
    char audit_line[128] = {0};
    char cache_line[128] = {0};

    if (!create_session(42, "alice", "admin")) {
        return 1;
    }

    request_context_init(&ctx, 7, "/admin/export");
    if (bind_request_session(&ctx, 42) != 0) {
        return 1;
    }

    expire_session(42);
    sweep_expired_sessions();

    handle_admin_export(&ctx, export_line, sizeof(export_line));
    append_request_audit(&ctx, audit_line, sizeof(audit_line));
    build_cached_summary(&ctx, cache_line, sizeof(cache_line));

    printf("export=%s\n", export_line);
    printf("audit=%s\n", audit_line);
    printf("cache=%s\n", cache_line);

    release_request_session(&ctx);
    return 0;
}
