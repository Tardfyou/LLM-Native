#include "session_store.h"

#include <stdlib.h>
#include <string.h>

#define MAX_SESSIONS 8

static Session *g_sessions[MAX_SESSIONS];

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

Session *create_session(int session_id, const char *user, const char *role) {
    Session *session = (Session *)calloc(1, sizeof(Session));
    int i;

    if (!session) {
        return NULL;
    }

    session->session_id = session_id;
    copy_text(session->user, sizeof(session->user), user);
    copy_text(session->role, sizeof(session->role), role);

    for (i = 0; i < MAX_SESSIONS; ++i) {
        if (!g_sessions[i]) {
            g_sessions[i] = session;
            return session;
        }
    }

    free(session);
    return NULL;
}

Session *find_session(int session_id) {
    int i;

    for (i = 0; i < MAX_SESSIONS; ++i) {
        if (g_sessions[i] && g_sessions[i]->session_id == session_id) {
            return g_sessions[i];
        }
    }

    return NULL;
}

void expire_session(int session_id) {
    Session *session = find_session(session_id);

    if (!session) {
        return;
    }

    session->expired = 1;
}

void sweep_expired_sessions(void) {
    int i;

    for (i = 0; i < MAX_SESSIONS; ++i) {
        if (g_sessions[i] && g_sessions[i]->expired) {
            free(g_sessions[i]);
            g_sessions[i] = NULL;
        }
    }
}

void destroy_session(Session *session) {
    int i;

    if (!session) {
        return;
    }

    for (i = 0; i < MAX_SESSIONS; ++i) {
        if (g_sessions[i] == session) {
            free(session);
            g_sessions[i] = NULL;
            return;
        }
    }

    free(session);
}
