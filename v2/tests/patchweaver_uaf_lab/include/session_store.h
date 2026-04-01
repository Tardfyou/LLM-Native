#ifndef SESSION_STORE_H
#define SESSION_STORE_H

typedef struct Session {
    int session_id;
    char user[32];
    char role[16];
    int expired;
} Session;

Session *create_session(int session_id, const char *user, const char *role);
Session *find_session(int session_id);
void expire_session(int session_id);
void sweep_expired_sessions(void);
void destroy_session(Session *session);

#endif
