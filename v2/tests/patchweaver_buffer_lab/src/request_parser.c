#include "request_parser.h"

#include <stdio.h>
#include <string.h>

void request_record_init(RequestRecord *record) {
    if (!record) {
        return;
    }

    memset(record, 0, sizeof(*record));
}

int set_request_user(RequestRecord *record, const char *user) {
    if (!record || !user) {
        return -1;
    }

    strcpy(record->user, user);
    return 0;
}

int set_request_path(RequestRecord *record, const char *path) {
    if (!record || !path) {
        return -1;
    }

    strncpy(record->path, path, sizeof(record->path) - 1);
    record->path[sizeof(record->path) - 1] = '\0';
    return 0;
}

int copy_request_body(RequestRecord *record, const char *payload) {
    if (!record || !payload) {
        return -1;
    }

    memcpy(record->body, payload, strlen(payload) + 1);
    return 0;
}

int build_cache_key(const RequestRecord *record, char *out_key, size_t out_size) {
    if (!record || !out_key || out_size == 0) {
        return -1;
    }

    strcpy(out_key, record->user);
    strcat(out_key, ":");
    strcat(out_key, record->path);
    return 0;
}
