#ifndef REQUEST_PARSER_H
#define REQUEST_PARSER_H

#include <stddef.h>

typedef struct {
    char user[32];
    char path[48];
    char body[64];
} RequestRecord;

void request_record_init(RequestRecord *record);
int set_request_user(RequestRecord *record, const char *user);
int set_request_path(RequestRecord *record, const char *path);
int copy_request_body(RequestRecord *record, const char *payload);
int build_cache_key(const RequestRecord *record, char *out_key, size_t out_size);

#endif
