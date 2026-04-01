#include "cache_serializer.h"
#include "request_parser.h"

#include <stdio.h>

int main(void) {
    RequestRecord record;
    CacheEntry entry;
    char cache_key[96];
    const char *long_user = "user-name-that-is-far-too-long-for-the-fixed-buffer";
    const char *long_body =
        "payload-payload-payload-payload-payload-payload-payload-payload";

    request_record_init(&record);
    cache_entry_init(&entry);

    set_request_user(&record, long_user);
    set_request_path(&record, "/api/v1/export");
    copy_request_body(&record, long_body);
    build_cache_key(&record, cache_key, sizeof(cache_key));

    cache_set_label(&entry, "cache-slot-with-an-unsafe-label");
    cache_set_value(&entry, "cached-response-data");

    printf("user=%s\n", record.user);
    printf("path=%s\n", record.path);
    printf("cache_key=%s\n", cache_key);
    printf("cache_label=%s\n", entry.label);
    return 0;
}
