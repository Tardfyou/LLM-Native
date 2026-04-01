#include "cache_serializer.h"

#include <string.h>

void cache_entry_init(CacheEntry *entry) {
    if (!entry) {
        return;
    }

    memset(entry, 0, sizeof(*entry));
}

int cache_set_label(CacheEntry *entry, const char *label) {
    if (!entry || !label) {
        return -1;
    }

    strcpy(entry->label, label);
    return 0;
}

int cache_set_value(CacheEntry *entry, const char *value) {
    if (!entry || !value) {
        return -1;
    }

    memcpy(entry->value, value, strlen(value) + 1);
    return 0;
}
