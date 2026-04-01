#ifndef CACHE_SERIALIZER_H
#define CACHE_SERIALIZER_H

typedef struct {
    char label[24];
    char value[48];
} CacheEntry;

void cache_entry_init(CacheEntry *entry);
int cache_set_label(CacheEntry *entry, const char *label);
int cache_set_value(CacheEntry *entry, const char *value);

#endif
