#ifndef CONTENT_CACHE_H
#define CONTENT_CACHE_H

#include <linux/hashtable.h>
#include <linux/spinlock.h>

struct content_cache_entry {
    const char *request_url;
    const char *response;
    struct hlist_node node;
    spinlock_t lock;
};

int request_hash(const char *request_url);
void init_content_cache_table(void);
void free_content_cache_table(void);
void insert_content_cache(char *request_url, char *cache_buffer);
const char *get_content(const char *request_url);

#endif