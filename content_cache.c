#include "content_cache.h"
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "timer.h"

DEFINE_READ_MOSTLY_HASHTABLE(content_cache_table, 8);

int request_hash(const char *request_url)
{
    unsigned long int value = 0x61C88647;
    size_t n = strlen(request_url);

    int i = 0;

    for (; value < ULONG_MAX && i < n; i++) {
        value = value << 8;
        value += request_url[i];
    }

    return value % 8;
}

void init_content_cache_table(void)
{
    timer_init();
    hash_init(content_cache_table);
}

void free_content_cache_table(void)
{
    struct content_cache_entry *entry;
    struct hlist_node *tmp;
    unsigned int bucket;

    hash_for_each_safe(content_cache_table, bucket, tmp, entry, node)
    {
        hash_del_rcu(&entry->node);
        synchronize_rcu();
        kfree(entry->request_url);
        kfree(entry->response);
        kfree(entry);
    }
    cache_free_timer();
}

void insert_content_cache(char *request_url, char *cache_buffer)
{
    struct content_cache_entry *entry =
        kmalloc(sizeof(struct content_cache_entry), GFP_KERNEL);
    if (!entry)
        return;

    entry->request_url = kmalloc(strlen(request_url) + 1, GFP_KERNEL);

    if (!entry->request_url) {
        kfree(entry);
        return;
    }
    strncpy(entry->request_url, request_url, strlen(request_url) + 1);

    entry->response = kmalloc(strlen(cache_buffer) + 1, GFP_KERNEL);

    if (!entry->response) {
        kfree(entry->request_url);
        kfree(entry);
        return;
    }
    strncpy(entry->response, cache_buffer, strlen(cache_buffer) + 1);

    cache_add_timer(entry, TIMEOUT_DEFAULT);

    spin_lock_init(&entry->lock);
    spin_lock(&entry->lock);
    hash_add_rcu(content_cache_table, &entry->node, request_hash(request_url));
    spin_unlock(&entry->lock);
}

const char *get_content(const char *request_url)
{
    struct content_cache_entry *entry;
    struct hlist_node *node;

    entry = kmalloc(sizeof(struct content_cache_entry), GFP_KERNEL);
    if (!entry)
        return "";

    rcu_read_lock();
    hash_for_each_possible_rcu(content_cache_table, entry, node,
                               request_hash(request_url))
    {
        if (!strcmp(entry->request_url, request_url)) {
            cache_timer_update(entry->timer, TIMEOUT_DEFAULT);
            return entry->response;
        }
    }
    rcu_read_unlock();

    return "";
}