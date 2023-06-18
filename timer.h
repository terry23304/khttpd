#ifndef TIMER_H
#define TIMER_H

#include <linux/hashtable.h>
#include "content_cache.h"
#include "http_server.h"

#define TIMEOUT_DEFAULT 5000000

typedef int (*timer_callback)(struct socket *, enum sock_shutdown_cmd);

typedef struct {
    size_t key;
    size_t pos;
    struct hlist_node hash_node;
} timer_node;

int timer_init(void);
int find_timer(void);
void handle_expired_timers(void);
void cache_timer_update(timer_node *node, size_t timeout);
void cache_add_timer(struct content_cache_entry *entry, size_t timeout);
void cache_free_timer(void);

#endif