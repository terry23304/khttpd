#include "timer.h"

#define TIMER_INFINITE (-1)
#define PQ_DEFAULT_SIZE 500

typedef int (*prio_queue_comparator)(void *pi, void *pj);

typedef struct {
    void **priv;
    atomic_t nalloc;
    atomic_t size;
    prio_queue_comparator comp;
} prio_queue_t;

static bool prio_queue_init(prio_queue_t *ptr,
                            prio_queue_comparator comp,
                            size_t size)
{
    ptr->priv = kmalloc(sizeof(void *) * (size + 1), GFP_KERNEL);
    if (!ptr->priv) {
        pr_err("prio_queue_init: malloc failed");
        return false;
    }

    atomic_set(&ptr->nalloc, 0);
    atomic_set(&ptr->size, size + 1);
    ptr->comp = comp;
    return true;
}

static inline bool prio_queue_is_empty(prio_queue_t *ptr)
{
    return atomic_read(&ptr->nalloc) == 0;
}

static inline void *prio_queue_min(prio_queue_t *ptr)
{
    return prio_queue_is_empty(ptr) ? NULL : ptr->priv[1];
}

static inline void prio_queue_swap(prio_queue_t *ptr, size_t i, size_t j)
{
    void *tmp = ptr->priv[i];
    ptr->priv[i] = ptr->priv[j];
    ptr->priv[j] = tmp;
}

static size_t prio_queue_sink(prio_queue_t *ptr, size_t k)
{
    size_t nalloc = atomic_read(&ptr->nalloc);

    while ((k << 1) <= nalloc) {
        size_t j = (k << 1);
        if (j < nalloc && ptr->comp(ptr->priv[j + 1], ptr->priv[j]))
            j++;
        if (!ptr->comp(ptr->priv[j], ptr->priv[k]))
            break;
        prio_queue_swap(ptr, j, k);
        k = j;
    }

    return k;
}

static bool prio_queue_delmin(prio_queue_t *ptr)
{
    size_t nalloc;
    timer_node *node = NULL;
    struct http_request *worker = NULL;
    struct content_cache_entry *entry = NULL;

    do {
        if (prio_queue_is_empty(ptr))
            return true;

        nalloc = atomic_read(&ptr->nalloc);
        prio_queue_swap(ptr, 1, nalloc);

        if (nalloc == atomic_read(&ptr->nalloc)) {
            node = ptr->priv[nalloc];
            break;
        }
        prio_queue_swap(ptr, 1, nalloc);
    } while (1);

    atomic_dec(&ptr->nalloc);
    prio_queue_sink(ptr, 1);

    hash_del_rcu(&node->hash_node);
    synchronize_rcu();

    return true;
}

static inline bool prio_queue_cmpxchg(timer_node **var,
                                      long long *old,
                                      long long neu)
{
    bool ret;
    union u64 {
        struct {
            int low, high;
        } s;
        long long ui;
    } cmp = {.ui = *old}, with = {.ui = neu};

    /**
     * 1. cmp.s.hi:cmp.s.lo compare with *var
     * 2. if equall, set ZF and copy with.s.hi:with.s.lo to *var
     * 3. if not equall， clear ZF and copy *var to cmp.s.hi:cmp.s.lo
     */
    __asm__ __volatile__("lock cmpxchg8b %1\n\tsetz %0"
                         : "=q"(ret), "+m"(*var), "+d"(cmp.s.high),
                           "+a"(cmp.s.low)
                         : "c"(with.s.high), "b"(with.s.low)
                         : "cc", "memory");
    if (!ret)
        *old = cmp.ui;
    return ret;
}

/* add a new item to the heap */
static bool prio_queue_insert(prio_queue_t *ptr, void *item)
{
    timer_node **slot;
    size_t old_nalloc, old_size;
    long long old;

restart:
    old_nalloc = atomic_read(&ptr->nalloc);
    old_size = atomic_read(&ptr->nalloc);

    // get the address want to store
    slot = (timer_node **) &ptr->priv[old_nalloc + 1];
    old = (long long) *slot;

    do {
        if (old_nalloc != atomic_read(&ptr->nalloc))
            goto restart;
    } while (!prio_queue_cmpxchg(slot, &old, (long long) item));

    atomic_inc(&ptr->nalloc);
    return true;
}

static int timer_comp(void *ti, void *tj)
{
    return ((timer_node *) ti)->key < ((timer_node *) tj)->key ? 1 : 0;
}

static prio_queue_t timer;
static atomic_t current_msec;

static void time_update(void)
{
    struct timespec64 tv;
    ktime_get_ts64(&tv);
    atomic_set(&current_msec, tv.tv_sec * 1000 + tv.tv_nsec / 1000000);
}

int timer_init()
{
    prio_queue_init(&timer, timer_comp, PQ_DEFAULT_SIZE);

    time_update();
    return 0;
}

void handle_expired_timers()
{
    while (!prio_queue_is_empty(&timer)) {
        time_update();
        timer_node *node = prio_queue_min(&timer);

        if (node->key > atomic_read(&current_msec))
            return;
        prio_queue_delmin(&timer);
    }
}

void cache_timer_update(timer_node *node, size_t timeout)
{
    time_update();
    node->key = atomic_read(&current_msec) + timeout;
    node->pos = prio_queue_sink(&timer, node->pos);
}

void cache_add_timer(struct content_cache_entry *entry, size_t timeout)
{
    timer_node *node = kmalloc(sizeof(timer_node), GFP_KERNEL);
    if (!node)
        return;

    time_update();
    entry->timer = node;
    node->key = atomic_read(&current_msec) + timeout;
    node->pos = atomic_read(&timer.nalloc) + 1;
    node->hash_node = entry->node;

    prio_queue_insert(&timer, node);
}

void cache_free_timer(void)
{
    int i;
    size_t nalloc = atomic_read(&timer.nalloc);

    for (i = 1; i < nalloc + 1; i++)
        kfree(timer.priv[i]);
    kfree(timer.priv);
}