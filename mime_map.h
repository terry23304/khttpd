#ifndef MIME_MAP_H
#define MIME_MAP_H

#include <linux/hashtable.h>

struct mime_map_entry {
    const char *extension;
    const char *mime_type;
    struct hlist_node node;
};

int mime_hash(const char *extension);
void init_mime_map_table(void);
void free_mime_map_table(void);
const char *get_mime_type(const char *extension);

#endif