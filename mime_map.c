#include "mime_map.h"
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/string.h>

DEFINE_READ_MOSTLY_HASHTABLE(mime_map_table, 8);

struct mime_map_entry mime_map[] = {
    {".aac", "audio/aac"},
    {".abw", "application/x-abiword"},
    {".arc", "application/x-freearc"},
    {".avi", "video/x-msvideo"},
    {".azw", "application/vnd.amazon.ebook"},
    {".bin", "application/octet-stream"},
    {".bmp", "image/bmp"},
    {".bz", "application/x-bzip"},
    {".bz2", "application/x-bzip2"},
    {".csh", "application/x-csh"},
    {".css", "text/css"},
    {".csv", "text/csv"},
    {".doc", "application/msword"},
    {".docx",
     "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {".eot", "application/vnd.ms-fontobject"},
    {".epub", "application/epub+zip"},
    {".gz", "application/gzip"},
    {".gif", "image/gif"},
    {".htm", "text/html"},
    {".html", "text/html"},
    {".ico", "image/vnd.microsoft.icon"},
    {".ics", "text/calendar"},
    {".jar", "application/java-archive"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {".js", "text/javascript"},
    {".json", "application/json"},
    {".jsonld", "application/ld+json"},
    {".mid", "audio/midi audio/x-midi"},
    {".midi", "audio/midi audio/x-midi"},
    {".mjs", "text/javascript"},
    {".mp3", "audio/mpeg"},
    {".mp4", "video/mp4"},
    {".mpeg", "video/mpeg"},
    {".mpkg", "application/vnd.apple.installer+xml"},
    {".odp", "application/vnd.oasis.opendocument.presentation"},
    {".ods", "application/vnd.oasis.opendocument.spreadsheet"},
    {".odt", "application/vnd.oasis.opendocument.text"},
    {".oga", "audio/ogg"},
    {".ogv", "video/ogg"},
    {".ogx", "application/ogg"},
    {".opus", "audio/opus"},
    {".otf", "font/otf"},
    {".png", "image/png"},
    {".pdf", "application/pdf"},
    {".php", "application/x-httpd-php"},
    {".ppt", "application/vnd.ms-powerpoint"},
    {".pptx",
     "application/"
     "vnd.openxmlformats-officedocument.presentationml.presentation"},
    {".rar", "application/vnd.rar"},
    {".rtf", "application/rtf"},
    {".sh", "application/x-sh"},
    {".svg", "image/svg+xml"},
    {".swf", "application/x-shockwave-flash"},
    {".tar", "application/x-tar"},
    {".tif", "image/tiff"},
    {".tiff", "image/tiff"},
    {".ts", "video/mp2t"},
    {".ttf", "font/ttf"},
    {".txt", "text/plain"},
    {".vsd", "application/vnd.visio"},
    {".wav", "audio/wav"},
    {".weba", "audio/webm"},
    {".webm", "video/webm"},
    {".webp", "image/webp"},
    {".woff", "font/woff"},
    {".woff2", "font/woff2"},
    {".xhtml", "application/xhtml+xml"},
    {".xls", "application/vnd.ms-excel"},
    {".xlsx",
     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {".xml", "text/xml"},
    {".xul", "application/vnd.mozilla.xul+xml"},
    {".zip", "application/zip"},
    {".3gp", "video/3gpp"},
    {".3g2", "video/3gpp2"},
    {".7z", "application/x-7z-compressed"},
    {NULL, NULL}};

int mime_hash(const char *extension)
{
    unsigned long int value = 0x61C88647;
    size_t n = strlen(extension);

    int i = 0;

    for (; value < ULONG_MAX && i < n; i++) {
        value = value << 8;
        value += extension[i];
    }

    return value % 8;
}

void init_mime_map_table(void)
{
    struct mime_map_entry *entry;

    hash_init(mime_map_table);

    for (entry = mime_map; entry->extension != NULL; entry++) {
        hash_add(mime_map_table, &entry->node, mime_hash(entry->extension));
    }
}

void free_mime_map_table(void)
{
    struct mime_map_entry *entry;
    struct hlist_node *tmp;
    unsigned int bucket;

    hash_for_each_safe(mime_map_table, bucket, tmp, entry, node)
    {
        hash_del(&entry->node);
        kfree(entry);
    }
}

const char *get_mime_type(const char *extension)
{
    if (!extension)
        return "text/plain";

    struct mime_map_entry *entry =
        kmalloc(sizeof(struct mime_map_entry), GFP_KERNEL);

    if (!entry)
        return "text/plain";
    struct hlist_node *node;

    hash_for_each_possible(mime_map_table, entry, node, mime_hash(extension))
    {
        if (!strcmp(entry->extension, extension))
            return entry->mime_type;
    }

    return "text/plain";
}