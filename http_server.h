#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <linux/workqueue.h>
#include <net/sock.h>
#include "http_parser.h"

#define MODULE_NAME "khttpd"
#define CACHE_BUFFER_SIZE 8192

struct http_server_param {
    struct socket *listen_socket;
};

extern int http_server_daemon(void *arg);

struct httpd_service {
    bool is_stopped;
    struct list_head head;
};
extern struct httpd_service daemon;

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    char cache_buffer[CACHE_BUFFER_SIZE];
    struct dir_context dir_context;
    struct list_head node;
    struct work_struct khttpd_work;
};

#endif
