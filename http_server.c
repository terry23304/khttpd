#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "http_server.h"
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>
#include "content_cache.h"
#include "mime_map.h"
#include "timer.h"

#define CRLF "\r\n"

#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                        \
    "HTTP/1.1 200 OK" CRLF "Server: KBUILD_MODNAME" CRLF         \
    "Content-Type: text/html" CRLF "Connection: Keep-Alive" CRLF \
    "Keep-Alive: timeout=5, max=1000" CRLF CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_404                                        \
    ""                                                           \
    "HTTP/1.1 404 Not Found" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 13" CRLF    \
    "Connection: Close" CRLF CRLF "404 Not Found"

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 256
#define REQUEST_URL_SIZE 64
#define DIR "/home/terry/Documents/linux-2023/khttpd"

struct httpd_service daemon = {.is_stopped = false};
extern struct workqueue_struct *khttpd_wq;

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

static int tracedir(struct dir_context *dir_context,
                    const char *name,
                    int namelen,
                    loff_t offset,
                    u64 ino,
                    unsigned int d_type)
{
    if (strcmp(name, ".")) {
        struct http_request *request =
            container_of(dir_context, struct http_request, dir_context);
        char buf[SEND_BUFFER_SIZE] = {0};

        snprintf(buf, SEND_BUFFER_SIZE,
                 "<tr><td><a href=\"%s\">%s</a></td></tr>\r\n", name, name);
        strncat(request->cache_buffer, buf, strlen(buf));
        http_server_send(request->socket, buf, strlen(buf));
    }

    return 0;
}

static void directory_listing(struct http_request *request)
{
    struct file *fp;
    char buf[SEND_BUFFER_SIZE] = {0};
    char request_url[REQUEST_URL_SIZE] = {0};
    char *response;

    request->dir_context.actor = tracedir;
    memset(request->cache_buffer, 0, CACHE_BUFFER_SIZE);

    snprintf(request_url, REQUEST_URL_SIZE, "%s%s", DIR, request->request_url);

    response = get_content(request_url);
    strncpy(request->cache_buffer, response, strlen(response));

    if (strlen(response) != 0) {
        http_server_send(request->socket, request->cache_buffer,
                         strlen(request->cache_buffer));
        return;
    }

    fp = filp_open(request_url, O_RDONLY, 0);

    if (IS_ERR(fp)) {
        pr_info("Open file failed");
        http_server_send(request->socket, HTTP_RESPONSE_404,
                         strlen(HTTP_RESPONSE_404));
        filp_close(fp, NULL);
        strncat(request->cache_buffer, HTTP_RESPONSE_404,
                strlen(HTTP_RESPONSE_404));
        return;
    }

    if (S_ISDIR(fp->f_inode->i_mode)) {
        http_server_send(request->socket, HTTP_RESPONSE_200_KEEPALIVE_DUMMY,
                         strlen(HTTP_RESPONSE_200_KEEPALIVE_DUMMY));

        strncat(request->cache_buffer, HTTP_RESPONSE_200_KEEPALIVE_DUMMY,
                strlen(HTTP_RESPONSE_200_KEEPALIVE_DUMMY));

        snprintf(buf, SEND_BUFFER_SIZE, "%s%s%s%s", "<html><head><style>\r\n",
                 "body{font-family: monospace; font-size: 15px;}\r\n",
                 "td {padding: 1.5px 6px;}\r\n",
                 "</style></head><body><table>\r\n");
        http_server_send(request->socket, buf, strlen(buf));

        strncat(request->cache_buffer, buf, strlen(buf));

        iterate_dir(fp, &request->dir_context);
        snprintf(buf, SEND_BUFFER_SIZE, "</table></body></html>\r\n");
        http_server_send(request->socket, buf, strlen(buf));

        strncat(request->cache_buffer, buf, strlen(buf));
    } else if (S_ISREG(fp->f_inode->i_mode)) {
        const char *extension = strchr(request->request_url, '.');
        snprintf(buf, SEND_BUFFER_SIZE, "%s%s%s%s", "HTTP/1.1 200 OK\r\n",
                 "Content-Type: ", get_mime_type(extension),
                 "\r\nConnection: Keep-Alive\r\n\r\n");
        http_server_send(request->socket, buf, strlen(buf));

        strncat(request->cache_buffer, buf, strlen(buf));

        char *file_content = kmalloc(fp->f_inode->i_size, GFP_KERNEL);
        if (!file_content) {
            pr_info("malloc failed");
            filp_close(fp, NULL);
            return;
        }

        int ret = kernel_read(fp, file_content, fp->f_inode->i_size, 0);
        http_server_send(request->socket, file_content, ret);

        strncat(request->cache_buffer, file_content, strlen(file_content));
        kfree(file_content);
    }

    insert_content_cache(request_url, request->cache_buffer);

    filp_close(fp, NULL);
    return;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    if (request->method != HTTP_GET) {
        http_server_send(request->socket, HTTP_RESPONSE_501_KEEPALIVE,
                         strlen(HTTP_RESPONSE_501_KEEPALIVE));
        return 0;
    }

    handle_expired_timers();
    directory_listing(request);

    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

static void http_server_worker(struct work_struct *work)
{
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request *worker =
        container_of(work, struct http_request, khttpd_work);

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return;
    }

    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &worker->socket;
    while (!daemon.is_stopped) {
        int ret = http_server_recv(worker->socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (worker->complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }

    kernel_sock_shutdown(worker->socket, SHUT_RDWR);
    kfree(buf);
}

static struct work_struct *create_work(struct socket *sk)
{
    struct http_request *work;

    if (!(work = kmalloc(sizeof(struct http_request), GFP_KERNEL)))
        return NULL;

    work->socket = sk;

    INIT_WORK(&work->khttpd_work, http_server_worker);

    list_add(&work->node, &daemon.head);

    return &work->khttpd_work;
}

static void free_work(void)
{
    struct http_request *l, *tar;
    /* cppcheck-suppress uninitvar */

    list_for_each_entry_safe (tar, l, &daemon.head, node) {
        kernel_sock_shutdown(tar->socket, SHUT_RDWR);
        flush_work(&tar->khttpd_work);
        sock_release(tar->socket);
        kfree(tar);
    }
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct work_struct *work;
    struct http_server_param *param = (struct http_server_param *) arg;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    INIT_LIST_HEAD(&daemon.head);

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }

        if (unlikely(!(work = create_work(socket)))) {
            printk(KERN_ERR MODULE_NAME
                   ": create work error, connection closed\n");
            kernel_sock_shutdown(socket, SHUT_RDWR);
            sock_release(socket);
            continue;
        }

        queue_work(khttpd_wq, work);
    }

    printk(MODULE_NAME ": daemon shutdown in progress...\n");

    daemon.is_stopped = true;
    free_work();

    return 0;
}
