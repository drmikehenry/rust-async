#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define LOG(message) write_log(__func__, __LINE__, message)

void
write_log(const char *func_name, int line_num, const char *message)
{
    int saved_errno = errno;
    fprintf(stderr, "%s:%d: %s\n", func_name, line_num, message);
    errno = saved_errno;
}

#define LOG_WITH_ERRNO(message) \
    write_log_with_errno(__func__, __LINE__, message)

void
write_log_with_errno(const char *func_name, int line_num, const char *message)
{
    int saved_errno = errno;
    fprintf(
        stderr,
        "%s:%d: %s; errno=%d: %s\n",
        func_name,
        line_num,
        message,
        saved_errno,
        strerror(saved_errno));
    errno = saved_errno;
}

#define EXIT_IF(predicate) ((void)(predicate && (LOG(#predicate), exit(1), 0)))

int
interrupted(int errno_value)
{
    return (errno_value == EINTR);
}

int
would_block(int errno_value)
{
    return (errno_value == EAGAIN || errno_value == EWOULDBLOCK);
}

ssize_t
safe_read(int fd, void *buf, size_t n)
{
    ssize_t rv;
    do
    {
        rv = read(fd, buf, n);
    } while (rv == -1 && interrupted(errno));
    if (rv == -1 && !would_block(errno))
    {
        LOG_WITH_ERRNO("read()");
    }
    return rv;
}

ssize_t
safe_write(int fd, const void *buf, size_t n)
{
    ssize_t rv;
    do
    {
        rv = write(fd, buf, n);
    } while (rv == -1 && interrupted(errno));
    if (rv == -1 && !would_block(errno))
    {
        LOG_WITH_ERRNO("write()");
    }
    return rv;
}

typedef union SockAddr
{
    struct sockaddr sa;
    struct sockaddr_in sa_in;
    struct sockaddr_storage sa_storage;
} SockAddr;

void
SockAddr_from_ip_port(
    SockAddr *addr, socklen_t *addr_size, uint32_t ip, uint16_t port)
{
    memset(addr, 0x00, sizeof(*addr));
    addr->sa_in.sin_family = AF_INET;
    addr->sa_in.sin_addr.s_addr = htonl(ip);
    addr->sa_in.sin_port = htons(port);
    *addr_size = sizeof(addr->sa_in);
}

int
socket_create_blocking(void)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        LOG_WITH_ERRNO("socket()");
        return -1;
    }
    return sock;
}

int
socket_set_non_blocking(int sock)
{
    int rv = fcntl(sock, F_SETFL, O_NONBLOCK);
    if (rv == -1)
    {
        LOG_WITH_ERRNO("fcntl(O_NONBLOCK)");
    }
    return rv;
}

int
socket_listen_ip_port(int sock, uint32_t ip, uint16_t port)
{
    SockAddr addr;
    socklen_t addr_size;
    SockAddr_from_ip_port(&addr, &addr_size, ip, port);

    if (bind(sock, &addr.sa, addr_size) == -1)
    {
        LOG_WITH_ERRNO("bind()");
        return -1;
    }
    if (listen(sock, 5) == -1)
    {
        LOG_WITH_ERRNO("listen()");
        return -1;
    }

    return sock;
}

int
socket_accept(
    int listen_sock, SockAddr *client_addr, socklen_t *client_addr_size)
{
    *client_addr_size = sizeof(client_addr->sa_storage);
    int sock = accept(listen_sock, &client_addr->sa, client_addr_size);
    if (sock < 0)
    {
        LOG_WITH_ERRNO("accept()");
    }
    return sock;
}

int
socket_connect_ip_port(int sock, uint32_t ip, uint16_t port)
{
    SockAddr addr;
    socklen_t addr_size;
    SockAddr_from_ip_port(&addr, &addr_size, ip, port);

    if (connect(sock, &addr.sa, addr_size) == -1)
    {
        LOG_WITH_ERRNO("connect()");
        return -1;
    }

    return sock;
}

//////////////////////////////////////////////////////////////////////////////
// Single-threaded copy

int
socket_copy(int src_sock, int dst_sock)
{
    unsigned char buf[1024];
    printf("copy %d -> %d\n", src_sock, dst_sock);

    for (;;)
    {
        ssize_t n = safe_read(src_sock, buf, sizeof(buf));
        if (n == -1)
        {
            LOG("safe_read()");
            return -1;
        }
        if (n == 0)
        {
            break;
        }

        unsigned char *p = buf;
        while (n > 0)
        {
            ssize_t rv = safe_write(dst_sock, p, n);
            if (rv == -1)
            {
                LOG("safe_write()");
                return -1;
            }
            p += rv;
            n -= rv;
        }
    }

    if (shutdown(dst_sock, SHUT_WR) == -1)
    {
        LOG("shutdown(dst_sock)");
        return -1;
    }
    printf("done %d -> %d\n", src_sock, dst_sock);

    return 0;
}

int
socket_relay_single(int left_sock, int right_sock)
{
    if (socket_copy(left_sock, right_sock) == -1)
    {
        LOG("socket_relay_single()");
        return -1;
    }
    return 0;
}

//////////////////////////////////////////////////////////////////////////////
// Multi-threaded copy

typedef struct SocketCopyThreadedArgs
{
    int left_sock;
    int right_sock;
    int rv;
} SocketCopyThreadedArgs;

void
SocketCopyThreadedArgs_init(
    SocketCopyThreadedArgs *args, int left_sock, int right_sock)
{
    args->left_sock = left_sock;
    args->right_sock = right_sock;
    args->rv = 0;
}

void *
socket_copy_threaded(void *args)
{
    SocketCopyThreadedArgs *copy_args = (SocketCopyThreadedArgs *)args;

    copy_args->rv = socket_copy(copy_args->left_sock, copy_args->right_sock);
    if (copy_args->rv == -1)
    {
        LOG("socket_copy()");
    }

    return NULL;
}

int
socket_relay_threaded(int left_sock, int right_sock)
{
    int rv;
    pthread_t left_thread;
    pthread_t right_thread;
    SocketCopyThreadedArgs left_args;
    SocketCopyThreadedArgs right_args;
    SocketCopyThreadedArgs_init(&left_args, left_sock, right_sock);
    SocketCopyThreadedArgs_init(&right_args, right_sock, left_sock);

    rv = pthread_create(&left_thread, NULL, socket_copy_threaded, &left_args);
    if (rv == -1)
    {
        LOG_WITH_ERRNO("pthread_create(left_thread)");
        return -1;
    }

    rv = pthread_create(&right_thread, NULL, socket_copy_threaded, &right_args);
    if (rv == -1)
    {
        LOG_WITH_ERRNO("pthread_create(right_thread)");
        return -1;
    }

    rv = pthread_join(left_thread, NULL);
    if (rv == -1)
    {
        LOG_WITH_ERRNO("pthread_join(left_thread)");
        return -1;
    }

    rv = pthread_join(right_thread, NULL);
    if (rv == -1)
    {
        LOG_WITH_ERRNO("pthread_join(right_thread)");
        return -1;
    }

    return 0;
}

//////////////////////////////////////////////////////////////////////////////
// Select-based copy

typedef struct SocketCopySelect
{
    int src_sock;
    int dst_sock;
    int writing;
    unsigned char buf[1024];
    ssize_t n;
    unsigned char *p;
} SocketCopySelect;

void
SocketCopySelect_init(int src_sock, int dst_sock, SocketCopySelect *scs)
{
    *scs = (SocketCopySelect){0};
    scs->src_sock = src_sock;
    scs->dst_sock = dst_sock;
}

int
socket_relay_select_write(SocketCopySelect *job)
{
    ssize_t rv = safe_write(job->dst_sock, job->p, job->n);
    if (rv == -1)
    {
        LOG("safe_write()");
        return -1;
    }
    job->p += rv;
    job->n -= rv;
    if (job->n == 0)
    {
        job->writing = 0;
        if (job->src_sock < 0)
        {
            int fd = job->dst_sock;
            job->dst_sock = -1;
            if (shutdown(fd, SHUT_WR) == -1)
            {
                LOG("shutdown(dst_sock)");
                return -1;
            }
        }
    }
    return 0;
}

int
socket_relay_select_read(SocketCopySelect *job)
{
    ssize_t n = safe_read(job->src_sock, job->buf, sizeof(job->buf));
    if (n == -1)
    {
        LOG("safe_read()");
        return -1;
    }
    if (n == 0)
    {
        job->src_sock = -1;
    }
    job->writing = 1;
    job->n = n;
    job->p = job->buf;
    return 0;
}

int
socket_relay_select(int left_sock, int right_sock)
{
    int i;
    int num_copy_jobs = 2;
    SocketCopySelect copy_jobs[2];

    SocketCopySelect_init(left_sock, right_sock, &copy_jobs[0]);
    SocketCopySelect_init(right_sock, left_sock, &copy_jobs[1]);

    for (;;)
    {
        int num_fds = 0;
        fd_set read_fds;
        fd_set write_fds;
        fd_set except_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_ZERO(&except_fds);
        for (i = 0; i < num_copy_jobs; i++)
        {
            int fd;
            SocketCopySelect *job = &copy_jobs[i];
            if (job->writing)
            {
                fd = job->dst_sock;
                if (fd < 0)
                {
                    continue;
                }
                FD_SET(fd, &write_fds);
            }
            else
            {
                fd = job->src_sock;
                if (fd < 0)
                {
                    continue;
                }
                FD_SET(fd, &read_fds);
            }
            FD_SET(fd, &except_fds);
            if (num_fds < fd + 1)
            {
                num_fds = fd + 1;
            }
        }
        if (num_fds == 0)
        {
            break;
        }

        int rv = select(num_fds, &read_fds, &write_fds, &except_fds, NULL);
        if (rv == -1)
        {
            LOG_WITH_ERRNO("select()");
            return -1;
        }

        for (i = 0; i < num_copy_jobs; i++)
        {
            SocketCopySelect *job = &copy_jobs[i];
            if (job->writing)
            {
                int fd = job->dst_sock;
                if (fd >= 0 && FD_ISSET(fd, &write_fds))
                {
                    int rv = socket_relay_select_write(job);
                    if (rv == -1)
                    {
                        LOG("socket_relay_select_write()");
                        return -1;
                    }
                }
            }
            else
            {
                int fd = job->src_sock;
                if (fd >= 0 && FD_ISSET(fd, &read_fds))
                {
                    int rv = socket_relay_select_read(job);
                    if (rv == -1)
                    {
                        LOG("socket_relay_select_read()");
                        return -1;
                    }
                }
            }
        }
    }
    return 0;
}

//////////////////////////////////////////////////////////////////////////////
// Async copy

typedef struct Context
{
    fd_set read_fds;
    fd_set write_fds;
    fd_set except_fds;
    int num_fds;
} Context;

void
Context_reset(Context *cx)
{
    FD_ZERO(&cx->read_fds);
    FD_ZERO(&cx->write_fds);
    FD_ZERO(&cx->except_fds);
    cx->num_fds = 0;
}

static inline void
Context_update(Context *cx, int fd)
{
    int min_num_fds = fd + 1;
    if (cx->num_fds < min_num_fds)
    {
        cx->num_fds = min_num_fds;
    }
}

void
Context_add_for_read(Context *cx, int fd)
{
    FD_SET(fd, &cx->read_fds);
    FD_SET(fd, &cx->except_fds);
    Context_update(cx, fd);
}

void
Context_add_for_write(Context *cx, int fd)
{
    FD_SET(fd, &cx->write_fds);
    FD_SET(fd, &cx->except_fds);
    Context_update(cx, fd);
}

typedef enum
{
    PollPending,
    PollReady,
} PollStatus;

typedef PollStatus
PollFunction(void *poll_state, Context *cx);

typedef struct SocketCopyAsyncState
{
    int location;
    int src_sock;
    int dst_sock;
    int rv;
    unsigned char buf[1024];
    ssize_t n;
    unsigned char *p;
} SocketCopyAsyncState;

enum
{
    SocketCopyAsyncLocation_Start,
    SocketCopyAsyncLocation_Read,
    SocketCopyAsyncLocation_Write,
};

void
socket_copy_async_init(int src_sock, int dst_sock, SocketCopyAsyncState *state)
{
    *state = (SocketCopyAsyncState){0};
    state->location = SocketCopyAsyncLocation_Start;
    state->src_sock = src_sock;
    state->dst_sock = dst_sock;
}

PollStatus
socket_copy_async_poll(SocketCopyAsyncState *poll_state, Context *cx)
{
    SocketCopyAsyncState *state = (SocketCopyAsyncState *)poll_state;
    switch (state->location)
    {
    case SocketCopyAsyncLocation_Start:
        goto location_start;

    case SocketCopyAsyncLocation_Read:
        goto location_read;

    case SocketCopyAsyncLocation_Write:
        goto location_write;
    }

location_start:

    printf("copy %d -> %d\n", state->src_sock, state->dst_sock);

    for (;;)
    {
    location_read:
        state->location = SocketCopyAsyncLocation_Read;
        state->n = safe_read(state->src_sock, state->buf, sizeof(state->buf));
        if (state->n == -1 && would_block(errno))
        {
            Context_add_for_read(cx, state->src_sock);
            return PollPending;
        }
        if (state->n == -1)
        {
            LOG("safe_read()");
            state->rv = -1;
            return PollReady;
        }
        if (state->n == 0)
        {
            break;
        }

        state->p = state->buf;
        while (state->n > 0)
        {
        location_write:
            state->location = SocketCopyAsyncLocation_Write;
            ssize_t rv = safe_write(state->dst_sock, state->p, state->n);
            if (rv == -1 && would_block(errno))
            {
                Context_add_for_write(cx, state->dst_sock);
                return PollPending;
            }
            if (rv == -1)
            {
                LOG("safe_write()");
                state->rv = -1;
                return PollReady;
            }
            state->p += rv;
            state->n -= rv;
        }
    }

    if (shutdown(state->dst_sock, SHUT_WR) == -1)
    {
        LOG("shutdown(dst_sock)");
        state->rv = -1;
        return PollReady;
    }
    printf("done %d -> %d\n", state->src_sock, state->dst_sock);
    state->rv = 0;
    return PollReady;
}

int
socket_relay_async(int left_sock, int right_sock)
{
    if (socket_set_non_blocking(left_sock) == -1)
    {
        LOG("socket_set_non_blocking(left_sock)");
        return -1;
    }
    if (socket_set_non_blocking(right_sock) == -1)
    {
        LOG("socket_set_non_blocking(right_sock)");
        return -1;
    }

    SocketCopyAsyncState state1;
    SocketCopyAsyncState state2;
    socket_copy_async_init(left_sock, right_sock, &state1);
    socket_copy_async_init(right_sock, left_sock, &state2);

    PollStatus poll1 = PollPending;
    PollStatus poll2 = PollPending;

    Context cx;

    while (poll1 == PollPending || poll2 == PollPending)
    {
        Context_reset(&cx);
        if (poll1 == PollPending)
        {
            poll1 = socket_copy_async_poll(&state1, &cx);
        }
        if (poll2 == PollPending)
        {
            poll2 = socket_copy_async_poll(&state2, &cx);
        }
        if (cx.num_fds > 0)
        {
            int rv = select(
                cx.num_fds, &cx.read_fds, &cx.write_fds, &cx.except_fds, NULL);
            if (rv == -1)
            {
                LOG_WITH_ERRNO("select()");
                return -1;
            }
        }
    }

    int rv = 0;
    if (state1.rv == -1)
    {
        LOG("state1 failed");
        rv = -1;
    }
    if (state2.rv == -1)
    {
        LOG("state2 failed");
        rv = -1;
    }
    return rv;
}

//////////////////////////////////////////////////////////////////////////////
// main

int
main(int argc, char *argv[])
{
    uint16_t listen_port = 8096;
    uint16_t connect_port = 8097;

    if (argc < 2 || argc > 4)
    {
        printf("Usage: relay MODE [LISTEN_PORT] [CONNECT_PORT]\n");
        printf("MODE is one of: single threaded select async\n");
        printf("Defaults:\n");
        printf("  LISTEN_PORT=%d\n", listen_port);
        printf("  CONNECT_PORT=%d\n", connect_port);
        exit(1);
    }

    const char *mode = argv[1];
    int (*socket_relay_func)(int src_sock, int dst_sock);
    if (strcmp(mode, "single") == 0)
    {
        socket_relay_func = socket_relay_single;
    }
    else if (strcmp(mode, "threaded") == 0)
    {
        socket_relay_func = socket_relay_threaded;
    }
    else if (strcmp(mode, "select") == 0)
    {
        socket_relay_func = socket_relay_select;
    }
    else if (strcmp(mode, "async") == 0)
    {
        socket_relay_func = socket_relay_async;
    }
    else
    {
        printf("Invalid mode %s\n", mode);
        exit(1);
    }

    if (argc >= 3)
    {
        listen_port = atoi(argv[2]);
    }
    if (argc >= 4)
    {
        connect_port = atoi(argv[3]);
    }
    printf(
        "Mode=%s: LISTEN_PORT=%d, CONNECT_PORT=%d\n",
        mode,
        listen_port,
        connect_port);

    uint32_t ip = 0x7f000001;

    int listen_sock = socket_create_blocking();
    EXIT_IF(listen_sock < 0);
    EXIT_IF(socket_listen_ip_port(listen_sock, ip, listen_port) == -1);

    SockAddr client_addr;
    socklen_t client_addr_size;
    int server_sock =
        socket_accept(listen_sock, &client_addr, &client_addr_size);
    EXIT_IF(server_sock < 0);

    int client_sock = socket_create_blocking();
    EXIT_IF(client_sock < 0);
    EXIT_IF(socket_connect_ip_port(client_sock, ip, connect_port) == -1);

    EXIT_IF(socket_relay_func(server_sock, client_sock) == -1);

    close(server_sock);
    close(client_sock);
    close(listen_sock);
    return 0;
}
