#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <pthread.h>

#define MAXEVENTS 1024
#define BUFLEN 1024

bool running = true;

int fdserver = 0;
int fdclient = 0;
int fdlisten = 0;

typedef enum {
    TUNNEL_STATE_INIT = 0,
    TUNNEL_STATE_OK,
    TUNNEL_STATE_NG
} ProxyState;

typedef struct _ProxyClient {
    int fd;

    struct sockaddr_in addr;
    socklen_t len;
    uint8_t rcv_buf[BUFLEN];
    struct _ProxyTunnel *node;

    struct _ProxyClient *next;
} ProxyClient;

typedef struct _ProxyTunnel {
    ProxyState state;

    bool stream;
    char *ip;
    int port;
    int portlocal;

    uint8_t rcv_buf[BUFLEN];

    int fd;                     /* connect to destnation's fd */
    int fdlocal;                /* bind to localport, server other client's fd */

    ProxyClient *clients;

    /*
     * 锁用来实现对线程间内存安全访问的保障（为避免 线程A 访问 线程B 释放过的内存）
     * tproxy 有两片内存区域需要保护：
     * 1. ProxyTunnel
     *    ProxyTunnel *zeta 整个连表都可能被 主线程 之 proxyDelete() 修改
     *    ProxyTunnel *node 连表中的某个节点会被 proxyPollXxx() 多个业务线程 随即读取
     * 2. ProxyClient
     *    ProxyClient *clients 整个连表都可能被 proxyPollClient线程 之 clientRemove() 修改
     *    Proxyclient *clients 在
     *                 proxyPollServer 线程中，server 发来消息，需要读取
     *                 proxyPollListen 线程中，新客户端建立了连接，需要修改
     *
     * 为此，引入两个锁： rwlock 用来处理情况1，clilock 用来处理情况2.
     */
    pthread_rwlock_t rwlock;
    pthread_mutex_t clilock;

    struct _ProxyTunnel *next;
} ProxyTunnel;

#define TPROXY_LOG(fmt, ...)                                            \
    do {                                                                \
        char _timestr[25] = {0};                                        \
        time_t _tvs = time(NULL);                                       \
        struct tm *_tm = localtime(&_tvs);                              \
        strftime(_timestr, 25, "%Y-%m-%d %H:%M:%S", _tm);               \
        fprintf(stdout, "[%s][%s:%d %s] ", _timestr, __FILE__, __LINE__, __func__); \
        fprintf(stdout, fmt, ##__VA_ARGS__);                            \
        fprintf(stdout, "\n");                                          \
    } while (0)

void useage(char *app)
{
    printf("%s [options]\n"
           "\n"
           "-t \"ip port fport\" Add a tcp tunnel, fport is my service port\n"
           "-u \"ip port fport\" Add a udp tuunel, fport is my service port\n"
           "-d \"ip port\" Delete the tunnel\n"
           "\n", app);
    exit(1);
}

size_t _sendTo(int fd, uint8_t *buf, size_t count)
{
    size_t rv, c;
    c = 0;
    while (c < count) {
        rv = send(fd, buf + c, count - c, MSG_NOSIGNAL);
        if (rv == count) return count;
        else if (rv < 0) return rv;
        else if (rv == 0) return c;

        c += rv;
    }

    return count;
}

/*
 * 172.16.2.8 50000  3001
 */
bool parseArgument3(char *inputs, char **ip, int *port, int *portlocal)
{
    if (!inputs || !ip || !port || !portlocal) return false;

    size_t len = strlen(inputs);
    char *p = inputs, *q = inputs + len;

    /* 去掉首位空格 */
    while (isblank(*p) && p < q) p++;
    while (isblank(*q) && q > p) {
        *q = '\0';
        q--;
    }
    if (p >= q) return false;

    /* ip */
    *ip = p;
    while (!isblank(*p) && p < q) p++;
    if (isblank(*p)) {
        *p = '\0';
        p++;
    }
    if (p >= q) return false;
    while (isblank(*p) && p < q) p++;
    if (p >= q) return false;

    /* port */
    *port = atoi(p);
    while (!isblank(*p) && p < q) p++;
    while (isblank(*p) && p < q) p++;
    if (p >= q) return false;

    /* portlocal */
    *portlocal = atoi(p);

    return true;
}

bool parseArgument2(char *inputs, char **ip, int *port)
{
    if (!inputs || !ip || !port) return false;

    size_t len = strlen(inputs);
    char *p = inputs, *q = inputs + len;

    /* 去掉首位空格 */
    while (isblank(*p) && p < q) p++;
    while (isblank(*q) && q > p) {
        *q = '\0';
        q--;
    }
    if (p >= q) return false;

    /* ip */
    *ip = p;
    while (!isblank(*p) && p < q) p++;
    if (isblank(*p)) {
        *p = '\0';
        p++;
    }
    if (p >= q) return false;
    while (isblank(*p) && p < q) p++;
    if (p >= q) return false;

    /* port */
    *port = atoi(p);

    return true;
}

void proxyOver(int sig)
{
    TPROXY_LOG("call me back, exit");

    running = false;
}

pid_t proxyProcessFind(char *app)
{
    return 0;
}

char* proxyAdd(ProxyTunnel *me, char *ip, int port, int portlocal, bool stream)
{
    //TPROXY_LOG("ADD %s %d %d %d", ip, port, portlocal, stream);

    ProxyTunnel *node, *tail;
    node = tail = me;
    while (node) {
        if (node->ip && node->port == port && !strcmp(node->ip, ip)) {
            return "代理已经存在";
        }

        tail = node;
        node = node->next;
    }

#define RETURN(msg)                                         \
    do {                                                    \
        if (node->fd > 0) { close(node->fd); }              \
        if (node->fdlocal > 0) { close(node->fdlocal); }  \
        tail->next = NULL;                                  \
        free(node->ip);                                     \
        free(node);                                         \
        perror("system call");                              \
        return (msg);                                       \
    } while (0)

    /*
     * 0. 创建 socket，连接目的地
     */
    node = calloc(1, sizeof(ProxyTunnel));
    node->state = TUNNEL_STATE_INIT;
    node->stream = stream;
    node->ip = strdup(ip);
    node->port = port;
    node->portlocal = portlocal;
    node->clients = NULL;
    pthread_rwlock_init(&node->rwlock, NULL);
    pthread_mutex_init(&node->clilock, NULL);
    node->next = NULL;

    tail->next = node;

    if (stream) node->fd = socket(AF_INET, SOCK_STREAM, 0);
    else node->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (node->fd < 0) RETURN("创建socket失败");

    struct in_addr ia;
    int rv = inet_pton(AF_INET, ip, &ia);
    if (rv <= 0) {
        struct hostent *he = gethostbyname(ip);
        if (he == NULL) RETURN("域名解析失败");

        ia.s_addr = *((in_addr_t*)(he->h_addr_list[0]));
    }

    struct sockaddr_in srvsa;
    srvsa.sin_family = AF_INET;
    srvsa.sin_port = htons(port);
    srvsa.sin_addr.s_addr = ia.s_addr;

    rv = connect(node->fd, (struct sockaddr*)&srvsa, sizeof(srvsa));
    if (rv < 0) RETURN("建立连接失败");

    fcntl(node->fd, F_SETFL, fcntl(node->fd, F_GETFL, 0) | O_NONBLOCK);

    struct epoll_event event;
    event.data.ptr = node;
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(fdserver, EPOLL_CTL_ADD, node->fd, &event) < 0) RETURN("加入epoll监听失败");

    /*
     * 1. 创建 socket，提供本地服务
     */
    if (stream) node->fdlocal = socket(AF_INET, SOCK_STREAM, 0);
    else node->fdlocal = socket(AF_INET, SOCK_DGRAM, 0);
    if (node->fdlocal < 0) RETURN("创建socket失败");

    inet_pton(AF_INET, "0.0.0.0", &ia);
    srvsa.sin_addr.s_addr = ia.s_addr;
    srvsa.sin_port = htons(portlocal);

    rv = 1;
    setsockopt(node->fdlocal, SOL_SOCKET, SO_REUSEADDR, &rv, sizeof(rv));

    rv = bind(node->fdlocal, (struct sockaddr*)&srvsa, sizeof(srvsa));
    if (rv < 0) RETURN("绑定本地端口失败");

    if (listen(node->fdlocal, 1024) < 0) RETURN("监听本地端口失败");

    struct epoll_event eventb;
    eventb.data.ptr = node;
    eventb.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(fdlisten, EPOLL_CTL_ADD, node->fdlocal, &eventb) < 0) RETURN("加入epoll监听失败");

    /*
     * over
     */
    node->state = TUNNEL_STATE_OK;

    TPROXY_LOG("建立通道 %s %d %d 成功", ip, port, portlocal);

    return NULL;

#undef RETURN
}

bool proxyDelete(ProxyTunnel *me, char *ip, int port)
{
    if (!me || !ip || port == 0) return false;

    pthread_rwlock_wrlock(&me->rwlock);
    ProxyTunnel *node = me, *prev = me;
    while (node) {
        if (node->ip && node->port == port && !strcmp(node->ip, ip)) {
            /* 因为我们置空了首节点，故首节点自身不会发生变化 */
            prev->next = node->next;

            free(node->ip);
            if (node->state == TUNNEL_STATE_OK) {
                epoll_ctl(fdserver, EPOLL_CTL_DEL, node->fd, NULL);
                epoll_ctl(fdlisten, EPOLL_CTL_DEL, node->fdlocal, NULL);
                close(node->fd);
                close(node->fdlocal);
            }

            ProxyClient *client = node->clients, *clientnext = node->clients;
            while (client) {
                clientnext = client->next;

                epoll_ctl(fdclient, EPOLL_CTL_DEL, client->fd, NULL);
                close(client->fd);
                client->node = NULL;
                free(client);

                client = clientnext;
            }

            free(node);

            pthread_rwlock_unlock(&me->rwlock);
            return true;
        }

        prev = node;
        node = node->next;
    }

    pthread_rwlock_unlock(&me->rwlock);
    return false;
}

void proxyDestroy(ProxyTunnel *me)
{
    ProxyTunnel *node, *next;
    node = next = me;
    while (node) {
        next = node->next;

        free(node->ip);
        if (node->state == TUNNEL_STATE_OK) {
            epoll_ctl(fdserver, EPOLL_CTL_DEL, node->fd, NULL);
            epoll_ctl(fdlisten, EPOLL_CTL_DEL, node->fdlocal, NULL);
            close(node->fd);
            close(node->fdlocal);
        }

        ProxyClient *client = node->clients, *clientnext = node->clients;
        while (client) {
            clientnext = client->next;

            epoll_ctl(fdclient, EPOLL_CTL_DEL, client->fd, NULL);
            close(client->fd);
            client->node = NULL;
            free(client);

            client = clientnext;
        }

        free(node);

        node = next;
    }
}

void serverDown(ProxyTunnel *node)
{
    if (!node) return;

    epoll_ctl(fdserver, EPOLL_CTL_DEL, node->fd, NULL);
    close(node->fd);
    node->state = TUNNEL_STATE_NG;

    /* 没有free，此处不用加锁 */
}

void clientRemove(ProxyClient *client)
{
    if (!client || !client->node) return;

    pthread_mutex_lock(&client->node->clilock);

    ProxyClient *node = client->node->clients, *prev = client->node->clients;

    while (node->fd != client->fd) {
        prev = node;
        node = node->next;
    }

    if (!prev || !node) {
        TPROXY_LOG("impossible, no this client");
        return;
    }

    if (node == client->node->clients) client->node->clients = node->next;
    prev->next = node->next;

    epoll_ctl(fdclient, EPOLL_CTL_DEL, client->fd, NULL);
    close(client->fd);
    client->fd = -1;
    free(client);

    pthread_mutex_unlock(&client->node->clilock);
}

void* proxyPollServer(void *arg)
{
    ssize_t len = 0;
    ProxyTunnel *zeta = (ProxyTunnel*)arg;

    struct epoll_event *events = calloc(MAXEVENTS, sizeof(struct epoll_event));
    while (running) {
        pthread_rwlock_rdlock(&zeta->rwlock);
        int n = epoll_wait(fdserver, events, MAXEVENTS, 2000);

        for (int i = 0; i < n; i++) {
            ProxyTunnel *node = (ProxyTunnel*)events[i].data.ptr;

            //TPROXY_LOG("On server event %s %d", node->ip, node->port);

            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
                TPROXY_LOG("On error %s %d %s", node->ip, node->port, strerror(errno));

                serverDown(node);
                continue;
            }

            while ((len = recv(node->fd, node->rcv_buf, BUFLEN, 0)) > 0) {
                TPROXY_LOG("On receive %s %d %zu bytes", node->ip, node->port, len);
                /*
                 * 消息下行：发给所有客户端
                 */
                pthread_mutex_lock(&node->clilock);
                ProxyClient *client = node->clients;
                while (client) {
                    _sendTo(client->fd, node->rcv_buf, len);

                    client = client->next;
                }
                pthread_mutex_unlock(&node->clilock);
            }
            if (len == 0) {
                TPROXY_LOG("On close %s %d", node->ip, node->port);

                serverDown(node);
                continue;
            } else if (len < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                TPROXY_LOG("unknown error on receive %d %zu %s", node->fd, len, strerror(errno));

                continue;
            }
        }
        pthread_rwlock_unlock(&zeta->rwlock);
    }

    free(events);

    return NULL;
}

void* proxyPollClient(void *arg)
{
    ssize_t len = 0;
    ProxyTunnel *zeta = (ProxyTunnel*)arg;

    struct epoll_event *events = calloc(MAXEVENTS, sizeof(struct epoll_event));
    while (running) {
        pthread_rwlock_rdlock(&zeta->rwlock);
        int n = epoll_wait(fdclient, events, MAXEVENTS, 2000);

        for (int i = 0; i < n; i++) {
            ProxyClient *client = (ProxyClient*)events[i].data.ptr;

            //TPROXY_LOG("On client event lo:%d", client->node->portlocal);

            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
                TPROXY_LOG("On error lo:%d %s", client->node->portlocal, strerror(errno));

                clientRemove(client);
                continue;
            }

            while ((len = recv(client->fd, client->rcv_buf, BUFLEN, 0)) > 0) {
                TPROXY_LOG("On receive lo:%d %zu bytes", client->node->portlocal, len);

                /*
                 * 消息上行：回发给服务器
                 */
                _sendTo(client->node->fd, client->rcv_buf, len);
            }
            if (len == 0) {
                TPROXY_LOG("On close lo:%d", client->node->portlocal);

                clientRemove(client);
                continue;
            } else if (len < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                TPROXY_LOG("unknown error on receive %d %zu %s", client->fd, len, strerror(errno));

                continue;
            }
        }
        pthread_rwlock_unlock(&zeta->rwlock);
    }

    free(events);

    return NULL;
}

void* proxyPollListen(void *arg)
{
    struct epoll_event *events = calloc(MAXEVENTS, sizeof(struct epoll_event));
    ProxyTunnel *zeta = (ProxyTunnel*)arg;

    while (running) {
        pthread_rwlock_rdlock(&zeta->rwlock);
        int n = epoll_wait(fdlisten, events, MAXEVENTS, 2000);

        for (int i = 0; i < n; i++) {
            ProxyTunnel *node = (ProxyTunnel*)events[i].data.ptr;

            ProxyClient *client = calloc(1, sizeof(ProxyClient));
            client->node = node;
            client->fd = accept(node->fdlocal, (struct sockaddr*)&(client->addr), &(client->len));
            if (client->fd < 0) {
                TPROXY_LOG("accept lo:%d %s", node->portlocal, strerror(errno));
                free(client);
                continue;
            }

            TPROXY_LOG("On accept lo:%d", node->portlocal);

            pthread_mutex_lock(&node->clilock);
            client->next = node->clients;
            node->clients = client;
            pthread_mutex_unlock(&node->clilock);

            fcntl(client->fd, F_SETFL, fcntl(client->fd, F_GETFL, 0) | O_NONBLOCK);
            int optval = 1;
            setsockopt(client->fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));

            struct epoll_event event;
            event.data.ptr = client;
            event.events = EPOLLIN | EPOLLET;
            if (epoll_ctl(fdclient, EPOLL_CTL_ADD, client->fd, &event) < 0) {
                TPROXY_LOG("epoll lo:%d %s", node->portlocal, strerror(errno));
                free(client);
            }
        }
        pthread_rwlock_unlock(&zeta->rwlock);
    }

    free(events);

    return NULL;
}

int main(int argc, char *argv[])
{
    char *ip = NULL;
    int port, portlocal;
    char *errmsg;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, proxyOver);

    pid_t pid = proxyProcessFind(argv[0]);
    if (pid > 0) {
        /* 系统中有这个进程在跑了，发消息给他就行 */
        return 0;
    } else {
        /* 还没有这个进程，后台运行 */
        //pid = fork();
        //if (pid > 0) return 0;
        //else if (pid < 0) {
        //    perror("Error in fork");
        //    return 1;
        //}
        //close(0);
        //setsid();
    }

    /* 冗余第一个节点，不干任何事情 */
    ProxyTunnel *zeta = calloc(1, sizeof(ProxyTunnel));
    if (!zeta) {
        perror("memory over!");
        return 1;
    }
    memset(zeta, 0x0, sizeof(ProxyTunnel));
    zeta->ip = strdup("nobody");
    pthread_rwlock_init(&zeta->rwlock, NULL);
    pthread_mutex_init(&zeta->clilock, NULL);

    fdserver = epoll_create1(0);
    fdclient = epoll_create1(0);
    fdlisten = epoll_create1(0);
    if (fdserver < 0 || fdclient < 0 || fdlisten < 0) {
        perror("Epoll Create");
        return 1;
    }

    int c;
    while ((c = getopt(argc, argv, "t:u:d:")) != -1) {
        switch (c) {
        case 't':
            if (parseArgument3(optarg, &ip, &port, &portlocal)) {
                errmsg = proxyAdd(zeta, ip, port, portlocal, true);
                if (errmsg) TPROXY_LOG("Add tunnel %s %d %d : %s", ip, port, portlocal, errmsg);
            } else TPROXY_LOG("%s format error", optarg);

            break;
        case 'u':
            if (parseArgument3(optarg, &ip, &port, &portlocal)) {
                errmsg = proxyAdd(zeta, ip, port, portlocal, false);
                if (errmsg) TPROXY_LOG("Add tunnel %s %d %d : %s", ip, port, portlocal, errmsg);
            } else TPROXY_LOG("%s format error", optarg);

            break;
        case 'd':
            if (parseArgument2(optarg, &ip, &port)) {
                if (!proxyDelete(zeta, ip, port))
                    TPROXY_LOG("tunnel %s %d don't exist", ip, port);
            } else TPROXY_LOG("%s format error", optarg);

            break;
        default:
            useage(argv[0]);
        }
    }

    TPROXY_LOG("tiny proxy running...");

    running = true;

    pthread_t workera, workerb, workerc;
    pthread_create(&workera, NULL, proxyPollServer, zeta);
    pthread_create(&workerb, NULL, proxyPollClient, zeta);
    pthread_create(&workerc, NULL, proxyPollListen, zeta);

    while (running) {
        //proxyAdd(zeta, "172.16.1.82", 7778, 3001, true);
        sleep(1);
        //proxyDelete(zeta, "172.16.1.82", 7778);
    }

    pthread_join(workera, NULL);
    pthread_join(workerb, NULL);
    pthread_join(workerc, NULL);

    TPROXY_LOG("tiny proxy over.");

    proxyDestroy(zeta);

    close(fdserver);
    close(fdclient);
    close(fdlisten);

    return 0;
}
