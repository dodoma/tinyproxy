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

#define MAXEVENTS 1024
#define MAXLEN 1024

bool running = true;

typedef enum {
    TUNNEL_STATE_INIT = 0,
    TUNNEL_STATE_OK,
    TUNNEL_STATE_NG
} ProxyState;

typedef struct _ProxyTunnel {
    ProxyState state;

    bool stream;
    char *ip;
    int port;
    int portlocal;

    uint8_t rcv_buf[MAXLEN];

    int fd;

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

char* proxyAdd(ProxyTunnel *me, int efd, char *ip, int port, int portlocal, bool stream)
{
    //TPROXY_LOG("ADD %s %d %d %d", ip, port, portlocal, stream);

    ProxyTunnel *node, *tail;
    node = tail = me;
    while (node) {
        if (node->ip && !strcmp(node->ip, ip) && node->port == port) {
            return "代理已经存在";
        }

        tail = node;
        node = node->next;
    }

#define RETURN(msg)                             \
    do {                                        \
        if (node->fd > 0) { close(node->fd); }  \
        tail->next = NULL;                      \
        free(node->ip);                         \
        free(node);                             \
        return (msg);                           \
    } while (0)

    node = calloc(1, sizeof(ProxyTunnel));
    node->state = TUNNEL_STATE_INIT;
    node->stream = stream;
    node->ip = strdup(ip);
    node->port = port;
    node->portlocal = portlocal;
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
    if (rv == -1) {
        perror("connect");
        RETURN("建立连接失败");
    }

    fcntl(node->fd, F_SETFL, fcntl(node->fd, F_GETFL, 0) | O_NONBLOCK);

    struct epoll_event event;
    event.data.ptr = node;
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(efd, EPOLL_CTL_ADD, node->fd, &event) < 0) RETURN("加入epoll监听失败");

    node->state = TUNNEL_STATE_OK;

    TPROXY_LOG("建立通道 %s %d %d 成功", ip, port, portlocal);

    return NULL;

#undef RETURN
}

bool proxyDelete(ProxyTunnel *me, int efd, char *ip, int port)
{
    return true;
}

void proxyDestroy(ProxyTunnel *me, int efd)
{
    ProxyTunnel *node, *next;
    node = next = me;
    while (node) {
        next = node->next;

        free(node->ip);
        if (node->state == TUNNEL_STATE_OK) {
            epoll_ctl(efd, EPOLL_CTL_DEL, node->fd, NULL);
            close(node->fd);
        }
        free(node);

        node = next;
    }
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

    int efd = epoll_create1(0);
    if (efd < 0) {
        perror("Epoll Create");
        return 1;
    }
    struct epoll_event *events = calloc(MAXEVENTS, sizeof(struct epoll_event));

    int c;
    while ((c = getopt(argc, argv, "t:u:d:")) != -1) {
        switch (c) {
        case 't':
            if (parseArgument3(optarg, &ip, &port, &portlocal)) {
                errmsg = proxyAdd(zeta, efd, ip, port, portlocal, true);
                if (errmsg) TPROXY_LOG("Add tunnel %s %d %d : %s", ip, port, portlocal, errmsg);
            } else TPROXY_LOG("%s format error", optarg);

            break;
        case 'u':
            if (parseArgument3(optarg, &ip, &port, &portlocal)) {
                errmsg = proxyAdd(zeta, efd, ip, port, portlocal, false);
                if (errmsg) TPROXY_LOG("Add tunnel %s %d %d : %s", ip, port, portlocal, errmsg);
            } else TPROXY_LOG("%s format error", optarg);

            break;
        case 'd':
            if (parseArgument2(optarg, &ip, &port)) {
                if (!proxyDelete(zeta, efd, ip, port))
                    TPROXY_LOG("tunnel %s %d don't exist", ip, port);
            } else TPROXY_LOG("%s format error", optarg);

            break;
        default:
            useage(argv[1]);
        }
    }

    TPROXY_LOG("tiny proxy running...");

    running = true;
    while (running) {
        int n = epoll_wait(efd, events, MAXEVENTS, 2000);
        //TPROXY_LOG("%d events polled", n);

        for (int i = 0; i < n; i++) {
            ProxyTunnel *node = (ProxyTunnel*)events[i].data.ptr;

            //TPROXY_LOG("poll return on %dnd %d %s %d", i, node->fd, node->ip, node->port);

            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) ||
                (!(events[i].events & EPOLLIN))) {
                TPROXY_LOG("epoll %d error", node->fd);

                epoll_ctl(efd, EPOLL_CTL_DEL, node->fd, NULL);
                close(node->fd);
                node->state = TUNNEL_STATE_NG;
                continue;
            }

            size_t len = recv(node->fd, node->rcv_buf, MAXLEN, 0);
            if (len == 0) {
                TPROXY_LOG("server closed connect");

                epoll_ctl(efd, EPOLL_CTL_DEL, node->fd, NULL);
                close(node->fd);
                node->state = TUNNEL_STATE_NG;
                continue;
            } else if (len < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                TPROXY_LOG("unknown error on receive %d %zu %s", node->fd, len, strerror(errno));

                continue;
            }

            TPROXY_LOG("%s %d receive %zu bytes", node->ip, node->port, len);
        }
    }

    TPROXY_LOG("tiny proxy over.");

    proxyDestroy(zeta, efd);

    free(events);
    close(efd);

    return 0;
}
