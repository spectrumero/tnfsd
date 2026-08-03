#include "event.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#define _EVENT_MAX_FDS 4096

struct epoll_event events[_EVENT_MAX_FDS];
int epfd;
event_wait_res_t wait_result;

void tnfs_event_init()
{
    wait_result.fds = calloc(_EVENT_MAX_FDS, sizeof(int));
    epfd = epoll_create(1);
}

bool tnfs_event_register(int fd)
{
    struct epoll_event ev;
    /*
     * Socket handlers consume one datagram, connection, or read per main-loop
     * iteration. Use level-triggered notifications so descriptors remain
     * ready while the kernel still has input queued for them.
     */
    ev.events = EPOLLIN | EPOLLRDHUP;
    ev.data.fd = fd;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1)
    {
        LOG("tnfs_event_register: can't register epoll descriptor\n");
        return false;
    }
    return true;
}

void tnfs_event_unregister(int fd)
{
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
}

event_wait_res_t* tnfs_event_wait(int timeout_sec)
{
    int readyfds = epoll_wait(epfd, events, _EVENT_MAX_FDS, timeout_sec * 1000);

    wait_result.size = readyfds;
    memset(wait_result.fds, 0, _EVENT_MAX_FDS * sizeof(int));

    if (readyfds == -1)
    {
        wait_result.size = -1;
        return &wait_result;
    }

    for (int i = 0; i < readyfds; i++)
    {
        wait_result.fds[i] = events[i].data.fd;
    }

    return &wait_result;

}

void tnfs_event_close()
{
    close(epfd);
    free(wait_result.fds);
}
