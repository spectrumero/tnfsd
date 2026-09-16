#include "event.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <unistd.h>

#define _EVENT_MAX_FDS 4096

struct kevent event[_EVENT_MAX_FDS];
struct timespec timeout;
int kq;
event_wait_res_t wait_result;

void tnfs_event_init()
{
    wait_result.fds = calloc(_EVENT_MAX_FDS, sizeof(int));
    kq = kqueue();
}

bool tnfs_event_register(int fd)
{
    struct kevent change_event[4];
    EV_SET(change_event, fd, EVFILT_READ, EV_ADD, 0, 0, 0);
    if (kevent(kq, change_event, 1, NULL, 0, NULL) == -1)
    {  
        LOG("tnfs_event_register: can't register kevent\n");
        return false;
    }
    return true;
}

void tnfs_event_unregister(int fd)
{
    struct kevent change_event;
    EV_SET(&change_event, fd, EVFILT_READ, EV_DELETE, 0, 0, 0);
    kevent(kq, &change_event, 1, NULL, 0, NULL);
}

event_wait_res_t* tnfs_event_wait(int timeout_sec)
{
    timeout.tv_sec = timeout_sec;

    int readyfds = kevent(kq, NULL, 0, event, _EVENT_MAX_FDS, &timeout);

    /* Return before memset so errno still describes the failure. */
    if (readyfds == -1)
    {
        wait_result.size = -1;
        return &wait_result;
    }

    wait_result.size = readyfds;
    memset(wait_result.fds, 0, _EVENT_MAX_FDS * sizeof(int));

    for (int i = 0; i < readyfds; i++)
    {
        wait_result.fds[i] = event[i].ident;
    }

    return &wait_result;
}

void tnfs_event_close()
{
    close(kq);
    free(wait_result.fds);
}
