#include "event.h"
#include "log.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#ifdef UNIX
#include <sys/select.h>
#define SOCKET_ERROR -1
#endif
/* definition of FD_COPY macro used in OpenBSD */
#ifndef FD_COPY
#define FD_COPY(f, t)   memcpy(t, f, sizeof(*(f)))
#endif

#define _EVENT_MAX_FDS 1024

int event_fd_list[_EVENT_MAX_FDS];
fd_set fdset;
fd_set errfdset;
struct timeval select_timeout;
event_wait_res_t wait_result;

void tnfs_event_init()
{
    memset(event_fd_list, 0, sizeof event_fd_list);
    wait_result.fds = calloc(_EVENT_MAX_FDS, sizeof(int));
}

bool tnfs_event_register(int fd)
{
    for (int i = 0; i < _EVENT_MAX_FDS; i++)
    {
        if (event_fd_list[i] == 0)
        {
            if (fd >= FD_SETSIZE)
            {
                LOG("tnfs_event_register: fd %d exceeds FD_SETSIZE\n", fd);
                return false;
            }
            event_fd_list[i] = fd;
            return true;
        }
    }
    LOG("tnfs_event_register: can't register new descriptor\n");
    return false;
}

void tnfs_event_unregister(int fd)
{
    for (int i = 0; i < _EVENT_MAX_FDS; i++)
    {
        if (event_fd_list[i] == fd)
        {
            event_fd_list[i] = 0;
        }
    }
}

event_wait_res_t* tnfs_event_wait(int timeout_sec)
{
    FD_ZERO(&fdset);
    for (int i = 0; i < _EVENT_MAX_FDS; i++)
    {
        if (event_fd_list[i] != 0)
        {
            FD_SET(event_fd_list[i], &fdset);
        }
    }
    FD_COPY(&fdset, &errfdset);

    select_timeout.tv_sec = timeout_sec;
    select_timeout.tv_usec = 0; /* select() writes back the remaining time */

    int readyfds = select(FD_SETSIZE, &fdset, NULL, &errfdset, &select_timeout);

    /* Return before memset so errno still describes the failure. */
    if (readyfds == SOCKET_ERROR)
    {
        wait_result.size = SOCKET_ERROR;
        return &wait_result;
    }

    wait_result.size = readyfds;
    memset(wait_result.fds, 0, _EVENT_MAX_FDS * sizeof(int));

    if (readyfds > 0)
    {
        int j = 0;
        for (int i = 0; i < _EVENT_MAX_FDS; i++)
        {
            if (event_fd_list[i] != 0 && FD_ISSET(event_fd_list[i], &fdset))
            {
                wait_result.fds[j++] = event_fd_list[i];
            }
        }
    }

    return &wait_result;
}

void tnfs_event_close()
{
    free(wait_result.fds);
}