#include <stdio.h>
#ifndef WIN32
#include <errno.h>
#include <string.h>
#include <sys/resource.h>
#endif

#include "atari.h"
#include "auth.h"
#include "datagram.h"
#include "directory.h"
#include "errortable.h"
#include "event.h"
#include "log.h"
#include "version.h"
#include "tnfsd.h"

void tnfsd_init()
{
	tnfs_init();              /* initialize structures etc. */
	tnfs_init_errtable();     /* initialize error lookup table */
}

void tnfsd_init_logs(int log_output_fd)
{
	FILE* log_output = fdopen(log_output_fd, "w");
	log_init(log_output);
}

#ifndef WIN32
/* config.h allows far more descriptors than a default 1024 soft limit does
 * (MAX_TCP_CONN, plus MAX_SESSIONS * MAX_FD_PER_CONN), so raise it. */
static void raise_fd_limit(void)
{
	struct rlimit rl;
	rlim_t want;

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
	{
		LOG("getrlimit(RLIMIT_NOFILE) failed: %s\n", strerror(errno));
		return;
	}

	/* Linux rejects an infinite soft limit here, so ask for something sane. */
	want = rl.rlim_max;
	if (want == RLIM_INFINITY || want > 65536)
		want = 65536;

	if (rl.rlim_cur < want)
	{
		rl.rlim_cur = want;
		if (setrlimit(RLIMIT_NOFILE, &rl) < 0)
			LOG("setrlimit(RLIMIT_NOFILE) failed: %s\n", strerror(errno));
		if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
			return;
	}

	LOG("Open file limit: %lu\n", (unsigned long)rl.rlim_cur);
}
#endif

int tnfsd_start(const char* path, int port, bool read_only, bool atari_mode)
{
	LOG("Starting tnfsd version %s on port %d using root directory \"%s\"\n", version, port, path);
	if (read_only)
	{
		LOG("The server runs in read-only mode. TNFS clients can only list and download files.\n");
	}
	else
	{
		LOG("The server runs in read-write mode. TNFS clients can upload and modify files. Use -r to enable read-only mode.\n");
	}
	if (atari_mode)
	{
		LOG("Atari mode enabled: Binary files ($FFFF) will be presented as ATR disk images.\n");
	}

	if (tnfs_setroot(path) < 0)
	{
		LOG("Invalid root directory: %s\n", path);
		return TNFSD_ERR_INVALID_DIR;
	}
#ifndef WIN32
	raise_fd_limit();
#endif
	tnfs_event_init();        /* initialize event system */
	if (tnfs_sockinit(port) < 0)  /* initialize communications */
	{
		LOG("Can't bind port %d\n", port);
		return TNFSD_ERR_SOCKET_ERROR;
	}
	auth_init(read_only);     /* initialize authentication */
	atari_init(atari_mode);   /* initialize Atari virtualization */
	tnfs_mainloop();          /* run */
	LOG("Stopping tnfsd server.\n");
	tnfs_event_close();
	return 0;
}

void tnfsd_stop(int sig)
{
	tnfs_stop_requested = 1;
	tnfs_sockclose();
}
