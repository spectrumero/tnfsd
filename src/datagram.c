/* The MIT License

Copyright (c) 2010 Dylan Smith

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

TNFS daemon datagram handler

*/

#include <sys/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#ifdef UNIX
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#include "tnfs.h"
#include "datagram.h"
#include "log.h"
#include "endian.h"
#include "session.h"
#include "errortable.h"
#include "directory.h"
#include "tnfs_file.h"
#include "event.h"
#include "auth.h"

int sockfd;			/* UDP global socket file descriptor */
int tcplistenfd;	/* TCP listening socket file descriptor */

/* Set by tnfsd_stop(). The loop used to exit only because a signal made
 * tnfs_event_wait() fail, which is indistinguishable from a real error. */
volatile sig_atomic_t tnfs_stop_requested = 0;

/* File scope so tnfs_send() can flag a connection whose peer stopped reading. */
static TcpConnection tcpsocks[MAX_TCP_CONN];

#ifndef WIN32
/* Held only so an EMFILE is recoverable -- see tcp_accept(). */
static int accept_reserve_fd = -1;
#endif
bool write_support; /* Whether writes should be enabled. */

tnfs_cmdfunc dircmd[NUM_DIRCMDS] =
	{&tnfs_opendir, &tnfs_readdir, &tnfs_closedir,
	 &tnfs_mkdir, &tnfs_rmdir, &tnfs_telldir, &tnfs_seekdir,
	 &tnfs_opendirx, &tnfs_readdirx};

tnfs_cmdfunc filecmd[NUM_FILECMDS] =
	{&tnfs_open_deprecated, &tnfs_read, &tnfs_write, &tnfs_close,
	 &tnfs_stat, &tnfs_lseek, &tnfs_unlink, &tnfs_chmod, &tnfs_rename,
	 &tnfs_open};

tnfs_cmdfunc devcmd[NUM_DEVCMDS] =
	{&tnfs_size, &tnfs_free, &tnfs_size, &tnfs_free};

const char *sesscmd_names[NUM_SESSCMDS] =
	{
		"TNFS_MOUNT",
		"TNFS_UMOUNT"};

const char *dircmd_names[NUM_DIRCMDS] =
	{
		"TNFS_OPENDIR",
		"TNFS_READDIR",
		"TNFS_CLOSEDIR",
		"TNFS_MKDIR",
		"TNFS_RMDIR",
		"TNFS_TELLDIR",
		"TNFS_SEEKDIR",
		"TNFS_OPENDIRX",
		"TNFS_READDIRX"};

const char *filecmd_names[NUM_FILECMDS] =
	{
		"TNFS_OPENFILE_OLD",
		"TNFS_READ",
		"TNFS_WRITE",
		"TNFS_CLOSE",
		"TNFS_STAT",
		"TNFS_SEEK",
		"TNFS_UNLINK",
		"TNFS_CHMOD",
		"TNFS_RENAME",
		"TNFS_OPEN"};

const char *devcmd_names[NUM_DEVCMDS] =
	{
		"TNFS_SIZEDEVICE",
		"TNFS_FREEDEVICE",
		"TNFS_SIZEBYTESDEVICE",
		"TNFS_FREEBYTESDEVICE"};

const char *get_cmd_name(uint8_t cmd)
{
	uint8_t class = cmd & 0xF0;
	uint8_t index = cmd & 0x0F;

	if (class == CLASS_FILE)
	{
		if (index < NUM_FILECMDS)
			return filecmd_names[index];
	}
	else if (class == CLASS_DIRECTORY)
	{
		if (index < NUM_DIRCMDS)
			return dircmd_names[index];
	}
	else if (class == CLASS_SESSION)
	{
		if (index < NUM_SESSCMDS)
			return sesscmd_names[index];
	}
	else if (class == CLASS_DEVICE)
	{
		if (index < NUM_DEVCMDS)
			return devcmd_names[index];
	}

	return "UNKNOWN_CMD";
}

int tnfs_sockinit(int port)
{
	struct sockaddr_in servaddr;

#ifdef WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)
	{
		LOG("WSAStartup() failed");
		return -1;
	}
#endif

	/* Create the UDP socket */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		LOG("Unable to open socket");
		return -1;
	}

	/* set up the network */
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htons(INADDR_ANY);
	servaddr.sin_port = htons(port);

	if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
	{
		LOG("Unable to bind");
		close(sockfd);
		return -1;
	}

	/* Create the TCP socket */
	tcplistenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (tcplistenfd < 0)
	{
		LOG("Unable to create TCP socket");
		close(sockfd);
		return -1;
	}
	int reuseaddr = 1;
	if (setsockopt(tcplistenfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuseaddr, sizeof(reuseaddr)) < 0)
	{
		LOG("setsockopt(SO_REUSEADDR) failed");
		tnfs_sockclose();
		return -1;
	}

	/* Bug fix (2026-05-19): The TCP keep-alive socket options
	 * (SO_KEEPALIVE, TCP_KEEPIDLE/TCP_KEEPALIVE, TCP_KEEPINTVL,
	 * TCP_KEEPCNT) used to be applied to the listening socket here.
	 *
	 * That was non-portable behaviour:
	 *   - On Linux these options are inherited by accepted connections
	 *     and have no effect on the listen socket itself, so the code
	 *     "worked".
	 *   - On macOS / BSD enabling SO_KEEPALIVE on a listening socket
	 *     causes the kernel to start sending TCP keep-alive probes on
	 *     the listening socket itself.  A listen socket has no peer,
	 *     so the probes go unanswered and after roughly
	 *     TCP_KA_IDLE + TCP_KA_COUNT * TCP_KA_INTVL seconds the kernel
	 *     reaps the socket.  Subsequent client SYNs are then rejected
	 *     by the kernel with RST,ACK because nothing is listening on
	 *     that port anymore (FujiNet would log
	 *     errno 104 "Connection reset by peer" and fall back to UDP).
	 *
	 * The intent was always to set keep-alive defaults for accepted
	 * client connections, so the options are now applied per-connection
	 * in tcp_accept() via apply_keepalive_options() instead.  See that
	 * function for the actual setsockopt() calls.
	 */

#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htons(INADDR_ANY);
	servaddr.sin_port = htons(port);
	if (bind(tcplistenfd, (struct sockaddr *)&servaddr,
			 sizeof(servaddr)) < 0)
	{
		LOG("Unable to bind TCP socket");
		tnfs_sockclose();
		return -1;
	}
	listen(tcplistenfd, 5);

#ifndef WIN32
	accept_reserve_fd = open("/dev/null", O_RDONLY);
#endif
	return 0;
}

void tnfs_sockclose()
{
#ifdef WIN32
	closesocket(tcplistenfd);
	closesocket(sockfd);
#else
	close(tcplistenfd);
	close(sockfd);
#endif
}

void tnfs_mainloop()
{
	int i;
	time_t last_stats_report = 0;
	time_t last_session_sweep = 0;
	time_t now = 0;

	memset(&tcpsocks, 0, sizeof(tcpsocks));

	/* add UDP socket and TCP listen socket to event listener */
	tnfs_event_register(sockfd);
	tnfs_event_register(tcplistenfd);

	while (!tnfs_stop_requested)
	{
		time(&now);

		tnfs_close_stale_connections(tcpsocks);

		/* Must run on a timer: expiry was reachable only via tnfs_mount(), so
		 * an idle server never released a dead client's fds. */
		if (now - last_session_sweep >= SESSION_SWEEP_INTERVAL)
		{
			tnfs_expire_sessions();
			last_session_sweep = now;
		}

		event_wait_res_t *wait_res = tnfs_event_wait(1);
		if (wait_res->size == SOCKET_ERROR)
		{
#ifndef WIN32
			/* A delivered signal is not a failure; this used to exit(0). */
			if (errno == EINTR)
				continue;
#endif
			LOG("event wait failed: %s\n", strerror(errno));
			break;
		}

		if (wait_res->size == 0)
		{
			// Just a normal timeout, reloop
			continue;
		}

		/* UDP message? */
		if (tnfs_event_is_active(wait_res, sockfd))
		{
			tnfs_handle_udpmsg();
		}

		/* Incoming TCP connection? */
		if (tnfs_event_is_active(wait_res, tcplistenfd))
		{
			tcp_accept(tcpsocks);
		}

		// was the fdset relevant to any of the existing connections?
		for (i = 0; i < MAX_TCP_CONN; i++)
		{
			if (tcpsocks[i].cli_fd)
			{
				if (tnfs_event_is_active(wait_res, tcpsocks[i].cli_fd))
				{
					tnfs_handle_tcpmsg(&tcpsocks[i]);
				}
			}
		}

		time(&now);
		if (STATS_INTERVAL > 0 && now - last_stats_report > STATS_INTERVAL)
		{
			stats_report(tcpsocks);
			last_stats_report = now;
		}
	}
	tnfs_close_all_connections(tcpsocks);
	tnfs_free_all_sessions();
}

#ifndef WIN32
/* Apply TCP keep-alive options to a freshly accepted client connection.
 *
 * These used to be applied to the listening socket in tnfs_sockinit(),
 * which broke the listener on macOS/BSD (see comment there).  Each
 * setsockopt failure here is logged but is not fatal -- a single client
 * connection that cannot enable keep-alive is still usable, and the
 * listener stays up to serve other clients.
 */
static void apply_keepalive_options(int fd)
{
	int ka_enable = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &ka_enable, sizeof(ka_enable)) < 0)
	{
		LOG("setsockopt(SO_KEEPALIVE) failed on accepted socket: %s\n", strerror(errno));
	}

	int ka_idle = TCP_KA_IDLE;
#if defined(TCP_KEEPIDLE)
	if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &ka_idle, sizeof(ka_idle)) < 0)
	{
		LOG("setsockopt(TCP_KEEPIDLE) failed on accepted socket: %s\n", strerror(errno));
	}
#elif defined(TCP_KEEPALIVE)
	/* macOS/BSD use TCP_KEEPALIVE to set the idle time (seconds) */
	if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &ka_idle, sizeof(ka_idle)) < 0)
	{
		LOG("setsockopt(TCP_KEEPALIVE) failed on accepted socket: %s\n", strerror(errno));
	}
#else
	/* no platform support for setting idle timeout; continue */
#endif

	int ka_interval = TCP_KA_INTVL;
#ifdef TCP_KEEPINTVL
	if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &ka_interval, sizeof(ka_interval)) < 0)
	{
		LOG("setsockopt(TCP_KEEPINTVL) failed on accepted socket: %s\n", strerror(errno));
	}
#endif

	int ka_count = TCP_KA_COUNT;
#ifdef TCP_KEEPCNT
	if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &ka_count, sizeof(ka_count)) < 0)
	{
		LOG("setsockopt(TCP_KEEPCNT) failed on accepted socket: %s\n", strerror(errno));
	}
#endif

	/* Keep-alive only covers idle connections. A peer that stalls with a full
	 * receive window is handled by the persist timer, which probes forever --
	 * so a blocking send() would hang the whole single-threaded server. Bound
	 * it at both the kernel and the syscall. */
#ifdef TCP_USER_TIMEOUT
	int user_timeout = (TCP_KA_IDLE + TCP_KA_INTVL * TCP_KA_COUNT) * 1000;
	if (setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout, sizeof(user_timeout)) < 0)
	{
		LOG("setsockopt(TCP_USER_TIMEOUT) failed on accepted socket: %s\n", strerror(errno));
	}
#endif

	struct timeval sndtimeo;
	sndtimeo.tv_sec = TCP_SEND_TIMEOUT;
	sndtimeo.tv_usec = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &sndtimeo, sizeof(sndtimeo)) < 0)
	{
		LOG("setsockopt(SO_SNDTIMEO) failed on accepted socket: %s\n", strerror(errno));
	}
}
#endif /* !WIN32 */

#ifndef WIN32
/* epoll is level-triggered, so a connection left on the accept queue keeps
 * tcplistenfd readable and the loop spins at 100% CPU, one log line per pass --
 * enough to block on a slow log sink and take UDP down too. Free the reserve fd,
 * use the slot to accept and drop the pending connection, then take it back. */
static void tcp_accept_drain_reserve(void)
{
	int fd;

	if (accept_reserve_fd < 0)
		return;

	close(accept_reserve_fd);
	accept_reserve_fd = -1;

	fd = accept(tcplistenfd, NULL, NULL);
	if (fd >= 0)
		close(fd);

	accept_reserve_fd = open("/dev/null", O_RDONLY);
}
#endif

/* Winsock reports through WSAGetLastError(), so errno is never set and
 * strerror() would describe an error nothing raised. */
static const char *tcp_accept_strerror(int err)
{
#ifdef WIN32
	static char buf[32];

	snprintf(buf, sizeof(buf), "WSA error %d", err);
	return buf;
#else
	return strerror(err);
#endif
}

/* Under fd exhaustion this fires on every pass of the loop, so rate-limit it. */
static void tcp_accept_warn(int err)
{
	static time_t last_warn = 0;
	static unsigned long suppressed = 0;
	time_t now = time(NULL);

	if (now - last_warn < ACCEPT_WARN_INTERVAL)
	{
		suppressed++;
		return;
	}

	if (suppressed > 0)
		LOG("unable to accept TCP connection: %s (%lu more suppressed)\n",
			tcp_accept_strerror(err), suppressed);
	else
		LOG("unable to accept TCP connection: %s\n", tcp_accept_strerror(err));

	last_warn = now;
	suppressed = 0;
}

/* Mark a connection dead so tnfs_close_stale_connections() reaps it next pass.
 * Closing it here would leave a dangling fd in the caller's scan. */
static void tnfs_mark_tcp_dead(int cli_fd)
{
	int i;

	if (cli_fd == 0)
		return;

	for (i = 0; i < MAX_TCP_CONN; i++)
	{
		if (tcpsocks[i].cli_fd == cli_fd)
		{
			tcpsocks[i].last_contact = 0;
			return;
		}
	}
}

void tcp_accept(TcpConnection *tcp_conn_list)
{
	int acc_fd, i;
	struct sockaddr_in cliaddr;

#ifdef WIN32
	int cli_len = sizeof(cliaddr);
#else
	socklen_t cli_len = sizeof(cliaddr);
#endif

	TcpConnection *tcp_conn;

	acc_fd = accept(tcplistenfd, (struct sockaddr *)&cliaddr, &cli_len);

	/* accept() yields INVALID_SOCKET on Windows, which truncates to -1 here.
	 * Don't compare against INVALID_SOCKET directly: it is unsigned and wider
	 * than int on 64-bit, so the comparison would never be true. */
	if (acc_fd < 0)
	{
#ifdef WIN32
		int accept_error = WSAGetLastError();

		tcp_accept_warn(accept_error);

		/* No reserve-descriptor trick here, so simply stop spinning on a
		 * listener that stays readable while the process is out of handles. */
		if (accept_error == WSAEMFILE || accept_error == WSAENOBUFS)
			Sleep(TCP_ACCEPT_RESOURCE_BACKOFF_MS);
#else
		switch (errno)
		{
		case EINTR:
		case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
		case EWOULDBLOCK:
#endif
		case ECONNABORTED:
			/* transient; client went away mid-handshake */
			return;
		case EMFILE:
		case ENFILE:
		case ENOBUFS:
		case ENOMEM:
			tcp_accept_warn(errno);
			tcp_accept_drain_reserve();
			return;
		default:
			break;
		}

		tcp_accept_warn(errno);
#endif
		return;
	}

	LOG("tcp_accept - accepted connection on fd %d\n", acc_fd);

#ifndef WIN32
	/* Apply per-connection keep-alive options.  See comment in
	 * tnfs_sockinit() for why this is done here and not on the
	 * listening socket. */
	apply_keepalive_options(acc_fd);
#endif

	bool event_registered = false;
	if (tnfs_event_register(acc_fd))
	{
		event_registered = true;
		tcp_conn = tcp_conn_list;
		for (i = 0; i < MAX_TCP_CONN; i++)
		{
			if (tcp_conn->cli_fd == 0)
			{
				MSGLOG(cliaddr.sin_addr.s_addr, "New TCP connection at index %d.", i);
				tcp_conn->cli_fd = acc_fd;
				tcp_conn->cliaddr = cliaddr;
				tcp_conn->last_contact = time(NULL);
				return;
			}
			tcp_conn++;
		}
	}
	if (event_registered)
	{
		tnfs_event_unregister(acc_fd);
	}

	MSGLOG(cliaddr.sin_addr.s_addr, "Can't accept client; too many connections.");

	/* tell the client 'too many connections' */
	unsigned char txbuf[9];
	uint16tnfs(txbuf, 0); // connID
	*(txbuf + 2) = 0;	  // retry
	*(txbuf + 3) = 0;	  // command
	*(txbuf + 4) = 0xFF;  // error
	*(txbuf + 5) = PROTOVERSION_LSB;
	*(txbuf + 6) = PROTOVERSION_MSB;

	send(acc_fd, (const char *)txbuf, sizeof(txbuf), 0);
	close(acc_fd);
}

void tnfs_handle_udpmsg()
{
#ifdef WIN32
	int len;
#else
	socklen_t len;
#endif
	int rxbytes;
	struct sockaddr_in cliaddr;
	unsigned char rxbuf[MAXMSGSZ];

	len = sizeof(cliaddr);
	rxbytes = recvfrom(sockfd, (char *)rxbuf, sizeof(rxbuf), 0,
					   (struct sockaddr *)&cliaddr, &len);

#ifdef WIN32
	if (rxbytes == SOCKET_ERROR)
	{
		LOG("recvfrom() failed: %d\n", WSAGetLastError());
		return;
	}
#else
	if (rxbytes < 0)
	{
		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
		{
			LOG("recvfrom() failed: %s\n", strerror(errno));
		}
		return;
	}
#endif

	if (rxbytes >= TNFS_HEADERSZ)
	{
		/* probably a valid TNFS packet, decode it */
		tnfs_decode(&cliaddr, 0, rxbytes, rxbuf);
	}
	else
	{
		MSGLOG(cliaddr.sin_addr.s_addr,
			   "Invalid datagram received");
	}
}

void tnfs_handle_tcpmsg(TcpConnection *tcp_conn)
{
	unsigned char buf[MAXMSGSZ];
	int sz;

	tcp_conn->last_contact = time(NULL);

	sz = recv(tcp_conn->cli_fd, (char *)buf, sizeof(buf), 0);

#ifdef WIN32
	if (sz == SOCKET_ERROR)
	{
		LOG("WSAGetLastError() = %d\n", WSAGetLastError());
	}
#else
	if (sz == -1)
	{
		LOG("Error: %s\n", strerror(errno));
	}
#endif

	if (sz <= 0)
	{
		MSGLOG(tcp_conn->cliaddr.sin_addr.s_addr, "Client disconnected, closing socket.");
		tnfs_close_tcp(tcp_conn);
		return;
	}
	tnfs_decode(&tcp_conn->cliaddr, tcp_conn->cli_fd, sz, buf);
}

void tnfs_close_tcp(TcpConnection *tcp_conn)
{
	tnfs_reset_cli_fd_in_sessions(tcp_conn->cli_fd);

#ifdef WIN32
	closesocket(tcp_conn->cli_fd);
#else
	close(tcp_conn->cli_fd);
#endif
	tnfs_event_unregister(tcp_conn->cli_fd);
	tcp_conn->cli_fd = 0;
}

void tnfs_decode(struct sockaddr_in *cliaddr, int cli_fd, int rxbytes, unsigned char *rxbuf)
{
	Header hdr;
	Session *sess;
	int sindex;
	int datasz = rxbytes - TNFS_HEADERSZ;
	int cmdclass, cmdidx;
	unsigned char *databuf = rxbuf + TNFS_HEADERSZ;

	memset(&hdr, 0, sizeof(hdr));

	/* note: don't forget about byte alignment issues on some
	 * architectures... */
	hdr.sid = tnfs16uint(rxbuf);
	hdr.seqno = *(rxbuf + 2);
	hdr.cmd = *(rxbuf + 3);
	hdr.ipaddr = cliaddr->sin_addr.s_addr;
	hdr.port = ntohs(cliaddr->sin_port);
	hdr.cli_fd = cli_fd;

#ifdef DEBUG
	TNFSMSGLOG(&hdr, "REQUEST cmd=0x%02x %s", hdr.cmd, get_cmd_name(hdr.cmd));
#endif

	if (!is_cmd_allowed(hdr.cmd))
	{
		tnfs_notpermitted(&hdr);
		return;
	}

	/* The MOUNT command is the only one that doesn't need an
	 * established session (since MOUNT is actually what will
	 * establish the session) */
	if (hdr.cmd != TNFS_MOUNT)
	{
		sess = tnfs_findsession_sid(hdr.sid, &sindex);
		if (sess == NULL)
		{
			tnfs_invalidsession(&hdr);
			return;
		}
		if (sess->ipaddr != hdr.ipaddr)
		{
			TNFSMSGLOG(&hdr, "Session and IP do not match");
			return;
		}
		if (sess->cli_fd != 0 && sess->cli_fd != cli_fd)
		{
			/* The same client (the IP was verified above) is reaching us on a
			 * new connection while the session is still bound to a previous one.
			 * This happens when the old connection went away without us seeing a
			 * close -- e.g. a NAT/firewall dropped the idle path, so the client's
			 * FIN never arrived and the old socket lingers as a zombie until
			 * keepalive/CONN_TIMEOUT reaps it. Migrate the session to the new
			 * connection instead of rejecting every request until then. */
			TNFSMSGLOG(&hdr, "Migrating session from fd %d to new TCP connection fd %d",
					   sess->cli_fd, cli_fd);
		}
		/* Update session timestamp */
		sess->last_contact = time(NULL);
		sess->cli_fd = cli_fd;
	}
	else
	{
		tnfs_mount(&hdr, databuf, datasz);
		return;
	}

	/* client is asking for a resend */
	if (hdr.seqno == sess->lastseqno)
	{
		tnfs_resend(sess, cliaddr, cli_fd);
		return;
	}

	/* find the command class and pass it off to the right
	 * function */
	cmdclass = hdr.cmd & 0xF0;
	cmdidx = hdr.cmd & 0x0F;
	switch (cmdclass)
	{
	case CLASS_SESSION:
		switch (cmdidx)
		{
		case TNFS_UMOUNT:
			tnfs_umount(&hdr, sess, sindex);
			break;
		default:
			tnfs_badcommand(&hdr, sess);
		}
		break;
	case CLASS_DIRECTORY:
		if (cmdidx < NUM_DIRCMDS)
			(*dircmd[cmdidx])(&hdr, sess, databuf, datasz);
		else
			tnfs_badcommand(&hdr, sess);
		break;
	case CLASS_FILE:
		if (cmdidx < NUM_FILECMDS)
			(*filecmd[cmdidx])(&hdr, sess, databuf, datasz);
		else
			tnfs_badcommand(&hdr, sess);
		break;
	case CLASS_DEVICE:
		if (cmdidx < NUM_DEVCMDS)
			(*devcmd[cmdidx])(&hdr, sess, databuf, datasz);
		else
			tnfs_badcommand(&hdr, sess);
		break;
	default:
		tnfs_badcommand(&hdr, sess);
	}
}

void tnfs_invalidsession(Header *hdr)
{
	TNFSMSGLOG(hdr, "Invalid session ID");
	hdr->status = TNFS_EBADSESSION;
	tnfs_send(NULL, hdr, NULL, 0);
}

void tnfs_badcommand(Header *hdr, Session *sess)
{
	TNFSMSGLOG(hdr, "Bad command");
	hdr->status = TNFS_ENOSYS;
	tnfs_send(sess, hdr, NULL, 0);
}

void tnfs_notpermitted(Header *hdr)
{
	TNFSMSGLOG(hdr, "Command %s is not permitted", get_cmd_name(hdr->cmd));
	hdr->status = TNFS_EPERM;
	tnfs_send(NULL, hdr, NULL, 0);
}

void tnfs_send(Session *sess, Header *hdr, unsigned char *msg, int msgsz)
{
	struct sockaddr_in cliaddr;
	ssize_t txbytes;
	unsigned char txbuf_nosess[5];
	unsigned char *txbuf = sess ? sess->lastmsg : txbuf_nosess;

	// TNFS_HEADERSZ + statuscode + msg
	if (TNFS_HEADERSZ + 1 + msgsz > MAXMSGSZ)
	{
		LOG("tnfs_send: Message too big");
		return;
	}

	cliaddr.sin_family = AF_INET;
	cliaddr.sin_addr.s_addr = hdr->ipaddr;
	cliaddr.sin_port = htons(hdr->port);

	uint16tnfs(txbuf, sess ? hdr->sid : 0);
	*(txbuf + 2) = hdr->seqno;
	*(txbuf + 3) = hdr->cmd;
	*(txbuf + 4) = hdr->status;
	if (msg)
		memcpy(txbuf + 5, msg, msgsz);

	if (sess)
	{
		sess->lastmsgsz = TNFS_HEADERSZ + 1 + msgsz; /* header + status code + payload */
		sess->lastseqno = hdr->seqno;
	}

	if (hdr->cli_fd == 0)
	{
		txbytes = sendto(sockfd, WIN32_CHAR_P txbuf, msgsz + TNFS_HEADERSZ + 1, 0,
						 (struct sockaddr *)&cliaddr, sizeof(cliaddr));
	}
	else
	{
		txbytes = send(hdr->cli_fd, WIN32_CHAR_P txbuf, msgsz + TNFS_HEADERSZ + 1, 0);
	}

	if (txbytes < 0)
	{
		TNFSMSGLOG(hdr, "Send failed: %s", strerror(errno));
		tnfs_mark_tcp_dead(hdr->cli_fd);
	}
	else if (txbytes < TNFS_HEADERSZ + 1 + msgsz)
	{
		/* A short write desynchronises the TCP stream; drop the connection. */
		TNFSMSGLOG(hdr, "Message was truncated");
		tnfs_mark_tcp_dead(hdr->cli_fd);
	}
}

void tnfs_resend(Session *sess, struct sockaddr_in *cliaddr, int cli_fd)
{
	int txbytes;
	if (cli_fd == 0)
	{
		txbytes = sendto(sockfd, WIN32_CHAR_P sess->lastmsg, sess->lastmsgsz, 0,
						 (struct sockaddr *)cliaddr, sizeof(struct sockaddr_in));
	}
	else
	{
		txbytes = send(cli_fd, WIN32_CHAR_P sess->lastmsg, sess->lastmsgsz, 0);
	}
	if (txbytes < sess->lastmsgsz)
	{
		MSGLOG(cliaddr->sin_addr.s_addr,
			   "Retransmit was truncated");
		tnfs_mark_tcp_dead(cli_fd);
	}
}

void tnfs_close_stale_connections(TcpConnection *tcp_conn_list)
{
	time_t now = time(NULL);
	TcpConnection *tcp_conn = tcp_conn_list;
	for (int i = 0; i < MAX_TCP_CONN; i++)
	{
		if (tcp_conn->cli_fd != 0)
		{
			if ((now - tcp_conn->last_contact) > CONN_TIMEOUT)
			{
				MSGLOG(tcp_conn->cliaddr.sin_addr.s_addr, "Socket is no longer active; disconnecting.");
				tnfs_close_tcp(tcp_conn);
			}
		}
		tcp_conn++;
	}
}

void tnfs_close_all_connections(TcpConnection *tcp_conn_list)
{
	TcpConnection *tcp_conn = tcp_conn_list;
	for (int i = 0; i < MAX_TCP_CONN; i++)
	{
		if (tcp_conn->cli_fd != 0)
		{
			tnfs_close_tcp(tcp_conn);
		}
		tcp_conn++;
	}
}
