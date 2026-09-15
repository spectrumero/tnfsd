#ifndef _CONFIG_H
#define _CONFIG_H
/* The MIT License
 * Copyright (c) 2010 Dylan Smith
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * tnfs daemon compile time configuration */

#define TNFSD_PORT	16384	/* UDP port to listen on */
#define MAXMSGSZ	532	/* maximum size of a TNFS message */
#define MAX_FD_PER_CONN	16	/* maximum open file descriptors per client */
#define MAX_DHND_PER_CONN 8	/* max open directories per client */
#define MAX_SESSIONS        4096   /* maximum number of opened sessions */
#define MAX_SESSIONS_PER_IP 16     /* max sessions from one IP. Must stay well below
                                      MAX_SESSIONS or MOUNT never recycles. */
#define MAX_TCP_CONN        4096   /* maximum number of TCP connections */
#define SESSION_TIMEOUT 600 /* Sessions are thrown out after no contact for this many seconds. 0 = no timeout */
#define CONN_TIMEOUT    600 /* TCP connections are thrown out after no contact for this many seconds. 0 = no timeout */
#define DIR_HANDLE_TIMEOUT 300 /* How long the traversal dir handles are cached. */
#define TNFS_HEADERSZ	4	/* minimum header size */
#define TNFS_MAX_PAYLOAD (MAXMSGSZ - TNFS_HEADERSZ - 1) /* Maximum usuable payload in a UDP datagram (-1 for status byte) */
#define MAX_TNFSPATH	256	/* maximum path length */
#define MAX_FILEPATH	384	/* Maximum path + filename */
#define MAX_ROOT	128	/* maximum root dir length */
#define PROTOVERSION_LSB 0x03	/* Protocol version, LSB */
#define PROTOVERSION_MSB 0x01	/* Protocol version, MSB */
#define TIMEOUT_LSB	0xE8	/* Timeout LSB (1 sec) */
#define TIMEOUT_MSB	0x03	/* Timeout MSB (1 sec) */
#define MAX_FILENAME_LEN 256	/* longest filename supported */
#define MAX_IOSZ	512	/* maximum size of an IO operation */
#define STATS_INTERVAL 60   /* how often the server stats should be logged. 0 to disable stats logging. */
#define TCP_KA_IDLE 30 /* the time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes */
#define TCP_KA_INTVL 1  /* the time (in seconds) between individual keepalive probes */
#define TCP_KA_COUNT 60 /* the maximum number of keepalive probes TCP should send before dropping the connection */
#define TCP_SEND_TIMEOUT 30 /* max seconds a send() to a client may stall */
#define SESSION_SWEEP_INTERVAL 10 /* how often the main loop reaps timed-out sessions */
#define ACCEPT_WARN_INTERVAL 10 /* minimum seconds between accept() failure warnings */

#endif
