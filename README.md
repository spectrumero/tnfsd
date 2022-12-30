# TNFS - The Trivial Network Filesystem

## Rationale

Protocols such as NFS (Unix) or SMB (Windows) are overly complex for 8 bit
systems. While NFS is well documented, it's a complex RPC based protocol.
SMB is much worse. It is also a complex RPC based protocol, but it's also
proprietary, poorly documented, and implementations differ so much that
to get something that works with a reasonable subset of SMB would add a
great deal of unwanted complexity. The Samba project has been going for 
*years* and they still haven't finished making it bug-for-bug compatible with
the various versions of Windows!

At the other end, there's FTP, but FTP is not great for a general file
system protocol for 8 bit systems - it requires two TCP sockets for
each connection, and some things are awkward in FTP, even if they work.

So instead, TNFS provides a straightforward protocol that can easily be
implemented on most 8 bit systems. It's designed to be a bit better than
FTP for the purpose of a filesystem, but not as complex as the "big" network
filesystem protocols like NFS or SMB. It is also designed to be usable
with 'incomplete' TCP/IP stacks (e.g. ones that only support UDP).

For a PC, TNFS can be implemented using something like FUSE (no, not the
Spectrum emulator, but the Filesystem In Userspace project). This is
at least available for most things Unixy (Linux, OS X, some of the BSDs),
and possibly by now for Windows also.

## Security

This is not intended to be a proper, secure network file system. If you're
storing confidential files on your Speccy, you're barmy :)  Encryption,
for example, is not supported. However, servers that may be exposed to the 
internet should be coded in such a way they won't open up the host system 
to exploits.

## Supported systems

So far, the following 8 bit systems have a TNFS client available:

* Sinclair ZX Spectrum (with the Spectranet)
* Atari 8-bit (with the FujiNet)
* Coleco Adam (with the FujiNet)
* Apple 8-bt (with the FujiNet) - in progress at the time of writing
* Commodore 64 (with the FujiNet) - in progress at the time of writing

## Supported server systems

The TNFS daemon has been built for the following systems. It has few
dependencies (which should all be supplied with a basic build environment).

* Linux
* Microsoft Windows
* BSD sytems (tested on OpenBSD)
* Mac OS X and successors

## Acknowledgements

The FujiNet team, for many improvements and enhancements to the basic
TNFS daemon. See https://fujinet.online

