CC=gcc

# Auto-detect OS if not provided. Map uname output to expected values.
ifndef OS
    UNAME_S := $(shell uname -s 2>/dev/null)
    ifeq ($(UNAME_S),Darwin)
        OS := BSD
    else ifeq ($(UNAME_S),Linux)
        OS := LINUX
    else ifeq ($(UNAME_S),Windows_NT)
        OS := Windows_NT
    else
        $(error Unknown OS. Please run `make OS=LINUX|BSD|Windows_NT`)
    endif
endif

ifeq ($(OS),LINUX)
    FLAGS = -Wall -DUNIX -DNEED_BSDCOMPAT
    EXOBJS = strlcpy.o strlcat.o event_epoll.o 
    LIBS =
    EXEC = tnfsd
endif
ifeq ($(OS),Windows_NT)
    FLAGS = -Wall -DWIN32 -DNEED_BSDCOMPAT
    EXOBJS = strlcpy.o strlcat.o event_select.o 
    LIBS = -lwsock32
    EXEC = tnfsd.exe
endif
ifeq ($(OS),BSD)
    FLAGS = -Wall -DUNIX -DBSD
    EXOBJS = event_kqueue.o
    LIBS =
    EXEC = tnfsd
endif

# ENABLE_CHROOT defaults to yes on Unix systems for security
# Disable with: make ENABLE_CHROOT=no
ifeq ($(OS),LINUX)
    ENABLE_CHROOT ?= yes
endif
ifeq ($(OS),BSD)
    ENABLE_CHROOT ?= yes
endif

ifeq ($(ENABLE_CHROOT),yes)
    CHROOTFLAGS = -DENABLE_CHROOT
endif

ifdef DEBUG
    EXFLAGS = -g -DDEBUG
endif

ifdef USAGELOG
    LOGFLAGS = -DUSAGELOG
endif

CFLAGS=$(FLAGS) $(CHROOTFLAGS) $(EXFLAGS) $(LOGFLAGS) -DNEED_ERRTABLE
OBJS=main.o datagram.o event_common.o log.o session.o endian.o directory.o errortable.o tnfs_file.o chroot.o fileinfo.o stats.o auth.o traverse.o match.o tnfsd.o atari.o $(EXOBJS)

# Check if boot sector assembly source exists
ATARI_BOOT_ASM := $(wildcard atari-boot-xex-file.asm)
ifneq ($(ATARI_BOOT_ASM),)
    # Check if xa assembler is available
    XA := $(shell which xa 2>/dev/null)
    ifneq ($(XA),)
        CFLAGS += -DATARI_BOOTSECTOR_EXISTS
        ATARI_BOOT_EXISTS := yes
    else
        $(error xa assembler not found but $(ATARI_BOOT_ASM) exists. Install xa: brew install xa (macOS) or apt-get install xa65 (Linux))
    endif
endif

all:	$(OBJS)
	$(CC) -o ../bin/$(EXEC) $(OBJS) $(LIBS)

# Assemble boot sector from assembly source
atari_bootsector.bin: atari-boot-xex-file.asm
	@echo "Assembling Atari boot sector from assembly source..."
	xa -o atari_bootsector.bin atari-boot-xex-file.asm

# Auto-generate boot sector header from binary
atari_bootsector.h: atari_bootsector.bin
	@echo "Converting Atari boot sector binary to header..."
	xxd -i atari_bootsector.bin > atari_bootsector.h

# atari.o depends on the generated header (if boot sector source exists)
ifeq ($(ATARI_BOOT_EXISTS),yes)
atari.o: atari.c atari.h atari_bootsector.h
else
atari.o: atari.c atari.h
endif

clean:
	$(RM) -f $(OBJS) atari_bootsector.bin atari_bootsector.h bin/$(EXEC)
