# Makefile to build libnss_fcombine
CC=gcc
CFLAGS=-D_REENTRANT -g -Wall -fPIC -Dlinux -DLINUX_PAM -D_POSIX_SOURCE \
	   -Wall -Wwrite-strings  -Wpointer-arith -Wcast-qual -Wcast-align \
	   -Wstrict-prototypes -Wmissing-prototypes -Wnested-externs -Winline \
	   -Wshadow -pedantic -fno-stack-protector -I/usr/include/libxml2 \
	   -DPAM_DYNAMIC -O2
LDFLAGS=-lxmlrpc_client


libnss_fcombine.so.2: passwd.o shadow.o group.o common.o
	$(CC) $(CFLAGS) -shared -dynamiclib -o libnss_fcombine.so.2 $(LDFLAGS) \
		-lfcombine_xmlrpc passwd.o shadow.o group.o common.o

passwd.o: passwd.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c passwd.c -o $@
	
shadow.o: shadow.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c shadow.c -o $@

group.o: group.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c group.c -o $@

common.o: common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c common.c -o $@

install:
	cp libnss_fcombine.so.2 /lib64/libnss_fcombine.so.2

clean:
	rm -f *.o *.so.2

all: clean libnss_fcombine.so.2 install
