# Makefile to build libfcombine_xmlrpc
CC=gcc
CFLAGS=-D_REENTRANT -g -Wall -fPIC -Dlinux -DLINUX_PAM -D_POSIX_SOURCE \
	   -Wall -Wwrite-strings  -Wpointer-arith -Wcast-qual -Wcast-align \
	   -Wstrict-prototypes -Wmissing-prototypes -Wnested-externs -Winline \
	   -Wshadow -pedantic -fno-stack-protector -I/usr/include/libxml2 \
	   -std=c99 -DPAM_DYNAMIC -O2
LDFLAGS=-lxmlrpc_client


libfcombine_xmlrpc.so: libfcombine_xmlrpc.o
	$(CC) $(CFLAGS) -shared -dynamiclib -o libfcombine_xmlrpc.so $(LDFLAGS) \
		libfcombine_xmlrpc.o

libfcombine_xmlrpc.o: 
	$(CC) $(CFLAGS) $(LDFLAGS) -c libfcombine_xmlrpc.c -o $@
	

install:
	cp libfcombine_xmlrpc.so /usr/lib64/libfcombine_xmlrpc.so

clean:
	rm -f *.o *.so

all: clean libfcombine_xmlrpc.so install
