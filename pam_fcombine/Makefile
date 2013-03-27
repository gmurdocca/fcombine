# Makefile to build pam_fcombine
CC=gcc
CFLAGS=-D_REENTRANT -g -Wall -fPIC -Dlinux -DLINUX_PAM -D_POSIX_SOURCE \
	   -Wall -Wwrite-strings  -Wpointer-arith -Wcast-qual -Wcast-align \
	   -Wstrict-prototypes -Wmissing-prototypes -Wnested-externs -Winline \
	   -Wshadow -pedantic -fno-stack-protector -I/usr/include/libxml2 \
	   -DPAM_DYNAMIC -O2
LDFLAGS=-lxmlrpc_client


pam_fcombine.so: pam_fcombine.o
	$(CC) $(CFLAGS) -shared -dynamiclib -o pam_fcombine.so $(LDFLAGS) \
			-lfcombine_xmlrpc pam_fcombine.o

pam_fcombine.o: $(OBJECTS) pam_fcombine.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c pam_fcombine.c -o $@

#fcombine_xmlrpc.o: fcombine_xmlrpc.c
#	$(CC) $(CFLAGS) $(LDFLAGS) -c fcombine_xmlrpc.c -o $@
	

install:
	cp pam_fcombine.so /lib64/security/pam_fcombine.so

clean:
	rm -f *.o *.so

all: clean pam_fcombine.so install
