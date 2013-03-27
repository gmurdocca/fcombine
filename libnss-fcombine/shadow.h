#include <nss.h>
#include <shadow.h>

enum nss_status _nss_fcombine_getspnam_r(const char* name, struct spwd *spbuf,
        char *buf, size_t buflen, int *errnop);
