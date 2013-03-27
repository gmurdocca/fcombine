#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <nss.h>
#include <sys/types.h>

enum nss_status _nss_fcombine_setpwent(void);
enum nss_status _nss_fcombine_endpwent(void);
enum nss_status _nss_fcombine_getpwent_r(struct passwd *pwbuf, char *buf,
        size_t buflen, int *errnop);
enum nss_status _nss_fcombine_getpwnam_r(const char* name, struct passwd *pwd,
        char *buf, size_t buflen, int *errnop);
enum nss_status _nss_fcombine_getpwuid_r(uid_t uid, struct passwd *pwd,
        char *buf, size_t buflen, int *errnop);
