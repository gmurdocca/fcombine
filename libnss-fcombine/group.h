#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <nss.h>
#include <sys/types.h>

enum nss_status _nss_fcombine_setgrent(void);
enum nss_status _nss_fcombine_endgrent(void);
enum nss_status _nss_fcombine_getgrent_r(struct group *grbuf, char *buf,
        size_t buflen, int *errnop);
enum nss_status _nss_fcombine_getgrnam_r(const char* name, struct group *grp,
        char *buf, size_t buflen, int *errnop);
enum nss_status _nss_fcombine_getgrgid_r(gid_t gid, struct group *grp,
        char *buf, size_t buflen, int *errnop);
