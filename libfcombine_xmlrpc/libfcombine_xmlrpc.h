/* Authentication returns */
#define FCOMBINE_AUTH_SUCCESS 0
#define FCOMBINE_AUTH_FAILED 1
#define FCOMBINE_DAEMON_ERR 2

/* NSS return types */
#define FCOMBINE_DAEMON_SUCCESS 3
#define FCOMBINE_BUFFER_TOOSMALL 4
#define FCOMBINE_NOT_FOUND 5

/* xmlrpc_start return values */
#define FCOMBINE_STARTUP_FAIL 6
#define FCOMBINE_STARTUP_SUCCESS 7


#define USER_AGENT "fcombine_xmlrpc"

#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <sys/types.h>

int xmlrpc_start(void);
void xmlrpc_end(void);

/* pam */
int xmlrpc_auth_user(const char *username, const char *password);

/* passwd */
int xmlrpc_getpwnam(const char *name, struct passwd *pwd, char *buf,
        size_t buflen);
int xmlrpc_getpwuid(uid_t uid, struct passwd *pwd, char *buf, size_t buflen);
int xmlrpc_setpwent(void);
int xmlrpc_endpwent(void);
int xmlrpc_getpwent(struct passwd *pwd, char *buf, size_t buflen);


/* group */
int xmlrpc_getgrnam(const char* name, struct group *grp, char *buf,
        size_t buflen);
int xmlrpc_getgrgid(gid_t gid, struct group *grp, char *buf, size_t buflen);
int xmlrpc_getgrent(struct group *grp, char *buf, size_t buflen);
int xmlrpc_setgrent(void);
int xmlrpc_endgrent(void);


/* shadow */
int xmlrpc_getspnam(const char* name, struct spwd *spbuf, char *buf,
        size_t buflen);
