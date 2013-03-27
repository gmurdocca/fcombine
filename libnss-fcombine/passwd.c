#include "../libfcombine_xmlrpc/libfcombine_xmlrpc.h"
#include "passwd.h"
#include "common.h"
#include <errno.h>
#include <grp.h>
#include <syslog.h>
#include <pwd.h>
#include <nss.h>
#include <stdlib.h>

/* This function is called when our passwd NSS database is "opened".  It allows
 * us to set up some things before other calls are made if neccessary */
enum nss_status _nss_fcombine_setpwent(void) {
    int xmlrpc_result;

    syslog(LOG_INFO, "_nss_fcombine_setpwent\n");

    if (xmlrpc_start() != FCOMBINE_STARTUP_SUCCESS)
        return NSS_STATUS_UNAVAIL;

    xmlrpc_result = xmlrpc_setpwent();
    xmlrpc_end();

    /* rewind to the start */
    return nss_response(xmlrpc_result);
}

/* This function is called when our passwd NSS database is being "destroyed".
 * It allows us to clean up */
enum nss_status _nss_fcombine_endpwent(void) {

    int xmlrpc_return;

    syslog(LOG_INFO, "_nss_fcombine_endpwent");

    if (xmlrpc_start() != FCOMBINE_STARTUP_SUCCESS)
        return NSS_STATUS_UNAVAIL;

    /* closes the password database after all the entries are retrieved */
    xmlrpc_return = xmlrpc_endpwent();
    xmlrpc_end();

    return nss_response(xmlrpc_return);
}

/* This function gets the next passwd entry from our database (in the case
 * of enumeration) ***TODO: clarify this */
enum nss_status _nss_fcombine_getpwent_r(struct passwd *pwd, char *buf,
        size_t buflen, int *errnop) {

    int xmlrpc_return;

    syslog(LOG_INFO, "_nss_fcombine_getpwent_r");

    if (xmlrpc_start() != FCOMBINE_STARTUP_SUCCESS)
        return NSS_STATUS_UNAVAIL;

    xmlrpc_return = xmlrpc_getpwent(pwd, buf, buflen);
    xmlrpc_end();

    return nss_response(xmlrpc_return);

}

/* Get user entry (struct passwd) by a username
 * _name_ is the username
 * _pwbuf */
enum nss_status _nss_fcombine_getpwnam_r(const char* name, struct passwd *pwd,
        char *buf, size_t buflen, int *errnop) {

    int xmlrpc_return;

    syslog(LOG_INFO, "_nss_fcombine_getpwnam_r");

    if (xmlrpc_start() != FCOMBINE_STARTUP_SUCCESS)
        return NSS_STATUS_UNAVAIL;

    xmlrpc_return = xmlrpc_getpwnam(name, pwd, buf, buflen);
    xmlrpc_end();
    syslog(LOG_INFO, "past");

    return nss_response(xmlrpc_return);
}

enum nss_status _nss_fcombine_getpwuid_r(uid_t uid, struct passwd *pwd,
        char *buf, size_t buflen, int *errnop) {

    int xmlrpc_return;

    syslog(LOG_INFO, "_nss_fcombine_getpwuid_r");

    if (xmlrpc_start() != FCOMBINE_STARTUP_SUCCESS)
        return NSS_STATUS_UNAVAIL;

    xmlrpc_return = xmlrpc_getpwuid(uid, pwd, buf, buflen);
    xmlrpc_end();

    return nss_response(xmlrpc_return);

}
