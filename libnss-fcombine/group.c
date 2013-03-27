#include "../libfcombine_xmlrpc/libfcombine_xmlrpc.h"
#include "group.h"
#include "common.h"
#include <errno.h>
#include <grp.h>
#include <syslog.h>
#include <nss.h>
#include <stdlib.h>



/* This function is called when our passwd NSS database is "opened".  It allows
 * us to set up some things before other calls are made if neccessary */
enum nss_status _nss_fcombine_setgrent(void) {

    syslog(LOG_INFO, "_nss_fcombine_setgrent\n");

    if (xmlrpc_start() != FCOMBINE_STARTUP_SUCCESS)
        return NSS_STATUS_UNAVAIL;

    /* rewind to the start */
    return nss_response(xmlrpc_setgrent());
}

/* This function is called when our passwd NSS database is being "destroyed".
 * It allows us to clean up */
enum nss_status _nss_fcombine_endgrent(void) {

    int xmlrpc_return;

    syslog(LOG_INFO, "_nss_fcombine_endgrent");

    if (xmlrpc_start() != FCOMBINE_STARTUP_SUCCESS)
        return NSS_STATUS_UNAVAIL;

    /* closes the password database after all the entries are retrieved */
    xmlrpc_return = xmlrpc_endgrent();
    xmlrpc_end();

    return nss_response(xmlrpc_return);
}

/* This function gets the next passwd entry from our database (in the case
 * of enumeration) ***TODO: clarify this */
enum nss_status _nss_fcombine_getgrent_r(struct group *grp, char *buf,
        size_t buflen, int *errnop) {

    int xmlrpc_return;

    if (xmlrpc_start() != FCOMBINE_STARTUP_SUCCESS)
        return NSS_STATUS_UNAVAIL;

    syslog(LOG_INFO, "_nss_fcombine_getgrent_r");
    xmlrpc_return = xmlrpc_getgrent(grp, buf, buflen);
    xmlrpc_end();

    return nss_response(xmlrpc_return);
}

/* Get group entry (struct group) by a groupname
 * _name_ is the groupname
 * _pwbuf */
enum nss_status _nss_fcombine_getgrnam_r(const char* name, struct group *grp,
        char *buf, size_t buflen, int *errnop) {

    int xmlrpc_return;

    syslog(LOG_INFO, "_nss_fcombine_getgrnam_r");

    if (xmlrpc_start() != FCOMBINE_STARTUP_SUCCESS)
        return NSS_STATUS_UNAVAIL;

    xmlrpc_return = xmlrpc_getgrnam(name, grp, buf, buflen);
    xmlrpc_end();

    return nss_response(xmlrpc_return);

}

enum nss_status _nss_fcombine_getgrgid_r(gid_t gid, struct group *grp,
        char *buf, size_t buflen, int *errnop) {

    int xmlrpc_return;

    syslog(LOG_INFO, "_nss_fcombine_getgrgid_r");

    if (xmlrpc_start() != FCOMBINE_STARTUP_SUCCESS)
        return NSS_STATUS_UNAVAIL;

    xmlrpc_return = xmlrpc_getgrgid(gid, grp, buf, buflen);
    xmlrpc_end();

    return nss_response(xmlrpc_return);
}
