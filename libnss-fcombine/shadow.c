#include "shadow.h"
#include "common.h"
#include "../libfcombine_xmlrpc/libfcombine_xmlrpc.h"
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>

/*
 * Get shadow information using username.
 */

enum nss_status _nss_fcombine_getspnam_r(const char* name, struct spwd *spbuf,
        char *buf, size_t buflen, int *errnop) {

    int xmlrpc_return;

    syslog(LOG_INFO, "_nss_fcombine_getspnam_r: for user %s", name);

    if (xmlrpc_start() != FCOMBINE_STARTUP_SUCCESS)
        return NSS_STATUS_UNAVAIL;

    xmlrpc_return = xmlrpc_getspnam(name, spbuf, buf, buflen);
    xmlrpc_end();

    return nss_response(xmlrpc_return);

}
