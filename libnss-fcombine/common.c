#include "../libfcombine_xmlrpc/libfcombine_xmlrpc.h"
#include <nss.h>

int nss_response(int xmlrpc_return) {

    switch (xmlrpc_return) {
        case FCOMBINE_DAEMON_SUCCESS:
            return NSS_STATUS_SUCCESS;
        case FCOMBINE_NOT_FOUND:
            return NSS_STATUS_NOTFOUND;
        case FCOMBINE_BUFFER_TOOSMALL:
            return NSS_STATUS_TRYAGAIN;
    }

    return NSS_STATUS_UNAVAIL;

}
