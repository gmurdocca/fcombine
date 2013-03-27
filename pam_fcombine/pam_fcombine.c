#define _GNU_SOURCE
#include "../libfcombine_xmlrpc/libfcombine_xmlrpc.h"
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <sys/resource.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h> 

/* when we define _GNU_SOURCE, we get this useful char buffer
 * containing the name of the invoking process, nomatter where we're
 * called from (for example pam_start() in vsftpd */
extern char *program_invocation_short_name;

/* glibc allows us to run a "constructor" when dlopen is called.
 * We use this to our advantage in order to expand VSFTPD's memory
 * before all the other pam modules are loaded */
void __attribute__ ((constructor)) my_init(void);
static void fix_rlimit(void);

void __attribute__ ((constructor)) my_init(void) {
    fix_rlimit();
}

static int __internal_pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
        const char *argv[]);

static void fix_rlimit(void) {
    const char *vsftpd_binary_name = "vsftpd";
    struct rlimit rlim;
    int l;

    getrlimit(RLIMIT_AS, &rlim);
    if (((l = strlen(program_invocation_short_name)) ==
            strlen(vsftpd_binary_name)) &&
            strncmp(program_invocation_short_name,
                    vsftpd_binary_name, l) == 0) {

        rlim.rlim_cur = RLIM_INFINITY;
        rlim.rlim_max = RLIM_INFINITY;
        setrlimit(RLIMIT_AS, &rlim);

        syslog(LOG_INFO, "Fixing VSFTPD rlimit on the fly");
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
        const char *argv[]) {

    int auth_result;

    /* note that closelog() is critical, as we're a shared library.
     * When openlog() is called, we replace the "ident" of the program
     * on the heap.  Once we disappear, the memory associated with the
     * string disappears.  Hence we need to closelog() */
    openlog("pam_fcombine", LOG_PID, LOG_LOCAL1); 
    syslog(LOG_INFO, "pam_fcombine started");

    auth_result = __internal_pam_sm_authenticate(pamh, flags, argc, argv);

    closelog();

    return auth_result;
}

static int __internal_pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
        const char *argv[]) {

    const char *user;
    const char *password;
    int pam_err;
    int result;

    /* get the user */
    if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
        syslog(LOG_INFO, "pam_get_user crapout");
        return (pam_err);
    }

    pam_err = pam_get_authtok(pamh, PAM_AUTHTOK, (const char **)&password,
            NULL);

    if (pam_err == PAM_CONV_ERR) {
        syslog(LOG_INFO, "pam_conv_err");
        return pam_err;
    }

    if (pam_err != PAM_SUCCESS) {
        syslog(LOG_INFO, "pam_auth_err");
        return PAM_AUTH_ERR;
    }


    if (xmlrpc_start() == FCOMBINE_STARTUP_FAIL) {
        syslog(LOG_INFO, "xmlrpc_start fail");
        return PAM_SYSTEM_ERR;
    }

    syslog(LOG_INFO, "pre-auth-user");
    result = xmlrpc_auth_user(user, password);
    syslog(LOG_INFO, "post-auth-user");

    xmlrpc_end();

    syslog(LOG_INFO, "pam_fcombine result = %d", result);

    switch (result) {
        case FCOMBINE_AUTH_SUCCESS:
            return PAM_SUCCESS;
        //case FCOMBINE_AUTH_FAILED:
        //    return PAM_USER_UNKNOWN;
        case FCOMBINE_AUTH_FAILED:
            return PAM_AUTH_ERR;
    }

    return PAM_SYSTEM_ERR;
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
        const char *argv[]) {
    return PAM_SUCCESS;
}


/*PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
        const char *argv[]) {
    return PAM_SUCCESS;
}*/
