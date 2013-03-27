#include "libfcombine_xmlrpc.h"
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>
#include <string.h>
#include <xmlrpc.h>
#include <xmlrpc_client.h>


xmlrpc_env rpc_env;
xmlrpc_value *result = NULL;
struct xmlrpc_clientparms client_params;
struct xmlrpc_curl_xportparms curl_params;
xmlrpc_int32 result_code;
xmlrpc_client *client;
const char *client_name = "pam_fcombine.so";
const char *version = "1.0";
const char *url = "https://127.0.0.1:9999"; 
const char *ssl_cert = "/etc/pki/tls/certs/fcombine_xmlrpc.crt";
const char *ssl_key = "/etc/pki/tls/private/fcombine_xmlrpc.key";
const char *ca_cert = "/etc/pki/tls/certs/fcombine_xmlrpc.crt";


static bool fault_handler(void);
int xmlrpc_fill_passwd(struct passwd *pwd, char *buf, size_t buflen);
int xmlrpc_fill_group(struct group *grp, char *buf, size_t buflen);


static bool fault_handler(void) {
    if (rpc_env.fault_occurred) {
        syslog(LOG_INFO, "XML-RPC Fault %s (%d)\n",
                rpc_env.fault_string, rpc_env.fault_code);
        return true;
    }

    return false;
}

int xmlrpc_start(void) {
    syslog(LOG_INFO, "xmlrpc_start");

    /* TODO: we should check both concurrency and we should probably check
     * whether we've already been initialized */

    curl_params.network_interface = 0;
    curl_params.no_ssl_verifypeer = 1;
    curl_params.no_ssl_verifyhost = 1;
    curl_params.user_agent        = "pam_fcombine.so";
    curl_params.ssl_cert = ssl_cert;
    curl_params.sslcerttype = "PEM";
    curl_params.sslcertpasswd = "";
    curl_params.sslkey = ssl_key;
    curl_params.sslkeytype = "PEM";
    curl_params.sslkeypasswd = "";
    curl_params.sslengine = "";
    curl_params.sslengine_default = 1;
    curl_params.sslversion = XMLRPC_SSLVERSION_TLSv1;
    curl_params.cainfo = ca_cert;

    client_params.transport          = "curl";
    client_params.transportparmsP    = &curl_params;
    client_params.transportparm_size = XMLRPC_CXPSIZE(cainfo);

    /* check that all our certs/keys exist */
    if (access(ssl_cert, R_OK) != 0) {
        syslog(LOG_INFO, "SSL certificate cannot be opened: %s", ssl_cert);
        return FCOMBINE_STARTUP_FAIL;
    }

    if (access(ssl_key, R_OK) != 0) {
        syslog(LOG_INFO, "SSL key cannot be opened: %s", ssl_key);
        return FCOMBINE_STARTUP_FAIL;
    }

    if (access(ca_cert, R_OK) != 0) {
        syslog(LOG_INFO, "CA certificate cannot be opened: %s", ca_cert);
        return FCOMBINE_STARTUP_FAIL;
    }


    /* Start up our XML-RPC client library. */
    xmlrpc_env_init(&rpc_env);
    xmlrpc_client_setup_global_const(&rpc_env);


    /* Initialize the RPC client */
    xmlrpc_client_create(&rpc_env, XMLRPC_CLIENT_NO_FLAGS, client_name, version,
            &client_params, XMLRPC_CPSIZE(transportparm_size), &client);
    if (fault_handler()) {
        return FCOMBINE_STARTUP_FAIL;
    }
    syslog(LOG_INFO, "xmlrpc_start ended");

    return FCOMBINE_STARTUP_SUCCESS;
}

int xmlrpc_auth_user(const char *username, const char *password) {

    xmlrpc_client_call2f(&rpc_env, client, url, "pam_authenticate", &result,
            "(ss)", username, password);
    if (fault_handler()) {
        return FCOMBINE_DAEMON_ERR;
    }

    /* Get the result of the RPC and print it out. */
    xmlrpc_read_int(&rpc_env, result, &result_code);
    if (fault_handler()) {
        return FCOMBINE_DAEMON_ERR;
    }

    return result_code;
}



/* PASSWD FUNCTIONS */


int xmlrpc_getpwnam(const char *name, struct passwd *pwd, char *buf,
        size_t buflen) {


    /* Call nss_getpwnam on the remote end and pass in the username as a
     * parameter */
    xmlrpc_client_call2f(&rpc_env, client, url, "nss_getpwnam", &result,
            "(s)", name);

    if (fault_handler()) {
        return FCOMBINE_DAEMON_ERR;
    }

    if (xmlrpc_value_type(result) == XMLRPC_TYPE_NIL) {
        return FCOMBINE_NOT_FOUND;
    }

    return xmlrpc_fill_passwd(pwd, buf, buflen);

}

int xmlrpc_getpwuid(uid_t uid, struct passwd *pwd, char *buf, size_t buflen) {

    /* Call nss_getpwuid on the remote end and pass in the user id as a
     * parameter */
    xmlrpc_client_call2f(&rpc_env, client, url, "nss_getpwuid", &result,
            "(i)", (int*)&(uid));

    if (fault_handler()) {
        return FCOMBINE_DAEMON_ERR;
    }

    if (xmlrpc_value_type(result) == XMLRPC_TYPE_NIL) {
        return FCOMBINE_NOT_FOUND;
    }

    return xmlrpc_fill_passwd(pwd, buf, buflen);

}

int xmlrpc_setpwent(void) {
    syslog(LOG_INFO, "xmlrpc_setpwent");

    xmlrpc_client_call2f(&rpc_env, client, url, "nss_setpwent", &result, "()");

    if (fault_handler()) {
        return FCOMBINE_DAEMON_ERR;
    }

    return FCOMBINE_DAEMON_SUCCESS;
}

int xmlrpc_endpwent(void) {
    syslog(LOG_INFO, "xmlrpc_endpwent");

    xmlrpc_client_call2f(&rpc_env, client, url, "nss_endpwent", &result, "()");

    if (fault_handler()) {
        return FCOMBINE_DAEMON_ERR;
    }

    return FCOMBINE_DAEMON_SUCCESS;
}

int xmlrpc_getpwent(struct passwd *pwd, char *buf, size_t buflen) {

    syslog(LOG_INFO, "xmlrpc_getpwent");

    /* Call nss_getpwent on the remote end */
    xmlrpc_client_call2f(&rpc_env, client, url, "nss_getpwent", &result, "()");

    if (xmlrpc_value_type(result) == XMLRPC_TYPE_NIL) {
        return FCOMBINE_NOT_FOUND;
    }

    if (fault_handler()) {
        return FCOMBINE_DAEMON_ERR;
    }

    return xmlrpc_fill_passwd(pwd, buf, buflen);

}




/* GROUP FUNCTIONS */

int xmlrpc_getgrnam(const char* name, struct group *grp, char *buf,
        size_t buflen) {

    syslog(LOG_INFO, "About to do xmlrpc gr_mem");

    /* Call nss_getpwnam on the remote end and pass in the username as a
     * parameter */
    xmlrpc_client_call2f(&rpc_env, client, url, "nss_getgrnam", &result,
            "(s)", name);

    if (fault_handler()) {
        return FCOMBINE_DAEMON_ERR;
    }

    if (xmlrpc_value_type(result) == XMLRPC_TYPE_NIL) {
        return FCOMBINE_NOT_FOUND;
    }

    return xmlrpc_fill_group(grp, buf, buflen);
}

int xmlrpc_getgrgid(gid_t gid, struct group *grp, char *buf, size_t buflen) {

    syslog(LOG_INFO, "About to do xmlrpc gr_mem for getgrgid");

    /* Call nss_getpwnam on the remote end and pass in the username as a
     * parameter */
    xmlrpc_client_call2f(&rpc_env, client, url, "nss_getgrgid", &result,
            "(i)", gid);

    if (fault_handler()) {
        return FCOMBINE_DAEMON_ERR;
    }

    if (xmlrpc_value_type(result) == XMLRPC_TYPE_NIL) {
        return FCOMBINE_NOT_FOUND;
    }

    return xmlrpc_fill_group(grp, buf, buflen);
}

int xmlrpc_setgrent(void) {
    syslog(LOG_INFO, "xmlrpc_setgrent");

    xmlrpc_client_call2f(&rpc_env, client, url, "nss_setgrent", &result, "()");

    if (fault_handler()) {
        return FCOMBINE_DAEMON_ERR;
    }

    return FCOMBINE_DAEMON_SUCCESS;
}

int xmlrpc_endgrent(void) {
    syslog(LOG_INFO, "xmlrpc_endgrent");

    xmlrpc_client_call2f(&rpc_env, client, url, "nss_endgrent", &result, "()");

    if (fault_handler()) {
        return FCOMBINE_DAEMON_ERR;
    }

    return FCOMBINE_DAEMON_SUCCESS;
}

int xmlrpc_getgrent(struct group *grp, char *buf, size_t buflen) {
    syslog(LOG_INFO, "xmlrpc_getgrent");

    /* Call nss_getgrent on the remote end */
    xmlrpc_client_call2f(&rpc_env, client, url, "nss_getgrent", &result, "()");

    if (fault_handler()) {
        return FCOMBINE_DAEMON_ERR;
    }

    if (xmlrpc_value_type(result) == XMLRPC_TYPE_NIL) {
        return FCOMBINE_NOT_FOUND;
    }

    return xmlrpc_fill_group(grp, buf, buflen);

}




/* HELPER FUNCTIONS */

int xmlrpc_fill_passwd(struct passwd *pwd, char *buf, size_t buflen) {

    size_t required_len;

    xmlrpc_value *x_name;
    xmlrpc_value *x_passwd;
    xmlrpc_value *x_uid;
    xmlrpc_value *x_gid;
    xmlrpc_value *x_gecos;
    xmlrpc_value *x_dir;
    xmlrpc_value *x_shell;

    const char *pw_name;
    const char *pw_passwd;
    const char *pw_gecos;
    const char *pw_dir;
    const char *pw_shell;

    size_t pw_name_len;
    size_t pw_passwd_len;
    size_t pw_gecos_len;
    size_t pw_dir_len;
    size_t pw_shell_len;
   


    /* pw_name */
    xmlrpc_struct_find_value(&rpc_env, result, "name", &x_name);
    if (x_name) {
        xmlrpc_read_string(&rpc_env, x_name, &pw_name);
        xmlrpc_DECREF(x_name);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }


    /* pw_passwd */
    xmlrpc_struct_find_value(&rpc_env, result, "passwd", &x_passwd);
    if (x_passwd) {
        xmlrpc_read_string(&rpc_env, x_passwd, &pw_passwd);
        xmlrpc_DECREF(x_passwd);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }


    /* pw_uid */
    xmlrpc_struct_find_value(&rpc_env, result, "uid", &x_uid);
    if (x_uid) {
        xmlrpc_read_int(&rpc_env, x_uid, (int*)&(pwd->pw_uid));
        xmlrpc_DECREF(x_uid);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }


    /* pw_gid */
    xmlrpc_struct_find_value(&rpc_env, result, "gid", &x_gid);
    if (x_gid) {
        xmlrpc_read_int(&rpc_env, x_gid, (int*)&(pwd->pw_gid));
        xmlrpc_DECREF(x_gid);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }


    /* pw_gecos */
    xmlrpc_struct_find_value(&rpc_env, result, "gecos", &x_gecos);
    if (x_gecos) {
        xmlrpc_read_string(&rpc_env, x_gecos, &pw_gecos);
        xmlrpc_DECREF(x_gecos);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }


    /* pw_dir */
    xmlrpc_struct_find_value(&rpc_env, result, "home_dir", &x_dir);
    if (x_dir) {
        xmlrpc_read_string(&rpc_env, x_dir, &pw_dir);
        xmlrpc_DECREF(x_dir);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }

    /* pw_shell */
    xmlrpc_struct_find_value(&rpc_env, result, "shell", &x_shell);
    if (x_shell) {
        xmlrpc_read_string(&rpc_env, x_shell, &pw_shell);
        xmlrpc_DECREF(x_shell);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }

    /* calculate the size needed to store all the various string values */
    pw_name_len = strlen(pw_name) + 1;
    pw_passwd_len = strlen(pw_passwd) + 1;
    pw_gecos_len = strlen(pw_gecos) + 1;
    pw_dir_len = strlen(pw_dir) + 1;
    pw_shell_len = strlen(pw_shell) + 1;

    required_len = pw_name_len + pw_passwd_len + pw_gecos_len + pw_dir_len + 
            pw_shell_len;

    if (required_len > buflen) {
        return FCOMBINE_BUFFER_TOOSMALL;
    }

    /* now set the various members of pwd */
    strcpy(buf, pw_name);
    pwd->pw_name = buf;
    buf += pw_name_len;

    strcpy(buf, pw_passwd);
    pwd->pw_passwd = buf;
    buf += pw_passwd_len;

    strcpy(buf, pw_gecos);
    pwd->pw_gecos = buf;
    buf += pw_gecos_len;

    strcpy(buf, pw_dir);
    pwd->pw_dir = buf;
    buf += pw_dir_len;

    strcpy(buf, pw_shell);
    pwd->pw_shell = buf;


    return FCOMBINE_DAEMON_SUCCESS;

}


void xmlrpc_end(void) {
    syslog(LOG_INFO, "xmlrpc_end");

    //TODO: we need to do this in the various functions, not here, because
    //it may not be initialized
    if (result != NULL)
        xmlrpc_DECREF(result);

    syslog(LOG_INFO, "xmlrpc_end success");
    xmlrpc_env_clean(&rpc_env);
    xmlrpc_client_destroy(client);
    xmlrpc_client_teardown_global_const();

}

int xmlrpc_getspnam(const char* name, struct spwd *spbuf, char *buf,
        size_t buflen) {

    size_t required_len;
    xmlrpc_value *x_value;

    const char *sp_namp;
    const char *sp_pwdp;

    size_t sp_namp_len;
    size_t sp_pwdp_len;

    /* Call nss_getspnam on the remote end and pass in the username as a
     * parameter */
    xmlrpc_client_call2f(&rpc_env, client, url, "nss_getspnam", &result,
            "(s)", name);

    if (fault_handler()) {
        return FCOMBINE_DAEMON_ERR;
    }

    /* sp_namp */
    xmlrpc_struct_find_value(&rpc_env, result, "namp", &x_value);
    if (x_value) {
        xmlrpc_read_string(&rpc_env, x_value, &sp_namp);
        xmlrpc_DECREF(x_value);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }


    /* sp_pwdp - the encrypted password */
    xmlrpc_struct_find_value(&rpc_env, result, "pwdp", &x_value);
    if (x_value) {
        xmlrpc_read_string(&rpc_env, x_value, &sp_pwdp);
        xmlrpc_DECREF(x_value);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }


    /* sp_lstchg */
    xmlrpc_struct_find_value(&rpc_env, result, "lstchg", &x_value);
    if (x_value) {
        xmlrpc_read_int(&rpc_env, x_value, (int*)&(spbuf->sp_lstchg));
        xmlrpc_DECREF(x_value);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }

    /* sp_min */
    xmlrpc_struct_find_value(&rpc_env, result, "min", &x_value);
    if (x_value) {
        xmlrpc_read_int(&rpc_env, x_value, (int*)&(spbuf->sp_min));
        xmlrpc_DECREF(x_value);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }

    /* sp_max */
    xmlrpc_struct_find_value(&rpc_env, result, "max", &x_value);
    if (x_value) {
        xmlrpc_read_int(&rpc_env, x_value, (int*)&(spbuf->sp_max));
        xmlrpc_DECREF(x_value);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }

    /* sp_warn */
    xmlrpc_struct_find_value(&rpc_env, result, "warn", &x_value);
    if (x_value) {
        xmlrpc_read_int(&rpc_env, x_value, (int*)&(spbuf->sp_warn));
        xmlrpc_DECREF(x_value);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }

    /* sp_inact */
    xmlrpc_struct_find_value(&rpc_env, result, "inact", &x_value);
    if (x_value) {
        xmlrpc_read_int(&rpc_env, x_value, (int*)&(spbuf->sp_inact));
        xmlrpc_DECREF(x_value);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }

    /* sp_expire */
    xmlrpc_struct_find_value(&rpc_env, result, "expire", &x_value);
    if (x_value) {
        xmlrpc_read_int(&rpc_env, x_value, (int*)&(spbuf->sp_expire));
        xmlrpc_DECREF(x_value);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }

    /* sp_flag */
    spbuf->sp_flag = 0;

    /* calculate the size needed to store all the various string values */
    sp_namp_len = strlen(sp_namp) + 1;
    sp_pwdp_len = strlen(sp_pwdp) + 1;

    required_len = sp_namp_len + sp_pwdp_len;

    if (required_len > buflen) {
        return FCOMBINE_BUFFER_TOOSMALL;
    }

    /* now set the various members of spwd */
    strcpy(buf, sp_namp);
    spbuf->sp_namp = buf;
    buf += sp_namp_len;

    strcpy(buf, sp_pwdp);
    spbuf->sp_pwdp = buf;
    buf += sp_pwdp_len;

    return FCOMBINE_DAEMON_SUCCESS;
}



int xmlrpc_fill_group(struct group *grp, char *buf, size_t buflen) {

    size_t required_len;
    xmlrpc_value *x_value;

    /* for handling our mem array */
    int member_count;
    xmlrpc_value *x_member;
    const char *group_name;
    size_t group_name_len;

    const char *gr_name;
    const char *gr_passwd; 
    char **ptr_area;

    size_t gr_name_len;
    size_t gr_passwd_len; 
    size_t ptr_area_len;
    size_t buf_index;


    /* gr_name */
    xmlrpc_struct_find_value(&rpc_env, result, "name", &x_value);
    if (x_value) {
        xmlrpc_read_string(&rpc_env, x_value, &gr_name);
        xmlrpc_DECREF(x_value);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }


    /* gr_passwd */
    xmlrpc_struct_find_value(&rpc_env, result, "passwd", &x_value);
    if (x_value) {
        xmlrpc_read_string(&rpc_env, x_value, &gr_passwd);
        xmlrpc_DECREF(x_value);
    } else {
        return FCOMBINE_DAEMON_ERR;
    } 

    /* gr_gid */
    xmlrpc_struct_find_value(&rpc_env, result, "gid", &x_value);
    if (x_value) {
        xmlrpc_read_int(&rpc_env, x_value, (int*)&(grp->gr_gid));
        xmlrpc_DECREF(x_value);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }

    /* calculate the size needed to store all the various string values */
    gr_name_len = strlen(gr_name) + 1;
    gr_passwd_len = strlen(gr_passwd) + 1;

    required_len = gr_name_len + gr_passwd_len;
    buf_index = required_len;

    if (required_len > buflen) {
        return FCOMBINE_BUFFER_TOOSMALL;
    }

    strcpy(buf, gr_name);
    grp->gr_name = buf;
    buf += gr_name_len;

    strcpy(buf, gr_passwd);
    grp->gr_passwd = buf;
    buf += gr_passwd_len;

    grp->gr_mem = (char**)buf;

    /* buf is laid out as follows:
     * |gr_name string|gr_passwd string|gr_mem contents|
     *
     * Pointers to the three elements above are assigned to the various members
     * of the group structure. Note all the members above are null terminated.
     *
     * gr_mem needs further explanation as it's quite complicated.
     * It is laid out as follows:
     *
     * |pointer to member 1|pointer to member 2|....|pointer to member n|NULL
     * |member 1 string    |member 2 string    |....|member n string    |
     *
     * Note that the members are null terminated */


    /* To speed things up and make things easier on this end, we do the string
     * concatenation on the python side and then figure out how much room
     * we need for the pointers.  We allocate room for the number of pointers
     * in buf, plus a NULL (by basically skipping over that region) and then
     * copy the concatenated strings into buf.  Once the strings are in buf,
     * we can calculate the pointers that need to be placed in the gap of memory
     * we left */

    /* gr_mem */
    syslog(LOG_INFO, "About to gr_mem");
    xmlrpc_struct_find_value(&rpc_env, result, "mem", &x_value);
    if (x_value) {
        member_count = xmlrpc_array_size(&rpc_env, x_value);

        /* iterate over all the group names and copy them into buf, leaving
         * some room for the list of pointers */

        /* increment buf to the point where we can plonk the array of group
         * strings, also checking that we don't exceed it's size */
        ptr_area = (char**)buf;
        ptr_area_len = (member_count + 1) * sizeof(char*);
        buf_index += ptr_area_len;
        if (buf_index > buflen)
            return FCOMBINE_BUFFER_TOOSMALL;

        buf += ptr_area_len;

        /* buf now points to the start of the string array */

        for (int i=0; i < member_count; i++) {
            /* get the next group name */
            xmlrpc_array_read_item(&rpc_env, x_value, i, &x_member);
            xmlrpc_read_string(&rpc_env, x_member, &group_name);
            group_name_len = strlen(group_name) + 1;

            syslog(LOG_INFO, "Got group name: %s, length: %d", group_name,
                    (int)group_name_len);

            buf_index += group_name_len;
            if (buf_index > buflen)
                return FCOMBINE_BUFFER_TOOSMALL;

            strcpy(buf, group_name);
            ptr_area[i] = buf;
            buf += group_name_len;

            xmlrpc_DECREF(x_member);
        }

        ptr_area[member_count] = NULL;

        xmlrpc_DECREF(x_value);
    } else {
        return FCOMBINE_DAEMON_ERR;
    }


    return FCOMBINE_DAEMON_SUCCESS;

}

