/*
 * Requires 'libpam0g-dev' and 'libcurl4-openssl-dev' on Ubuntu.
 *
 * Setup:
 *  mkdir /lib/security
 *  gcc -fPIC -fno-stack-protector -c pam_oidc_authz.c
 *  ld -x --shared -o /lib/security/pam_oidc_authz.so pam_oidc_authz.o `curl-config --libs`
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <curl/curl.h>

/*
 * Callback for libcurl to handle data.
 * Does nothing, instead of default behaviour to print to stdout.
 */
size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    return size * nmemb;
}

/*
 * Verify the access token.
 */
int verify_access_token(const char* username, const char* access_token,
                        const char* url, int verify_ssl) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        return PAM_SYSTEM_ERR;
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    /* url may be redirected, so we tell libcurl to follow redirection */
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    if (!verify_ssl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    /* Encode parameters */
    char* encoded_username = curl_easy_escape(curl, username, 0);
    char* encoded_access_token = curl_easy_escape(curl, access_token, 0);
    if (!encoded_username || ! encoded_access_token) {
        return PAM_SYSTEM_ERR;
    }

    /* Build url */
    char full_url[1024];
    snprintf(full_url, sizeof(full_url), "%s?user=%s&access_token=%s", url,
             encoded_username, encoded_access_token);
    curl_free(encoded_username);
    curl_free(encoded_access_token);

    printf("Full url: %s\n", full_url);
    curl_easy_setopt(curl, CURLOPT_URL, full_url);

    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    long http_code = 0;
    curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    return http_code == 200;
}

/*
 * PAM module callback for 'auth'
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv ) {
    int retval;

    if (argc < 1) {
        return PAM_SYSTEM_ERR; // fail instantly if not configured with url
    }

    const char* p_user;
    retval = pam_get_user(pamh, &p_user, "Username: ");
    if (retval != PAM_SUCCESS) {
        return retval;
    }

    const char* p_access_token;
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &p_access_token, "Access token: ");
    if (retval != PAM_SUCCESS) {
        return retval;
    }

    int verify_ssl = 1;
    if (argc == 2) {
        verify_ssl = atoi(argv[1]);
    }

    return verify_access_token(p_user, p_access_token, argv[0], verify_ssl) ?
                PAM_SUCCESS : PAM_AUTH_ERR;
}

/*
 * PAM module callback for 'auth'
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv ) {
	return PAM_SUCCESS;
}