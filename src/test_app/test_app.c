/*
 * From https://github.com/beatgammit/simple-pam
 *
 * To compile it: gcc -o test_app test_app.c -lpam -lpam_misc
 *
 * Simple example PAM config (Ubuntu: in the file /etc/pam.d/test_app):
 *  auth requisite pam_oidc_authz.so <url to service provider> <verify_ssl {0, 1}>
 *  account sufficient pam_permit.so
 *
 */

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

/*
 * Simple conversation function for PAM, which reads data from file instead
 * of prompting the user.
 */
int conv_func(int num_msg, const struct pam_message **msg,
                struct pam_response **resp, void *appdata_ptr) {
    struct pam_response *reply = malloc(sizeof(struct pam_response));

    FILE *fp = fopen(appdata_ptr, "r");
    char* data = calloc(200, sizeof(char));
    fgets(data, 200, fp);
    fclose(fp);

    /* Remove trailing newline (if any) */
    data[strcspn(data, "\n")] = 0;

    reply[0].resp = data;
    reply[0].resp_retcode = 0;

    *resp = reply;
    return PAM_SUCCESS;
}

int main(int argc, char *argv[]) {
	pam_handle_t* pamh = NULL;
	int retval;

	if(argc != 3) {
		printf("Usage: %s <username> <access_token_file>\n", argv[0]);
		exit(1);
	}

	const struct pam_conv conv = {
	    conv_func,
	    argv[2] /* Send the filename as app data */
    };

	/* Initialize PAM transaction */
	const char* user = argv[1];
	retval = pam_start("test_app", user, &conv, &pamh);

	// Are the credentials correct?
	if (retval == PAM_SUCCESS) {
		printf("Credentials accepted.\n");
		retval = pam_authenticate(pamh, 0);
	}

	// Can the accound be used at this time?
	if (retval == PAM_SUCCESS) {
		printf("Account is valid.\n");
		retval = pam_acct_mgmt(pamh, 0);
	}

	// Did everything work?
	if (retval == PAM_SUCCESS) {
		printf("Authenticated\n");
	} else {
		printf("Not Authenticated\n");
	}

	// close PAM (end session)
	if (pam_end(pamh, retval) != PAM_SUCCESS) {
		pamh = NULL;
		printf("check_user: failed to release authenticator\n");
		exit(1);
	}

	return retval == PAM_SUCCESS ? 0 : 1;
}