# Implementation of OpenID Connect Access Tokens as per client passwords.

This repository contains a proof-of-concept implementation of
https://tools.ietf.org/html/draft-sakimura-oidc-extension-nonweb-01.


## OpenID Connect Provider
The implementation of a provider with support for non-web access tokens can
be found in `src/op`. It has the following features:

* Support for "auth scope values" (request with scope value starting with
  "auth_" will in long-lived access tokens).
* The end user can name access tokens as part of the authentication flow.
* An authenticated user can revoke access tokens (see below).
* Support for dynamic registration and provider configuration information.

### Setup
1. Install dependencies:
        pip install -r src/op/requirements.txt
1. Configure the provider:
  1. Copy the file `src/op/op/config.py.example` to
`src/op/op/config.py.example`
  1. Update the base url and paths to SSL certs, encryption/signing keys, etc.
1. Start the provider:
        python op.py -p <port> config

### Revoking access tokens
A list of all valid access tokens can be viewed at the endpoint `/my_tokens`
of the provider. From that page each individual access token can be revoked.


## OpenID Connect Relying Party
The implementation of a relying party can be found in `src/service_provider`.
This RP registers with the provider dynamically and uses the
"Authorization Code Flow" and makes a token request to obtain the access token.

### Setup
1. Install dependencies:
        pip install -r src/service_provider/requirements.txt
1. Configure the client:
  1. Copy the file `src/service_provider/conf.py.example` to
     `src/service_provider/conf.py`
  1. Update the paths to SSL certs and the port if necessary.
  1. Update the `"srv_discovery_url"` of the `"non-web-op"` in `CLIENTS` to
     point to the base url of the provider described above.


## PAM module

A PAM module to verify an access token can be found in `src/pam_module`.
It sends (using `libcurl`) the entered access token to the relying party
(described above) authorization.

### Setup in Ubuntu
    # Install dependencies
    apt-get install libpam0g-dev libcurl4-openssl-dev
    # Compile
    gcc -fPIC -fno-stack-protector -c pam_oidc_authz.c
    # Create shared library for PAM
    mkdir /lib/security
    ld -x --shared -o /lib/security/pam_oidc_authz.so pam_oidc_authz.o `curl-config --libs`


## Test application
A small application for testing the flow can be found in `src/test_app`.

### PAM configuration in Ubuntu
Add the following to the file `/etc/pam.d/test_app`:

    auth requisite pam_oidc_authz.so <url to service provider> <verify_ssl {0, 1}>
    account sufficient pam_permit.so

### Setup

    # Compile
    gcc -o test_app test_app.c -lpam -lpam_misc
    # Run
    ./test_app <username> <path to file containing access token>
