import argparse
from functools import partial
import importlib
import json
import os
import urlparse
import sys

from cherrypy import wsgiserver
import cherrypy
from cherrypy.wsgiserver import ssl_pyopenssl
from mako.lookup import TemplateLookup
from oic.oic.non_web_provider import NonWebProvider, MakoRenderer
from oic.oic.provider import AuthorizationEndpoint, TokenEndpoint, \
    UserinfoEndpoint, RegistrationEndpoint, EndSessionEndpoint
from oic.utils import shelve_wrapper
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.authz import AuthzHandling
from oic.utils.http_util import wsgi_wrapper, ServiceError, BadRequest, \
    Response, \
    get_or_post
from oic.utils.keyio import keyjar_init
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo
from oic.utils.webfinger import OIC_ISSUER, WebFinger


class OICProviderMiddleware(object):
    def __init__(self, provider, app):
        self.provider = provider
        self.app = app

    def __call__(self, environ, start_response):
        environ["oic.oas"] = self.provider
        return self.app(environ, start_response)


def token(environ, start_response):
    _oas = environ["oic.oas"]
    return wsgi_wrapper(environ, start_response, _oas.token_endpoint)


def authorization(environ, start_response):
    _oas = environ["oic.oas"]
    return wsgi_wrapper(environ, start_response, _oas.authorization_endpoint)


def userinfo(environ, start_response):
    _oas = environ["oic.oas"]
    return wsgi_wrapper(environ, start_response, _oas.userinfo_endpoint)


def op_info(environ, start_response):
    _oas = environ["oic.oas"]
    return wsgi_wrapper(environ, start_response, _oas.providerinfo_endpoint)


def registration(environ, start_response):
    _oas = environ["oic.oas"]

    if environ["REQUEST_METHOD"] == "POST":
        return wsgi_wrapper(environ, start_response, _oas.registration_endpoint)
    elif environ["REQUEST_METHOD"] == "GET":
        return wsgi_wrapper(environ, start_response, _oas.read_registration)
    else:
        resp = ServiceError("Method not supported")
        return resp(environ, start_response)


def endsession(environ, start_response):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.endsession_endpoint)


def webfinger(environ, start_response):
    query = urlparse.parse_qs(environ["QUERY_STRING"])
    try:
        assert query["rel"] == [OIC_ISSUER]
        resource = query["resource"][0]
    except KeyError:
        resp = BadRequest("Missing parameter in request")
    else:
        wf = WebFinger()
        resp = Response(wf.response(subject=resource, base=OAS.baseurl))
    return resp(environ, start_response)


def consent(environ, start_response):
    _oas = environ["oic.oas"]

    params_str = get_or_post(environ)
    params = dict(urlparse.parse_qsl(params_str))

    return _oas.consent_endpoint(**params)(environ, start_response)


def list_access_tokens(environ, start_response):
    _oas = environ["oic.oas"]
    return wsgi_wrapper(environ, start_response,
                        _oas.list_access_tokens_endpoint)


def revoke_access_token(environ, start_response):
    _oas = environ["oic.oas"]

    params_str = get_or_post(environ)
    params = dict(urlparse.parse_qsl(params_str))

    return _oas.revoke_access_token_endpoint(**params)(environ, start_response)


ENDPOINTS = [
    AuthorizationEndpoint(authorization),
    TokenEndpoint(token),
    UserinfoEndpoint(userinfo),
    RegistrationEndpoint(registration),
    EndSessionEndpoint(endsession)
]

LOOKUP = TemplateLookup(directories=["templates"], input_encoding='utf-8',
                        output_encoding='utf-8')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument(dest="config")
    args = parser.parse_args()

    # Client data base
    cdb = shelve_wrapper.open("client_db", writeback=True)

    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)
    config.issuer = config.issuer % args.port

    ac = AuthnBroker()
    authn = UsernamePasswordMako(
        None, "login.mako", LOOKUP, config.PASSWD,
        "%s/authorization" % config.issuer)
    ac.add("UsernamePassword", authn)

    # dealing with authorization
    authz = AuthzHandling()

    # Consent and list tokens page
    renderer = MakoRenderer(LOOKUP)
    consent_page_handler = partial(renderer, "consent.mako",
                                   form_action="/consent_ok")
    list_tokens_page_handler = partial(renderer, "list_access_tokens.mako")

    OAS = NonWebProvider(config.issuer, SessionDB(config.baseurl), cdb, ac,
                         None, authz, verify_client, config.SYM_KEY,
                         consent_page_handler, list_tokens_page_handler)

    for authn in ac:
        authn.srv = OAS

    # User info is a simple dictionary in this case statically defined in
    # the configuration file
    OAS.userinfo = UserInfo(config.USERDB)

    OAS.endpoints = ENDPOINTS

    if args.port == 80:
        OAS.baseurl = config.baseurl
    else:
        if config.baseurl.endswith("/"):
            config.baseurl = config.baseurl[:-1]
        OAS.baseurl = "%s:%d" % (config.baseurl, args.port)

    if not OAS.baseurl.endswith("/"):
        OAS.baseurl += "/"

    try:
        jwks = keyjar_init(OAS, config.keys, kid_template="op%d")
    except Exception, err:
        OAS.key_setup("static", sig={"format": "jwk", "alg": "rsa"})
    else:
        new_name = "jwks.json"
        with open(os.path.join(config.STATIC_DIR, new_name), "w") as f:
            json.dump(jwks, f)
        OAS.jwks_uri.append("%sstatic/%s" % (OAS.baseurl, new_name))

        # Static file handling
    static_config = {
        "/static": {
            "tools.staticdir.on": True,
            "tools.staticdir.dir": config.STATIC_DIR
        }
    }
    static_handler = cherrypy.tree.mount(None, "/", config=static_config)

    # Setup endpoints
    all_endpoints = [
        ("/.well-known/openid-configuration",
         OICProviderMiddleware(OAS, op_info)),
        ("/.well-known/webfinger", OICProviderMiddleware(OAS, webfinger)),
        ("/verify",
         lambda environ, start_response: wsgi_wrapper(environ, start_response,
                                                      authn.verify)),
        ("/my_tokens",
         OICProviderMiddleware(OAS, list_access_tokens)),
        ("/consent_ok", OICProviderMiddleware(OAS, consent)),
        ("/revoke_token", OICProviderMiddleware(OAS, revoke_access_token)),
        ("/static", static_handler)
    ]
    for ep in ENDPOINTS:
        all_endpoints.append(("/%s" % ep.etype, OICProviderMiddleware(OAS, ep)))

    d = wsgiserver.WSGIPathInfoDispatcher(all_endpoints)
    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port), d)

    https = ""
    if config.baseurl.startswith("https"):
        https = "using HTTPS"
    SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
        config.SERVER_CERT, config.SERVER_KEY, config.CERT_CHAIN)

    print "OC server starting listening on port:%s %s" % (args.port, https)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()