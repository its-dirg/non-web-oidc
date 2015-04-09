#!/usr/bin/env python
import importlib
import urllib
import urlparse
from urlparse import parse_qs
import logging

import argparse
from jwkest.jws import alg2keytype
from mako.lookup import TemplateLookup
from oic.utils.http_util import NotFound, Unauthorized, ServiceError
from oic.utils.http_util import Response
from oic.utils.http_util import Redirect
from src.service_provider.database import PamDatabase


LOGGER = logging.getLogger("")
LOGFILE_NAME = 'service_provider.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

LOOKUP = TemplateLookup(directories=['templates', 'htdocs'],
                        module_directory='modules',
                        input_encoding='utf-8',
                        output_encoding='utf-8')

SERVER_ENV = {}


# noinspection PyUnresolvedReferences
def static(environ, start_response, logger, path):
    logger.info("[static]sending: %s" % (path,))

    try:
        text = open(path).read()
        if path.endswith(".ico"):
            start_response('200 OK', [('Content-Type', "image/x-icon")])
        elif path.endswith(".html"):
            start_response('200 OK', [('Content-Type', 'text/html')])
        elif path.endswith(".json"):
            start_response('200 OK', [('Content-Type', 'application/json')])
        elif path.endswith(".txt"):
            start_response('200 OK', [('Content-Type', 'text/plain')])
        elif path.endswith(".css"):
            start_response('200 OK', [('Content-Type', 'text/css')])
        else:
            start_response('200 OK', [('Content-Type', "text/xml")])
        return [text]
    except IOError:
        resp = NotFound()
        return resp(environ, start_response)


def opchoice(environ, start_response, clients):
    resp = Response(mako_template="opchoice.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "op_list": clients.keys()
    }
    return resp(environ, start_response, **argv)


def access_token_page(environ, start_response, access_token):
    resp = Response(mako_template="access_token.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "access_token": access_token,
    }

    return resp(environ, start_response, **argv)


def operror(environ, start_response, error=None):
    resp = Response(mako_template="operror.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "error": error
    }
    return resp(environ, start_response, **argv)


#
def get_id_token(client, session):
    return client.grant[session["state"]].get_id_token()


# Produce a JWS, a signed JWT, containing a previously received ID token
def id_token_as_signed_jwt(client, id_token, alg="RS256"):
    ckey = client.keyjar.get_signing_key(alg2keytype(alg), "")
    _signed_jwt = id_token.to_jwt(key=ckey, algorithm=alg)
    return _signed_jwt


def verify_access_token(query):
    local_user = query['user'][0]
    row = DATABASE.get_row(local_user)

    if not row:
        error_message = "No local user (%s) found in the database."  % local_user
        LOGGER.error(error_message)
        return ServiceError(error_message)

    access_token = query['access_token'][0]
    client = CLIENTS[row["issuer"]]
    user_info = client.request_user_info(access_token)
    if user_info["sub"] == row["subject_id"]:
        for scope in conf.BEHAVIOUR["scope"]:
            if scope in user_info:
                return Response()
        error_message = "No auth claim in user info response (%s)" % user_info.keys()
        LOGGER.error(error_message)
        return ServiceError(error_message)
    error_message = "Logged in user (%s) does not match the one stored in the database (%s)" % (user_info["sub"], row["subject_id"])
    LOGGER.debug(error_message)
    return Unauthorized(error_message)


def application(environ, start_response):
    session = environ['beaker.session']
    path = environ.get('PATH_INFO', '').lstrip('/')
    if path == "robots.txt":
        return static(environ, start_response, LOGGER, "static/robots.txt")

    if path.startswith("static/"):
        return static(environ, start_response, LOGGER, path)

    query = parse_qs(environ["QUERY_STRING"])

    if path == "rp":  # After having chosen which OP to authenticate at
        if "uid" in query:
            client = CLIENTS.dynamic_client(query["uid"][0])
            session["op"] = client.provider_info["issuer"]
        else:
            client = CLIENTS[query["op"][0]]
            session["op"] = query["op"][0]

        try:
            resp = client.create_authn_request(session, ACR_VALUES)
        except Exception:
            raise
        else:
            return resp(environ, start_response)
    elif path == "authz_cb":  # After having authenticated at the OP
        client = CLIENTS[session["op"]]
        try:
            result = client.callback(query, session)
            if isinstance(result, Redirect):
                return result(environ, start_response)
        except OIDCError as err:
            return operror(environ, start_response, "%s" % err)
        except Exception as ex:
            raise
        else:
            #TODO get local_user
            DATABASE.upsert(issuer=session["op"], local_user="temp", subject_id=result['id_token']['sub'])
            return access_token_page(environ, start_response, result['access_token'])

    elif path == "logout":  # After the user has pressed the logout button
        client = CLIENTS[session["op"]]
        logout_url = client.end_session_endpoint
        try:
            # Specify to which URL the OP should return the user after
            # log out. That URL must be registered with the OP at client
            # registration.
            logout_url += "?" + urllib.urlencode(
                {"post_logout_redirect_uri": client.registration_response[
                    "post_logout_redirect_uris"][0]})
        except KeyError:
            pass
        else:
            # If there is an ID token send it along as a id_token_hint
            _idtoken = get_id_token(client, session)
            if _idtoken:
                logout_url += "&" + urllib.urlencode({
                    "id_token_hint": id_token_as_signed_jwt(client, _idtoken,
                                                            "HS256")})
            # Also append the ACR values
            logout_url += "&" + urllib.urlencode({"acr_values": ACR_VALUES},
                                                 True)

        LOGGER.debug("Logout URL: %s" % str(logout_url))
        LOGGER.debug("Logging out from session: %s" % str(session))
        session.delete()
        resp = Redirect(str(logout_url))
        return resp(environ, start_response)
    elif path == "logout_success":  # post_logout_redirect_uri
        return Response("Logout successful!")(environ, start_response)
    elif path == "session_iframe":  # session management
        kwargs = session["session_management"]
        resp = Response(mako_template="rp_session_iframe.mako", template_lookup=LOOKUP)
        return resp(environ, start_response, session_change_url="{}session_change".format(SERVER_ENV["base_url"]),
                    **kwargs)
    elif path == "session_change":
        try:
            client = CLIENTS[session["op"]]
        except KeyError:
            return Response("No valid session.")(environ, start_response)

        kwargs = {"prompt": "none"}
        # If there is an ID token send it along as a id_token_hint
        idt = get_id_token(client, session)
        if idt:
            kwargs["id_token_hint"] = id_token_as_signed_jwt(client, idt, "HS256")
        resp = client.create_authn_request(session, ACR_VALUES, **kwargs)
        return resp(environ, start_response)
    elif path == "verify_access_token":
        response = verify_access_token(query)
        return response(environ, start_response)

    return opchoice(environ, start_response, CLIENTS)


if __name__ == '__main__':
    from src.service_provider.oidc import OIDCClients
    from src.service_provider.oidc import OIDCError
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver

    parser = argparse.ArgumentParser()
    parser.add_argument(dest="config")
    args = parser.parse_args()
    conf = importlib.import_module(args.config)

    global ACR_VALUES
    ACR_VALUES = conf.ACR_VALUES

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.key': "{}.beaker.session.id".format(urlparse.urlparse(conf.BASE).netloc.replace(":", "."))
    }

    CLIENTS = OIDCClients(conf)
    SERVER_ENV.update({"template_lookup": LOOKUP, "base_url": conf.BASE})

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', conf.PORT),
                                        SessionMiddleware(application,
                                                          session_opts))
    DATABASE = PamDatabase(conf.PAM_DATABASE)

    if conf.BASE.startswith("https"):
        from cherrypy.wsgiserver import ssl_pyopenssl

        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            conf.SERVER_CERT, conf.SERVER_KEY, conf.CA_BUNDLE)

    LOGGER.info("RP server starting listening on port:%s" % conf.PORT)
    print "RP server starting listening on port:%s" % conf.PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
