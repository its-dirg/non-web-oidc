#!/usr/bin/env python

import argparse
from mako.lookup import TemplateLookup
from oic.utils.http_util import Response

LOOKUP = TemplateLookup(directories=['templates'],
                        module_directory='modules',
                        input_encoding='utf-8',
                        output_encoding='utf-8')

def login_page(environ, start_response):
    resp = Response(mako_template="list_access_tokens.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {"service_provider_url": SERVICE_PROVIDER_URL}
    return resp(environ, start_response, **argv)

def application(environ, start_response):
    return login_page(environ, start_response)

if __name__ == '__main__':
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument(dest='service_provider_url')
    args = parser.parse_args()

    SERVICE_PROVIDER_URL = args.service_provider_url

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port),
                                        SessionMiddleware(application))

    print "RP server starting listening on port:%s" % args.port
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()