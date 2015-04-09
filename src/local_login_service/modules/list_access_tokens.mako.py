# -*- encoding:utf-8 -*-
from mako import runtime, filters, cache
UNDEFINED = runtime.UNDEFINED
__M_dict_builtin = dict
__M_locals_builtin = locals
_magic_number = 9
_modified_time = 1428581449.165467
_enable_loop = True
_template_filename = 'templates/list_access_tokens.mako'
_template_uri = 'list_access_tokens.mako'
_source_encoding = 'utf-8'
_exports = []


def render_body(context,**pageargs):
    __M_caller = context.caller_stack._push_frame()
    try:
        __M_locals = __M_dict_builtin(pageargs=pageargs)
        service_provider_url = context.get('service_provider_url', UNDEFINED)
        __M_writer = context.writer()
        # SOURCE LINE 1
        __M_writer(u'<!DOCTYPE html>\n<html>\n<head lang="en">\n    <meta charset="UTF-8">\n    <title></title>\n</head>\n<body>\n\n    <form action="')
        # SOURCE LINE 9
        __M_writer(unicode(service_provider_url))
        __M_writer(u'" method="GET">\n        Please enter your username:<br>\n        <input type="text" name="username">\n\n        <input type="submit" value="Submit">\n    </form>\n    \n</body>\n</html>')
        return ''
    finally:
        context.caller_stack._pop_frame()


