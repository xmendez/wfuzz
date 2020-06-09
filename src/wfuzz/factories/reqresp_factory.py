import abc

import pycurl

from ..helpers.obj_factory import HttpRequestFactory
from ..helpers.str_func import (
    python2_3_convert_to_unicode,
    python2_3_convert_from_unicode,
)


from ..externals.reqresp import Response


PYCURL_PATH_AS_IS = True
if not hasattr(pycurl, "PATH_AS_IS"):
    PYCURL_PATH_AS_IS = False


class ReqRespRequestFactory(HttpRequestFactory):
    def to_http_object(options, req, pycurl_c):
        pycurl_c.setopt(pycurl.MAXREDIRS, 5)

        pycurl_c.setopt(pycurl.WRITEFUNCTION, req._request.body_callback)
        pycurl_c.setopt(pycurl.HEADERFUNCTION, req._request.header_callback)

        pycurl_c.setopt(pycurl.NOSIGNAL, 1)
        pycurl_c.setopt(pycurl.SSL_VERIFYPEER, False)
        pycurl_c.setopt(pycurl.SSL_VERIFYHOST, 0)

        if PYCURL_PATH_AS_IS:
            pycurl_c.setopt(pycurl.PATH_AS_IS, 1)

        pycurl_c.setopt(
            pycurl.URL, python2_3_convert_to_unicode(req._request.completeUrl)
        )

        if req._request.getConnTimeout():
            pycurl_c.setopt(pycurl.CONNECTTIMEOUT, req._request.getConnTimeout())

        if req._request.getTotalTimeout():
            pycurl_c.setopt(pycurl.TIMEOUT, req._request.getTotalTimeout())

        authMethod, userpass = req._request.getAuth()
        if authMethod or userpass:
            if authMethod == "basic":
                pycurl_c.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
            elif authMethod == "ntlm":
                pycurl_c.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_NTLM)
            elif authMethod == "digest":
                pycurl_c.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_DIGEST)
            pycurl_c.setopt(pycurl.USERPWD, python2_3_convert_to_unicode(userpass))
        else:
            pycurl_c.unsetopt(pycurl.USERPWD)

        pycurl_c.setopt(
            pycurl.HTTPHEADER, python2_3_convert_to_unicode(req._request.getHeaders())
        )

        curl_options = {
            "GET": pycurl.HTTPGET,
            "POST": pycurl.POST,
            "PATCH": pycurl.UPLOAD,
            "HEAD": pycurl.NOBODY,
        }

        for verb in curl_options.values():
            pycurl_c.setopt(verb, False)

        if req._request.method in curl_options:
            pycurl_c.unsetopt(pycurl.CUSTOMREQUEST)
            pycurl_c.setopt(curl_options[req._request.method], True)
        else:
            pycurl_c.setopt(pycurl.CUSTOMREQUEST, req._request.method)

        if req._request._non_parsed_post is not None:
            pycurl_c.setopt(
                pycurl.POSTFIELDS,
                python2_3_convert_to_unicode(req._request._non_parsed_post),
            )

        pycurl_c.setopt(pycurl.FOLLOWLOCATION, 1 if req._request.followLocation else 0)

        # proxy = req._request.getProxy()
        # if proxy is not None:
        #     pycurl_c.setopt(pycurl.PROXY, python2_3_convert_to_unicode(proxy))
        #     if req._request.proxytype == "SOCKS5":
        #         pycurl_c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
        #     elif req._request.proxytype == "SOCKS4":
        #         pycurl_c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS4)
        #     req._request.delHeader("Proxy-Connection")
        # else:
        #     pycurl_c.setopt(pycurl.PROXY, "")

        if req.wf_ip:
            pycurl_c.setopt(
                pycurl.CONNECT_TO,
                ["::{}:{}".format(req.wf_ip["ip"], req.wf_ip["port"])],
            )

        return pycurl_c

    def from_http_object(options, req, pycurl_c, header, body):
        raw_header = python2_3_convert_from_unicode(
            header.decode("utf-8", errors="surrogateescape")
        )

        if pycurl_c.getinfo(pycurl.EFFECTIVE_URL) != req._request.completeUrl:
            req._request.setFinalUrl(pycurl_c.getinfo(pycurl.EFFECTIVE_URL))

        req._request.totaltime = pycurl_c.getinfo(pycurl.TOTAL_TIME)

        req._request.response = Response()
        req._request.response.parseResponse(raw_header, rawbody=body)

        return req._request.response
