# app.py
import requests
import falcon
import logging

from httplib import HTTPConnection

import sys


class PingResource:
    """A resource to verify the api is up and running"""

    def __init__(self):
        pass

    def on_get(self, req, resp):
        log_request(req)
        resp.body = '{ "hello": "world" }'


class AuthorizeResource:
    """Adapter for the authorization code grant process"""

    def __init__(self):
        pass

    def on_get(self, req, resp):
        auth_url = "https://sandbox.apihub.citi.com/gcb/api/authCode/oauth2/authorize"
        auth_url += "?response_type=code"
        auth_url += ("&client_id=" + req.get_param('client_id'))
        auth_url += ("&scope=" + "accounts_details_transactions")
        auth_url += "&countryCode=US"
        auth_url += "&businessCode=GCB"
        auth_url += "&locale=en_US"
        auth_url += ("&state=" + req.get_param('state'))
        auth_url += ("&redirect_uri=" + req.get_param('redirect_uri'))

        headers = {'Accept': req.accept}
        response = requests.get(auth_url, headers=headers, allow_redirects=False)

        falcon_req_logger.debug("STATUS CODE: " + str(response.status_code))
        for keys, values in response.headers.items():
            resp.set_header(keys, values)

        resp.set_header("Location", str("https://sandbox.apihub.citi.com") + response.headers.get('Location'))
        resp.status = str(response.status_code)
        resp.body = response.text


class TokenResource:
    """The resource invoked by Amazon when either a new token is requested or a token refresh is request"""

    def __init__(self):
        pass

    def on_post(self, req, resp):
        log_request(req)
        body = req.bounded_stream.read()
        falcon_req_logger.debug("BODY: %s", body)
        parsed_body = falcon.uri.parse_query_string(body)
        falcon_req_logger.debug("PARSED BODY: %s", parsed_body)
        grant_type = parsed_body["grant_type"]

        api_url = ""
        if grant_type == "authorization_code":
            api_url = "https://sandbox.apihub.citi.com/gcb/api/authCode/oauth2/token/us/gcb"
        elif grant_type == "refresh_token":
            api_url = "https://sandbox.apihub.citi.com/gcb/api/authCode/oauth2/refresh"
        else:
            resp.status = 500
            logging.debug("grant_type has an unknown value %s", grant_type)
            return

        # remote client_id form the dict
        parsed_body.pop('client_id', None)

        headers = {'Authorization': req.get_header('Authorization'), 'Content-Type': req.get_header('Content-Type')}
        response = requests.post(api_url, data=parsed_body, headers=headers)

        for names, values in response.headers.items():
            if names == "Vary" or names == "Content-Encoding":
                # skip the Vary and Content-Encoding header
                continue
            else:
                resp.set_header(names, values)

        resp.body = response.content
        resp.status = str(response.status_code)
        # log_response(resp)
        falcon_req_logger.debug("BODY: %s", response.content)


def log_response(resp):
    for keys, values in resp.headers.items():
        falcon_req_logger.debug("HEADER: %s, = %s", keys, str(values))


def log_request(req):
    """Logs query string and header info from falcon request object"""
    falcon_req_logger.debug("QUERY STRING: %s", req.query_string)
    for keys, values in req.headers.items():
        falcon_req_logger.debug("HEADER: %s, = %s", keys, values)


requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
HTTPConnection.debuglevel = 1

req_formatting = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
falcon_req_handler = logging.StreamHandler()
falcon_req_handler.setFormatter(req_formatting)
falcon_req_handler.setLevel(logging.DEBUG)
falcon_req_logger = logging.getLogger('requests')
falcon_req_logger.setLevel(logging.DEBUG)
falcon_req_logger.addHandler(falcon_req_handler)

api = falcon.API()
api.add_route('/ping', PingResource())
api.add_route('/authorize', AuthorizeResource())
api.add_route('/token', TokenResource())
