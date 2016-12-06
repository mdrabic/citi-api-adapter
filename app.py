# app.py
import urllib2
import falcon


class PingResource:
    """A resource to verify the api is up and running"""

    def __init__(self):
        pass

    def on_get(self, req, resp):
        resp.body = '{ "hello": "world" }'


class AuthorizeResource:
    """Adapter for the authorization code grant process"""
    def __init__(self):
        pass

    def on_get(self, req, resp):
        print "INCOMING: " + req.url
        auth_url = "https://sandbox.apihub.citi.com/gcb/api/authCode/oauth2/authorize"
        auth_url += "?response_type=code"
        auth_url += ("&client_id=" + req.get_param('client_id'))
        auth_url += "&scope=customers_profiles"
        auth_url += "&countryCode=US"
        auth_url += "&businessCode=GCB"
        auth_url += "&locale=en_US"
        auth_url += ("&state=" + req.get_param('state'))
        auth_url += ("&redirect_uri=" + req.get_param('redirect_uri'))

        print "AUTH URL: " + auth_url
        response = urllib2.urlopen(auth_url)
        resp.body = response.read()

api = falcon.API()
api.add_route('/ping', PingResource())
api.add_route('/authorize', AuthorizeResource())