"""
DuoAuth is a custom authentication class for the requests module.

It is basically a port of the official authentication (sign) function
to Python 3.

The best way to use it is with a Session object:

s = requests.Session()
s.auth = DuoAuth(skey=SKEY, ikey=IKEY)
"""

import base64
import email
import hashlib
import hmac
import urllib.parse
from requests.auth import AuthBase


class DuoAuth(AuthBase):
    """Attach HTTP Duo authentication to the given Request object."""

    def __init__(self, skey, ikey):
        self.skey = skey
        self.ikey = ikey

    def __call__(self, r):
        url = urllib.parse.urlparse(r.url)
        method = r.method.upper()
        host = url.netloc.lower()
        path = url.path
        if method == 'GET':
            params = urllib.parse.parse_qs(url.query)
        elif method == 'POST':
            params = urllib.parse.parse_qs(r.body)
        else:
            params = {}
        # create canonical string
        now = email.utils.formatdate()
        canon = [now, method, host, path]
        args = []
        for key in sorted(params.keys()):
            val = params[key][0]
            args.append('{}={}'.format(urllib.parse.quote(key.encode(), '~'),
                                       urllib.parse.quote(val.encode(), '~')))
        canon.append('&'.join(args))
        canon = '\n'.join(canon)

        # sign canonical string
        sig = hmac.new(self.skey.encode(), canon.encode(), hashlib.sha1)
        auth = '{}:{}'.format(self.ikey, sig.hexdigest())

        # add headers
        r.headers['Date'] = now
        r.headers['Authorization'] = 'Basic {}'.format(base64.b64encode(auth.encode()).decode())
        r.headers['Content-Type'] = 'application/x-www-form-urlencoded'

        return r
