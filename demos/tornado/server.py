#!/usr/bin/env python
"""A demonstration of how to use asyncio-portier with Tornado.

A mashup of https://github.com/tornadoweb/tornado/tree/master/demos/blog and
https://github.com/portier/demo-rp/blob/master/server.py
"""
from asyncio import get_event_loop
from datetime import timedelta
from os import path
from urllib.parse import urlencode
from uuid import uuid4

import fakeredis
from tornado.options import define, options
from tornado.platform.asyncio import AsyncIOMainLoop
import tornado.web

from asyncio_portier import get_verified_email

define('port', default=8888, help='run on the given port', type=int)

broker_url = 'https://broker.portier.io'
here = path.abspath(path.dirname(__file__))
cache = fakeredis.FakeStrictRedis()


class Application(tornado.web.Application):
    """The Application class for the server."""

    def __init__(self):
        """Define the endpoints and application settings."""
        handlers = [
            (r'/', IndexHandler),
            (r'/login', LoginHandler),
            (r'/verify', VerifyHandler),
            (r'/logout', LogoutHandler),
            (r'/requires-authentication', RequiresAuthenticationHandler)]
        settings = {
            'template_path': path.join(here, 'templates'),
            'xsrf_cookies': True,
            'cookie_secret': '__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__',
            'login_url': '/login',
            'debug': True}
        super(Application, self).__init__(handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    """The base class for handlers."""

    audience = 'http://localhost:{}'.format(options.port)

    def get_current_user(self):
        """Define current_user in templates."""
        return self.get_secure_cookie('user_email')


class IndexHandler(BaseHandler):
    """The handler for the site index."""

    def get(self):
        """Render the homepage."""
        # Check if the user has a session cookie
        if self.current_user:
            self.render('verified.html')
            return
        self.render('index.html', next_page=self.get_argument('next', '/'))


class LoginHandler(BaseHandler):
    """The handler for the login endpoint."""

    def get(self):
        """Redirect GET /login to /."""
        url = '/'
        next_page = self.get_argument('next', None)
        if next_page is not None:
            url += '?next={}'.format(next_page)
        self.redirect(url)

    def post(self):
        """Redirect to the broker to begin an Authentication Request.

        The specific parameters used in the Authentication Request are
        described in the OpenID Connect `Implicit Flow`_ spec, which Portier
        brokers implement.

        To prevent replay attacks, each Authentication Request is tagged with a
        unique nonce. This nonce is echoed back via the broker during user
        login.
        .. _Implicit Flow:
            https://openid.net/specs/openid-connect-core-1_0.html
            #ImplicitFlowAuth
        """
        # Generate and store a nonce for this authentication request
        nonce = uuid4().hex
        next_page = self.get_argument('next', '/')
        expiration = timedelta(minutes=15)
        cache.set('portier:nonce:{}'.format(nonce), next_page, expiration)

        # Forward the user to the broker, along with all necessary parameters
        query_args = urlencode({
            'login_hint': self.get_argument('email'),
            'scope': 'openid email',
            'nonce': nonce,
            'response_type': 'id_token',
            'response_mode': 'form_post',
            'client_id': self.audience,
            'redirect_uri': self.audience + '/verify'})
        self.redirect(broker_url + '/auth?' + query_args)


class VerifyHandler(BaseHandler):
    """The handler for Portier verification endpoint."""

    def check_xsrf_cookie(self):
        """Disable XSRF check.

        OpenID doesn't reply with _xsrf header.
        https://github.com/portier/demo-rp/issues/10
        """
        pass

    def get(self):
        """Redirect GET /verify to /."""
        self.redirect('/')

    async def post(self):
        """Validate an Identity Token and log the user in.

        If the token is valid and signed by a trusted broker, you can directly
        log the user into the site, just like you would if you had verified a
        password.

        Normally, this would include setting a signed, http-only session
        cookie.
        """
        # Check for an error coming from the upstream broker
        error = self.get_argument('error', None)
        if error is not None:
            description = self.get_argument('error_description', None)
            msg = 'Broker Error ({})'.format(error)
            if description is not None:
                msg += ': {}'.format(description)
            self.set_status(400)
            self.render('error.html', error=msg)
            return

        # Get the user's signed identity token from the HTTP POST form data
        token = self.get_argument('id_token')

        # Check the validity and authenticity of the identity token
        try:
            email, next_page = await get_verified_email(
                broker_url,
                token,
                self.audience,
                broker_url,
                cache)
        except ValueError as exc:
            self.set_status(400)
            self.render('error.html', error=exc)
            return

        # Done logging in! Set a session cookie with the following properties:
        # - It should be cryptographically signed to prevent tampering.
        # - It should be marked 'http-only' to prevent exfiltration via XSS.
        # - If possible, it should be marked 'secure' so it's only sent via
        # HTTPS.
        self.set_secure_cookie(
            'user_email', email, httponly=True,
            # We're not using HTTPS on localhost, but we would otherwise
            secure=False,
        )
        self.redirect(next_page)


class LogoutHandler(BaseHandler):
    """The handler for logout endpoint."""

    def get(self):
        """Display a button that POSTS to /logout."""
        self.render('logout.html')

    def post(self):
        """Clear session cookies."""
        self.clear_cookie('user_email')
        self.redirect('/')


class RequiresAuthenticationHandler(BaseHandler):
    """The handler for an example endpoint requiring authentication."""

    @tornado.web.authenticated
    def get(self):
        """Render the example endpoint."""
        self.render('requires-authentication.html')


def main():
    """Start the server."""
    AsyncIOMainLoop().install()
    Application().listen(options.port)
    print('Web server running at http://localhost:{}'.format(options.port))
    get_event_loop().run_forever()


if __name__ == '__main__':
    main()
