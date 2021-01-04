#!/usr/bin/env python
"""A demonstration of how to use asyncio-portier with Tornado.

A mashup of https://github.com/tornadoweb/tornado/tree/master/demos/blog and
https://github.com/portier/demo-rp/blob/master/server.py
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlencode
from uuid import uuid4

import fakeredis.aioredis
import tornado.ioloop
import tornado.locks
from tornado.options import define, options
import tornado.web

from asyncio_portier import get_verified_email
from asyncio_portier.cache import AsyncCache

define('port', default=8888, help='run on the given port', type=int)

broker_url = 'https://broker.portier.io'
parent_path = Path(__file__) / '..'


class Application(tornado.web.Application):
    """The Application class for the server."""

    def __init__(self, cache: AsyncCache) -> None:
        """Define the endpoints and application settings."""
        self.cache = cache
        handlers: tornado.routing._RuleList = [
            (r'/', IndexHandler),
            (r'/login', LoginHandler),
            (r'/verify', VerifyHandler),
            (r'/logout', LogoutHandler),
            (r'/requires-authentication', RequiresAuthenticationHandler)]
        settings: dict[str, Any] = {
            'template_path': parent_path / 'templates',
            'xsrf_cookies': True,
            'cookie_secret': '__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__',
            'login_url': '/login',
            'debug': True}
        super(Application, self).__init__(handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    """The base class for handlers."""

    application: Application
    audience = f'http://localhost:{options.port}'

    @property
    def cache(self) -> AsyncCache:
        """Return the application's aioredis cache."""
        return self.application.cache

    def get_current_user(self) -> Optional[bytes]:
        """Define current_user in templates."""
        return self.get_secure_cookie('user_email')


class IndexHandler(BaseHandler):
    """The handler for the site index."""

    def get(self) -> None:
        """Render the homepage."""
        # Check if the user has a session cookie
        if self.current_user:
            self.render('verified.html')
            return
        self.render('index.html', next_page=self.get_argument('next', '/'))


class LoginHandler(BaseHandler):
    """The handler for the login endpoint."""

    def get(self) -> None:
        """Redirect GET /login to /."""
        url = '/'
        if (next_page := self.get_argument('next', None)) is not None:
            url += f'?next={next_page}'
        self.redirect(url)

    async def post(self) -> None:
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
        expire = timedelta(minutes=15).seconds
        await self.cache.set(f'portier:nonce:{nonce}', next_page, expire=expire)

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

    def check_xsrf_cookie(self) -> None:
        """Disable XSRF check.

        OpenID doesn't reply with _xsrf header.
        https://github.com/portier/demo-rp/issues/10
        """
        pass

    def get(self) -> None:
        """Redirect GET /verify to /."""
        self.redirect('/')

    async def post(self) -> None:
        """Validate an Identity Token and log the user in.

        If the token is valid and signed by a trusted broker, you can directly
        log the user into the site, just like you would if you had verified a
        password.

        Normally, this would include setting a signed, http-only session
        cookie.
        """
        # Check for an error coming from the upstream broker
        if (error := self.get_argument('error', None)) is not None:
            msg = f'Broker Error ({error})'
            if (desc := self.get_argument('error_description', None)) is not None:
                msg += f': {desc}'
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
                self.cache)
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

    def get(self) -> None:
        """Display a button that POSTS to /logout."""
        self.render('logout.html')

    def post(self) -> None:
        """Clear session cookies."""
        self.clear_cookie('user_email')
        self.redirect('/')


class RequiresAuthenticationHandler(BaseHandler):
    """The handler for an example endpoint requiring authentication."""

    @tornado.web.authenticated
    def get(self) -> None:
        """Render the example endpoint."""
        self.render('requires-authentication.html')


async def main() -> None:
    """Start the server."""
    cache = await fakeredis.aioredis.create_redis_pool()
    app = Application(cache)
    app.listen(options.port)
    shutdown_event = tornado.locks.Event()
    print('Web server running at http://localhost:{}'.format(options.port))
    await shutdown_event.wait()


if __name__ == '__main__':
    tornado.ioloop.IOLoop.current().run_sync(main)
