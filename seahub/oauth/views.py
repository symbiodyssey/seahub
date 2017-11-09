# -*- coding: utf-8 -*-

import os
import logging
from constance import config
from requests_oauthlib import OAuth2Session
from django.http import HttpResponseRedirect
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.core.urlresolvers import reverse
from django.core.cache import cache
from django.utils.translation import ugettext as _

from seahub import auth

import seahub.settings as settings

if getattr(settings, 'ENABLE_OAUTH_INSECURE_TRANSPORT', False):
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

logger = logging.getLogger(__name__)

class Oauth2(object):

    CLIENT_ID = ''
    CLIENT_SECRET= ''
    AUTHORIZATION_BASE_URL = ''
    TOKEN_URL = ''
    REDIRECT_URI = ''
    SCOPE = []
    USER_INFO_URL = ''

    def __init__(self):

        self.CLIENT_ID = getattr(settings,
                'OAUTH_CLIENT_ID', None)

        self.CLIENT_SECRET = getattr(settings,
                'OAUTH_CLIENT_SECRET', None)

        self.AUTHORIZATION_BASE_URL = getattr(settings,
                'OAUTH_AUTHORIZATION_URL', 'http://192.168.1.114:8000/o/authorize/')

        self.REDIRECT_URI = getattr(settings,
                'OAUTH_REDIRECT_URL', '%s/oauth/callback/' % config.SERVICE_URL)

        self.TOKEN_URL = getattr(settings,
                'OAUTH_TOKEN_URL', 'http://192.168.1.114:8000/o/token/')

        self.USER_INFO_URL = getattr(settings,
                'OAUTH_USER_INFO_URL', 'http://192.168.1.114:8000/users/2/')

        self.session = OAuth2Session(client_id=self.CLIENT_ID,
                redirect_uri=self.REDIRECT_URI)

    def get_authorization_url_and_state(self):

        authorization_url, state = self.session.authorization_url(
                self.AUTHORIZATION_BASE_URL)

        return authorization_url, state

    def get_access_token(self, state, authorization_response):

        self.session.fetch_token(
                self.TOKEN_URL, client_secret=self.CLIENT_SECRET,
                authorization_response=authorization_response)

    def get_user_info(self):

        user_info = {
            'email': '',
            'name': '',
            'contact_email': '',
        }

        user_info_response = self.session.get(self.USER_INFO_URL)
        email = user_info_response.json().get('email')
        user_info['email'] = email

        return user_info

oauth = Oauth2()

def oauth_login(request):
    """Step 1: User Authorization.
    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """

    try:
        authorization_url, state = oauth.get_authorization_url_and_state()
    except Exception as e:
        logger.error(e)
        return render_to_response('error.html', {
                'error_msg': _('Internal Server Error'),
                }, context_instance=RequestContext(request))

    cache_key = 'oauth_state_cache_key'
    cache.set(cache_key, state, 24 * 60 * 60)

    return HttpResponseRedirect(authorization_url)

# Step 2: User authorization, this happens on the provider.
def oauth_callback(request):
    """ Step 3: Retrieving an access token.
    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """

    cache_key = 'oauth_state_cache_key'
    state = cache.get(cache_key)

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    try:
        oauth.get_access_token(state, request.get_full_path())
        user_info = oauth.get_user_info()
    except Exception as e:
        logger.error(e)
        return render_to_response('error.html', {
                'error_msg': _('Internal Server Error'),
                }, context_instance=RequestContext(request))


    # seahub authenticate user
    email = user_info['email']
    user = auth.authenticate(remote_user=email)

    if not user or not user.is_active:
        # a page for authenticate user failed
        return HttpResponseRedirect(reverse('libraries'))

    # User is valid.  Set request.user and persist user in the session
    # by logging the user in.
    request.user = user
    auth.login(request, user)
    user.set_unusable_password()
    user.save()

    # redirect user to home page
    return HttpResponseRedirect(reverse('libraries'))
