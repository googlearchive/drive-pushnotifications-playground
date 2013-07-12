#  Copyright 2013 Google Inc. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import hashlib
import json
import os
import pickle
import urllib
import urlparse
import uuid
import logging

import httplib2
import jinja2
import webapp2
from webapp2_extras import sessions

from apiclient.discovery import build
from google.appengine.api import channel
from google.appengine.api import urlfetch
from oauth2client.client import AccessTokenRefreshError
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client.clientsecrets import loadfile

# Load client secrets from 'client_secrets.json' file.
CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secrets.json')
client_type, client_info = loadfile(CLIENT_SECRETS)
FLOW = flow_from_clientsecrets(
    CLIENT_SECRETS,
    scope=('https://www.googleapis.com/auth/drive '
           'https://www.googleapis.com/auth/userinfo.profile'),
    redirect_uri=client_info['redirect_uris'][0],)

# Load Jinja2 template environment.
JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__),
                                                'templates')),
    extensions=['jinja2.ext.autoescape'])


def ValidateCredential(function):
  """A decorator to validate credential."""
  def _decorated(self, *args, **kwargs):
    if 'credential' in self.session:
      # Load credential from session data.
      credential = pickle.loads(self.session.get('credential'))
      if credential.invalid:
        try:
          credential.refresh()
        except AccessTokenRefreshError:
          # When credential is invalid and refreshing fails, it returns 401.
          self.response.set_status(401)
          self.response.write('Unauthorized Access - Credential refresh failed')
          self.LogOut()
          return
        else:
          # Saves refreshed credential back to session data.
          self.session['credential'] = pickle.dumps(credential)
      function(self, *args, **kwargs)
    else:
      self.response.set_status(401)
      self.response.write('Unauthorized Access - User not logged in')
  return _decorated


class BaseHandler(webapp2.RequestHandler):
  """Base request handling class."""

  def dispatch(self):
    """Get a session store for this request."""
    self.session_store = sessions.get_store(request=self.request)
    try:
      # Dispatch the request.
      webapp2.RequestHandler.dispatch(self)
    finally:
      # Save all sessions.
      self.session_store.save_sessions(self.response)

  @webapp2.cached_property
  def session(self):
    """Return a session using key from the configuration."""
    return self.session_store.get_session()

  def CreateLogInUrl(self, state=''):
    """Return an oauth authorization url if user needs authorization.

    Args:
      state: string, state parameter of oauth2 request url.
    """
    login_url = None
    if 'credential' not in self.session:
      # Create OAuth2 authentication url with given state parameter.
      login_url = FLOW.step1_get_authorize_url()+'&state='+state
    return login_url

  def Unsubscribe(self, state, force_delete=False):
    """Unsubscribe from push notifications.

    Args:
      state: string, task to unsubscribe from.
      force_delete: boolean, force delete session even when unsubscribe fails.
    Returns:
      dict, containing result of unsubscribe request.
      dict['success'], boolean, True if unsubscribe request was successful.
      Additional following data when unsubscribe request failed.
      dict['error_code'], int, Status code of unsubscribe request.
      dict['error_msg'], string, Error message of unsubscribe request.
    """
    # Retrieve task-specific notification_id and resource_id
    notification_id = self.session.get('notification_id_{0}'.format(state))
    resource_id = self.session.get('resource_id_{0}'.format(state))
    # If not subscribed, return False
    if not (notification_id and resource_id):
      return False
    # Make unsubscribe request
    credential = pickle.loads(self.session.get('credential'))
    url = 'https://www.googleapis.com/drive/v2/channels/stop'
    headers = {
        'Authorization': 'Bearer {0}'.format(credential.access_token),
        'Content-Type': 'application/json',
        }
    data = {
        'id': notification_id,
        'resourceId': resource_id
        }
    form_data = json.dumps(data)
    result_raw = urlfetch.fetch(url=url,
                                payload=form_data,
                                method=urlfetch.POST,
                                headers=headers,
                                deadline=20)
    return_val = {}
    if result_raw.status_code/100==2:
      return_val['success'] = True
    else:
      return_val['success'] = False
      try:
        result = json.loads(result_raw.content)
      except ValueError:
        return_val['error_code'] = 500
        return_val['error_msg'] = 'Unexpected response from the server'
      else:
        error = result.get('error')
        if error:
          return_val['error_code'] = result_raw.status_code
          return_val['error_msg'] = str(error.get('message'))
        else:
          return_val['error_code'] = 500
          return_val['error_msg'] = 'Unexpected response from the server'
    if return_val['success'] or force_delete:
      # Delete subscription information from session
      del self.session['notification_id_{0}'.format(state)]
      del self.session['resource_id_{0}'.format(state)]
    return return_val

  def Render(self, template, template_values=None):
    """Renders Jinja2 template with template values and writes a response.

    In addition to given template values, it automatically passes 'state'
    which is a link for previous page user visited and 'login_url' which
    is None if user is logged in and OAuth authentication link otherwise.
    Also, it adds notification_id which saves temporary id of the
    notifications channel user is listening to.

    Args:
      template: string, filename of template file to render
      template_values: dict, values used to render the template
    """
    if not template_values:
      template_values = {}
    # Pass name of current page
    state = ''
    if template != 'index.html':
      state = os.path.splitext(template)[0]
    template_values['state'] = state
    # Pass notification_id of current page
    notification_id = 'notification_id_{0}'.format(state)
    template_values['notification_id'] = self.session.get(notification_id)
    # Pass login url
    template_values['login_url'] = self.CreateLogInUrl(state)
    token_name = 'token_{0}'.format(state)
    if token_name in self.session:
      template_values['channel_id'] = self.session.get(token_name)
    template = JINJA_ENVIRONMENT.get_template(template)
    self.response.write(template.render(template_values))

  def LogOut(self):
    """Unsubscribe and delete credential in session data."""
    if 'credential' in self.session:
      self.Unsubscribe('all', True)
      self.Unsubscribe('specific', True)
      del self.session['credential']


class IndexHandler(BaseHandler):
  """Request handling class for /."""

  def get(self):
    """GET request handling method.

    Parse template index.html with oauth login url.
    """
    self.Render('index.html')


class AllHandler(BaseHandler):
  """Request handling class for /all."""

  def get(self):
    """GET request handling method.

    Parse template all.html with oauth login url.
    """
    self.Render('all.html')


class SpecificHandler(BaseHandler):
  """Request handling class for /specific."""

  def get(self):
    """GET request handling method.

    Parse template specific.html with oauth login url.
    """
    self.Render('specific.html')


class SubscribeHandler(BaseHandler):
  """Request handling class for /subscribe."""

  @ValidateCredential
  def post(self):
    """POST request handling method.

    Make POST request to subscribe for Drive Files/Changes resources.
    Subscribe to files resources if file id is provided with POST['file_id'].
    Subscribe to changes resources if not.
    """
    # if POST['file_id'] is provided, request push notifications on files.
    if 'file_id' in self.request.POST:
      url = 'https://www.googleapis.com/drive/v2/files/{0}/watch'.format(
          self.request.POST.get('file_id'))
    # Otherwise, request push notifications on all changes of Drive.
    else:
      url = 'https://www.googleapis.com/drive/v2/changes/watch'
    # Prepare for push notifications request.
    credential = pickle.loads(self.session.get('credential'))
    state = self.request.POST.get('state')
    headers = {
        'Authorization': 'Bearer {0}'.format(credential.access_token),
        'Content-Type': 'application/json',
        }
    # Token data to deliver target channel id and state of notifications.
    token_data = {
        'channel_id': self.session.get('token_{0}'.format(state)),
        'state': self.request.POST.get('state')
        }
    token_string = urllib.urlencode(token_data)
    notification_id = str(uuid.uuid4())
    data = {
        'id': notification_id,
        'type': 'web_hook',
        'address': self.request.host_url+'/notificationcallback',
        'token': token_string,
        'params': {'ttl': 1800}
        }
    form_data = json.dumps(data)
    # Make POST request to subscribe to push notifications
    result_raw = urlfetch.fetch(url=url,
                                payload=form_data,
                                method=urlfetch.POST,
                                headers=headers,
                                deadline=20)
    logging.info('response body: '+str(result_raw.content))
    try:
      result = json.loads(result_raw.content)
    except ValueError:
      self.response.set_status(500)
      self.response.write('Unexpected response from the server')
    else:
      if result_raw.status_code/100==2:
        self.session['notification_id_{0}'.format(state)] = notification_id
        self.session['resource_id_{0}'.format(state)] = result['resourceId']
        response = {
            'notification_id': notification_id
            }
        self.response.write(json.dumps(response))
      else:
        error = result.get('error')
        if error:
          self.response.set_status(result_raw.status_code)
          self.response.write(str(error.get('message')))
        else:
          self.response.set_status(500)
          self.response.write('Unexpected response from the server')
        if result_raw.status_code==401:
          self.LogOut()


class UnsubscribeHandler(BaseHandler):
  """Request handling class for /unsubscribe."""

  @ValidateCredential
  def post(self):
    """POST request handling method.

    Unsubscribe from push notifications.
    Return 500 error when it fails for unknown reason.
    """
    result = self.Unsubscribe(self.request.POST.get('state'))
    if not result['success']:
      self.response.set_status(result['error_code'])
      self.response.write(result['error_msg'])
      if result['error_code']==401:
        self.LogOut()


class NotificationCallbackHandler(BaseHandler):
  """Request handling class for /notification."""

  def post(self):
    """POST request handling method.

    Log header and body of incoming notifications.
    """
    logging.info('header: '+str(self.request.headers))
    logging.info('body: '+str(self.request.body))
    # Ignore sync message.
    if self.request.headers['X-Goog-Resource-State'] == 'sync':
      return
    data = {
        'notification_id': self.request.headers['X-Goog-Channel-ID'],
        'resource_state': self.request.headers['X-Goog-Resource-State'],
        'expiration': self.request.headers['X-Goog-Channel-Expiration']
        }
    # Parse Token string to get channel_id and state.
    token_string = self.request.headers['X-Goog-Channel-Token']
    token = dict(urlparse.parse_qsl(token_string))
    channel_id = token['channel_id']
    state = token['state']
    if state == 'all':
      data['self_link'] = json.loads(self.request.body).get('selfLink')
    else:
      data['self_link'] = self.request.headers['X-Goog-Resource-Uri']
      try:
        data['changed'] = self.request.headers['X-Goog-Changed']
      except KeyError:
        pass
    # Send useful data back to the user.
    channel.send_message(channel_id, json.dumps(data))


class OAuth2CallbackHandler(BaseHandler):
  """Request handling class for /oauth2callback."""

  def get(self):
    """GET request handling method.

    Receive authentication code from user with GET['code'].
    Save credential if code exchange is successful.
    Redirect to previous page user visited.
    """
    if 'code' in self.request.GET:
      try:
        credential = FLOW.step2_exchange(self.request.GET.get('code'))
      except FlowExchangeError:
        pass
      else:
        # Save credential to session data if code exchange succeeded.
        self.session['credential'] = pickle.dumps(credential)
        # Retrieve basic information about the user
        http = httplib2.Http()
        http = credential.authorize(http)
        users_service = build('oauth2', 'v2', http=http)
        user_document = users_service.userinfo().get().execute()
        # Create channel to push results back to the user
        channel_id = hashlib.sha1(user_document['id']).hexdigest()
        token_all = channel.create_channel(channel_id+'all')
        token_specific = channel.create_channel(channel_id+'specific')
        self.session['token_all'] = token_all
        self.session['token_specific'] = token_specific
    self.redirect('/'+(self.request.GET.get('state') or ''))


class LogOutHandler(BaseHandler):
  """Request handling class for /logout."""

  def get(self):
    """GET request handling method.

    Delete credential from session data.
    Redirect to previous page user visited.
    """
    self.LogOut()
    self.redirect('/'+(self.request.GET.get('state') or ''))

# Configure secret key for session.
config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': hashlib.sha512(FLOW.client_secret).hexdigest()
}
# Configure url handler for webapp2.
handler = webapp2.WSGIApplication([
    ('/', IndexHandler),
    ('/all', AllHandler),
    ('/specific', SpecificHandler),
    ('/subscribe', SubscribeHandler),
    ('/unsubscribe', UnsubscribeHandler),
    ('/notificationcallback', NotificationCallbackHandler),
    ('/oauth2callback', OAuth2CallbackHandler),
    ('/logout', LogOutHandler),
], config=config, debug=True)
