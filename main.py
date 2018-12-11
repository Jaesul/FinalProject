import urllib, urllib2, webbrowser, json
import jinja2
from google.appengine.api import urlfetch
from google.appengine.ext import db
import logging
import os
import base64
import Cookie
import email.utils
import hashlib
import hmac
import logging
import time
import webapp2
from secrets import STRAVA_APP_CLIENT_ID
from secrets import STRAVA_APP_SECRET

def pretty(obj):
    return json.dumps(obj, sort_keys=True, indent=2)

JINJA_ENVIRONMENT = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

class User(db.Model):
    created = db.DateTimeProperty(auto_now_add=True)
    updated = db.DateTimeProperty(auto_now=True)
    access_token = db.StringProperty(required=True)
    uid = db.StringProperty(required=True)
    name = db.StringProperty(required=True)


class BaseHandler(webapp2.RequestHandler):
    # @property followed by def current_user makes it so that if x is an instance
    # of BaseHandler, x.current_user can be referred to, which has the effect of
    # invoking x.current_user()
    @property
    def current_user(self):
        """Returns the logged in Strava user, or None if unconnected."""
        if not hasattr(self, "_current_user"):
            self._current_user = None
            # find the user_id in a cookie
            user_id = parse_cookie(self.request.cookies.get("strava_user"))
            if user_id:
                self._current_user = User.get_by_key_name(user_id)
        return self._current_user

class MainHandler(BaseHandler):
    def get(self):
        args = {'current_user': self.current_user}
        template = JINJA_ENVIRONMENT.get_template('StravaTemplate.html')
        self.response.write(template.render(args))

class LoginHandler(BaseHandler):
    def get(self):
        args = {'client_id': STRAVA_APP_CLIENT_ID}
        verification_code = self.request.get("code")
        if verification_code:
            user_verification_data = json.loads(getToken(verification_code))
            firstname = user_verification_data['athlete']['firstname']
            uid = user_verification_data['athlete']['id']
            access_token = user_verification_data['access_token']
            user = User(key_name=str(uid), uid=str(uid), name=str(firstname), access_token=str(access_token))
            user.put()
            set_cookie(self.response, "strava_user", str(uid), expires=time.time() + 30 * 86400)
            self.redirect('/')
        else:
            # not logged in yet-- send the user to Strava to do that
            args['redirect_uri'] = self.request.path_url
            args["scope"] = "activity:read_all,profile:read_all"
            args['client_id'] = STRAVA_APP_CLIENT_ID
            args['response_type'] = 'code'
            url = "https://www.strava.com/oauth/authorize?" + urllib.urlencode(args)
            self.redirect(url)

class StravaResultsHandler(BaseHandler):
    def post(self):
        logging.info('this is a post')
        search_input = self.request.get('ride_id')
        vals = {}
        vals['error'] = 'error'
        if search_input:
            current_user = self.current_user
            access_token = current_user.access_token
            data = json.loads(getRideData(str(search_input), access_token))
            slat = data['start_latitude']
            slong = data['start_longitude']
            elat = data['end_latlng']['0']
            elong = data['end_latlng']['1']
            vals['data'] = pretty(data)
            vals['ride_id'] = search_input
            template = JINJA_ENVIRONMENT.get_template('StravaResults.html')
            self.response.write(template.render(vals))
        else:
            vals['error'] = 'cannot get ride data without ride id'
            template = JINJA_ENVIRONMENT.get_template('StravaTemplate.html')
            self.response.write(template.render(vals))

class LogoutHandler(BaseHandler):
    def get(self):
        set_cookie(self.response, "strava_user", "", expires=time.time() - 86400)
        self.redirect("/")

def set_cookie(response, name, value, domain=None, path="/", expires=None):
    """Generates and signs a cookie for the give name/value"""
    timestamp = str(int(time.time()))
    value = base64.b64encode(value)
    signature = cookie_signature(value, timestamp)
    cookie = Cookie.BaseCookie()
    cookie[name] = "|".join([value, timestamp, signature])
    cookie[name]["path"] = path
    if domain: cookie[name]["domain"] = domain
    if expires:
        cookie[name]["expires"] = email.utils.formatdate(
            expires, localtime=False, usegmt=True)
    response.headers.add("Set-Cookie", cookie.output()[12:])

def parse_cookie(value):
    """Parses and verifies a cookie value from set_cookie"""
    if not value: return None
    parts = value.split("|")
    if len(parts) != 3: return None
    if cookie_signature(parts[0], parts[1]) != parts[2]:
        logging.warning("Invalid cookie signature %r", value)
        return None
    timestamp = int(parts[1])
    if timestamp < time.time() - 30 * 86400:
        logging.warning("Expired cookie %r", value)
        return None
    try:
        return base64.b64decode(parts[0]).strip()
    except:
        return None

def cookie_signature(*parts):
    """Generates a cookie signature.

    We use the STRAVA app secret since it is different for every app (so
    people using this example don't accidentally all use the same secret).
    """
    chash = hmac.new(STRAVA_APP_SECRET, digestmod=hashlib.sha1)
    for part in parts: chash.update(part)
    return chash.hexdigest()

def getToken(code):
    token_url = 'https://www.strava.com/oauth/token?'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    token_url_payload = {'grant_type': 'authorization_code', 'client_id': STRAVA_APP_CLIENT_ID, 'client_secret': STRAVA_APP_SECRET, 'code':code}
    data = urllib.urlencode(token_url_payload)
    response = urlfetch.fetch(url=token_url, payload=data, method=urlfetch.POST, headers=headers)
    return response.content

def getRideData(rideID, access_token, params=None):
    # header = {'Authorization': 'Bearer ' + accessToken}
    url = 'https://www.strava.com/api/v3/activities/' + str(rideID)
    # req = urllib2.Request(url)
    # req.add_header('Authorization', 'Bearer ' + str(accessToken))
    # resp = urllib2.urlopen(req)
    # content = resp.read()
    payload = {'Authorization': 'Bearer ' + access_token}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = urlfetch.fetch(url, method=urlfetch.GET, payload=payload, headers=headers)
    return response.content

application = webapp2.WSGIApplication([ \
     ("/auth/login", LoginHandler), ('/.*', MainHandler), ("/auth/logout", LogoutHandler),
    ('/stravaresults', StravaResultsHandler)
],
    debug=True)

# test = getRideData(1961462367, hello)
# print(pretty(test))

# print(pretty(rider_data))
# print("total number of calories during ride: %s" %calories)
# moving_time = float(rider_data['moving_time'])/(60*60)
# print("total hours spent moving: %s" %moving_time)

