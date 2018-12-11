import urllib, urllib2, json
import jinja2
import logging
import os
import webapp2
from secrets import STRAVA_APP_CLIENT_ID
from secrets import STRAVA_APP_SECRET


JINJA_ENVIRONMENT = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

def pretty(obj):
    return json.dumps(obj, sort_keys=True, indent=2)

# access_token = str(open('Strava_token.txt').read())
# print(access_token)
# #Parameter for the API call
# header = {'Authorization:':access_token}
# url = 'https://www.strava.com/api/v3/activities/1995217707'
# header = {'Authorization': access_token}
# print(pretty(r.get(url, headers=header).json()))

#Makes the dictionary readable

#Retreiving data from API
# This method gets the bearer token from Strava given the slient id and the client secret. Takes parameter client_id

def getToken(code):
    token_url = 'https://www.strava.com/oauth/token?'
    headers = {'grant_type':'authorization_code'}
    token_url_payload = {'client_id':STRAVA_APP_CLIENT_ID, 'client_secret': STRAVA_APP_SECRET, 'code':code}
    data = urllib.urlencode(token_url_payload)
    request = urllib2.Request(token_url, data)
    token_data = urllib2.urlopen(request)
    return json.load(token_data)
#
# # def refreshToken():
# def refreshToken():
#     url = 'https://www.strava.com/oauth/token'
#     req = urllib2.Request(url)
#     req.add_header('client_id', 'string')
#     req.add_header('client_secret', 'string')
#     req.add_header('grant_type', 'refresh_token')
#     req.add_header('refresh_token', 'string')
#     resp = urllib2.urlopen(req)
#     content = resp.read()
#     return json.load(content)

# print(pretty(refreshToken()))
#
# 'c3834a2c3c0e4e5476015e209e525acb8dce8bd2'
# 780513704
# 29924
print(pretty(getToken('1b4f326fe918855f091682a51c1d1c60b535f260')))

def getRideData(rideID, accessToken):

    # header = {'Authorization': 'Bearer ' + accessToken}
    url = 'https://www.strava.com/api/v3/activities/' + str(rideID)
    req = urllib2.Request(url)
    req.add_header('Authorization', 'Bearer ' + accessToken)
    req.add_header('include_all_efforts', False)
    resp = urllib2.urlopen(req)
    content = resp.read()
    return json.loads(content)
    # print(token_url)
    # req = urllib2.Request(token_url)
    # req.add_header('Authorization', 'Bearer access_token')
    # data = urllib.urlencode(header)
    # url = token_url + data

    # return r.get(url, headers=header).json()

# print(pretty(getRideData('1995217707', '8281c610e7f4642c364b39e6bc95cf2f9327dfbc')))


    # URL = 'https://www.strava.com/api/v3/activities/' + str(rideID)
    # access_token = 'Bearer ' + accessToken
    # print(access_token)
    # header = {'Authorization': access_token}
    # return r.get(url=URL, params=header).json()

# access_token = str(open('Strava_token.txt').read())
#
# data=getRideData('1995217707',access_token)
#
# vals = {}
# vals['calories'] : data['calories']

class MainHandler(webapp2.RequestHandler):
    def get(self):
        template_values = {}
        template = JINJA_ENVIRONMENT.get_template('StravaTemplate.html')
        self.response.write(template.render(template_values))
        # vals = {}
        # vals['title'] = "tester'"
        # template = JINJA_ENVIRONMENT.get_template('StravaTemplate.html')
        # self.response.write(template.render(vals))

class LoginHandler(webapp2.RequestHandler):
    def get(self):
        args = {'client_id': STRAVA_APP_CLIENT_ID}
        verification_code = self.request.get("code")
        print(verification_code)
        if verification_code:
            # after successful login; redirected here with code;

            # use code to get the access_token from Strava
            args["client_id"] = STRAVA_APP_CLIENT_ID
            args["client_secret"] = STRAVA_APP_SECRET
            args["code"] = self.request.get("code")
            args['redirect_uri'] = self.request.path_url
            args['grant_type'] = 'authorization_code'
            url = "https://www.strava.com/oauth/token" + urllib.urlencode(args)
            logging.info(url)
            response = urllib.urlopen(url).read()

            # get the access token & user_id
            response_dict = json.loads(response)
            access_token = response_dict["access_token"]
            user_id = response_dict['user_id']

        else:
            # not logged in yet-- send the user to Strava to do that
            args['redirect_uri'] = self.request.path_url
            args["scope"] = "activity:read_all,profile:read_all"
            args['client_id'] = STRAVA_APP_CLIENT_ID
            args['response_type'] = 'code'
            url = "https://www.strava.com/oauth/authorize?" + urllib.urlencode(args)
            self.redirect(url)

# class StravaResultsHandler(webapp2.RedirectHandler):
#     def post(self):
#         search_input = self.request.get('ride_id')
#         vals = {}
#         if search_input:
#             access_token = str(open('Strava_token.txt').read())
#             data = getRideData(str(search_input), 'fcdcdad3a74e9ee6591d1d1615033700f169761a')
#             vals['calories'] = data['calories']
#             template = JINJA_ENVIRONMENT.get_template('StravaResults.html')
#             self.response.write(template.render(vals))
#         else:
#             vals['prompt'] = 'cannot get ride data without ride id'
#             template = JINJA_ENVIRONMENT.get_template('StravaTemplate.html')
#             self.response.write(template.render(vals))
#
# # hello = open("stravaoutput.html", "w")
# # template = JINJA_ENVIRONMENT.get_template('flickrsearchform.html')
# # hello.response.write(template.render(vals))

application = webapp2.WSGIApplication([ \
     ("/auth/login", LoginHandler),
    ('/.*', MainHandler)
],
    debug=True)

# test = getRideData(1961462367, hello)
# print(pretty(test))

# print(pretty(rider_data))
# print("total number of calories during ride: %s" %calories)
# moving_time = float(rider_data['moving_time'])/(60*60)
# print("total hours spent moving: %s" %moving_time)




