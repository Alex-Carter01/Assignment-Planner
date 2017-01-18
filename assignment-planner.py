import webapp2
import logging
import re
import cgi
import jinja2
import os
import random
import time
import string
import hashlib
import hmac
import Cookie 
from google.appengine.ext import db
import sys
import urllib2
import socket
import select
import json
from xml.dom import minidom


toolbar = """
 <a class="tool-link" href="/">home </a>|
 <a class="tool-link" href="/agenda">agenda </a>|
 <a class="tool-link" href="/logout">logout</a>
 """

toolbar2 = """
  <a class="tool-link" href="/">home </a>|
  <a class="tool-link" href="/login">login </a>|
  <a class="tool-link" href="/signup">signup</a>
"""

## see http://jinja.pocoo.org/docs/api/#autoescaping
def guess_autoescape(template_name):
   if template_name is None or '.' not in template_name:
      return False
      ext = template_name.rsplit('.', 1)[1]
      return ext in ('xml', 'html', 'htm')

JINJA_ENVIRONMENT = jinja2.Environment(
   autoescape=guess_autoescape,     ## see http://jinja.pocoo.org/docs/api/#autoxscaping
   loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
   extensions=['jinja2.ext.autoescape'])

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")  # 3-20 characters (A-Za-z0-9_-)
def valid_username(username):
   return USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{4,20}$")          # 4-20 characters (any)
def valid_password(username):
   return PASSWORD_RE.match(username)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(username):
   return EMAIL_RE.match(username)

class Handler(webapp2.RequestHandler):
   def write(self, *items):    
      self.response.write(" : ".join(items))

   def render_str(self, template, **params):
      tplt = JINJA_ENVIRONMENT.get_template('templates/'+template)
      return tplt.render(params)

   def render(self, template, **kw):
      self.write(self.render_str(template, **kw))

def make_salt():
   return ''.join(random.choice(string.hexdigits) for _ in range(25))

def make_pw_hash(name, pw, salt=None):
   if not salt:
      salt = make_salt()
   return hashlib.sha256(name+pw+salt).hexdigest()+'|'+salt

def valid_pw(name, pw, h):
   salt = h.split('|')[1]
   return h == make_pw_hash(name, pw, salt)

def hash_str(s):
   return hmac.new(str(s)).hexdigest()

def make_secure_val(s):
   return s+'|'+hash_str(s)

def check_secure_val(h):
   val = h.split('|')[0]
   if (h == make_secure_val(val)):
      return val

WEBSITE_REGEX = re.compile(r"^(http|https)://www[.]")
def valid_url(url):
    logging.info("*** regex match: "+str(bool(WEBSITE_REGEX.match(url))))
    return bool(WEBSITE_REGEX.match(url))

def check_login_handle(self):
   cook = self.request.cookies.get('user_id','0')
   if check_secure_val(cook):
      #user is logged in
      us_id = cook.split('|')[0]
      user = MyUsers.get_by_id(int(us_id))
      return user
   else:
      #user is not logged in
      self.redirect('/')
      time.sleep(0.2)
      return False

class MyUsers(db.Model):
   username   = db.StringProperty()   
   pwhashsalt = db.StringProperty()
   email      = db.StringProperty()
   created    = db.DateTimeProperty(auto_now_add = True)

class MainPage(Handler):
   def get(self):
      logging.info("********** MainPage GET **********")
      cook = self.request.cookies.get('user_id','0')
      if check_secure_val(cook):
         #user is logged in1
         us_id = cook.split('|')[0]
         username = MyUsers.get_by_id(int(us_id))
      else:
         #user is not logged in
         username =  False
      self.render("home.html", username=username, toolbar = toolbar, toolbar2 = toolbar2)

class Agenda(Handler):
  def get(self):
    logging.info("enter assignment/calendar get req")
    username = check_login_handle(self)

  def post(self):
    logging.info("enter agenda post handler")

class SignUp(Handler):
   def write_signup(self, username_error_msg="", password_error_msg="", verify_error_msg="", \
                    email_error_msg="", user_username="", user_email=""):
      cook = self.request.cookies.get('user_id','0')
      if check_secure_val(cook):
         #user is logged in
         us_id = cook.split('|')[0]
         user = MyUsers.get_by_id(int(us_id))
         self.redirect('|')#they are already logged in 
      else:
         template_values = {'error_username': username_error_msg,
                            'error_password': password_error_msg,
                            'error_verify'  : verify_error_msg,
                            'error_email'   : email_error_msg,
                            'username_value': user_username,
                            'email_value'   : user_email}
         self.render("signup.html", toolbar = toolbar, toolbar2 = toolbar2)

   def get(self):
      logging.info("********** SignUp Page GET **********")
      self.write_signup()

   def post(self):
      logging.info("********** SignUp Page POST **********")
      user_username = self.request.get('username')
      user_password = self.request.get('password')
      user_verify   = self.request.get('verify')
      user_email    = self.request.get('email')

      user_username_v = valid_username(user_username)
      user_password_v = valid_password(user_password)
      user_verify_v   = valid_password(user_verify)
      user_email_v    = valid_email(user_email)

      username_error_msg = password_error_msg = verify_error_msg = email_error_msg = ""
      if not(user_username_v):
         username_error_msg = "That's not a valid username."

      if (user_password != user_verify):
         password_error_msg = "Passwords do not match."
      elif not(user_password_v):
         password_error_msg = "That's not a valid password."
         if (user_email != "") and not(user_email_v):
            email_error_msg = "That's not a valid email."

      ## this should also work   userQuery = db.GqlQuery("SELECT * FROM MyUsers WHERE username = :1", user_username)      
      userQuery = db.GqlQuery("SELECT * FROM MyUsers WHERE username = '%s'" % user_username)
      if not(userQuery.count() == 0 or userQuery.count() == 1): 
         logging.info("***DBerr(signup) username = " + user_username + " (count = " + str(userQuery.count()) + ")" )
      user = userQuery.get() ## .get() returns Null if no results are found for the database query

      if user and user.username == user_username:   ## not really necessay to see if usernames are equal, since query would only have returned if there was a match
         user_username_v = False
         username_error_msg = "That user already exists."

      if not(user_username_v and user_password_v and user_verify_v and ((user_email == "") or user_email_v) and (user_password == user_verify)):
         self.write_signup(username_error_msg, password_error_msg, verify_error_msg, \
                           email_error_msg, user_username, user_email)
      else:
         pw_hash = make_pw_hash(user_username, user_password)
         u = MyUsers(username=user_username, pwhashsalt=pw_hash, email=user_email)
         u.put()
         id = u.key().id()
         self.response.headers.add_header('Set-Cookie', 'user_id=%s; Max-Age=604800; Path=/' % make_secure_val(str(id)))
         self.redirect("/")


class LogIn(Handler):
   def write_login(self, error=""):
      self.render("login.html", toolbar = toolbar, toolbar2 = toolbar2)

   def get(self):
      logging.info("********** LogIn Page GET **********")
      cook = self.request.cookies.get('user_id','0')
      if check_secure_val(cook):
         #user is logged in
         us_id = cook.split('|')[0]
         user = MyUsers.get_by_id(int(us_id))
         self.redirect('|')#they are already logged in 
      else:
         self.write_login()

   def post(self):
      logging.info("***DBG: LogIn Page POST")
      user_username = self.request.get('username')
      user_password = self.request.get('password')   
      userQuery = db.GqlQuery("SELECT * FROM MyUsers WHERE username = '%s'" % user_username)
      if not(userQuery.count() == 0 or userQuery.count() == 1): 
         logging.info("***DBerr (login) username = " + user_username + " (count = " + str(userQuery.count()) + ")" )
      user = userQuery.get() ## .get() returns Null if no results are found for the database query
      logging.info(">>> username=" + str(user_username) + " type=" + str(type(user_username)))             
      if user and user.username == user_username and valid_pw(user_username,user_password,user.pwhashsalt):  ## not really necessay to see if usernames are equal, since query would only have returned if there was a match
         id = user.key().id()
         self.response.headers.add_header('Set-Cookie', 'user_id=%s; Max-Age=604800;Path=/' % make_secure_val(str(id)))
         self.redirect("/")
      else:
         self.write_login("Invalid login")

class LogoutPage(Handler):
   def get(self):
      self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
      self.redirect("/")

application = webapp2.WSGIApplication([
   ('/', MainPage),
   (r'/agenda/?', Agenda),
   (r'/signup/?', SignUp),
   (r'/login/?', LogIn),
   (r'/logout/?', LogoutPage),
], debug=True)
