import os
import webapp2
import jinja2
import re
import hashlib
import hmac
import random
from string import letters

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'supercalifraglisticspalidoesous'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_val(secure_val):
    val = secure_val.split("|")[0]
    if secure_val == make_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def make_cookie(self, name, val):
        cookie_val = make_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_val(cookie_val)

    def login(self, user):
        self.make_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)
    

class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, everyone!')

##### security
def create_salt(length = 10):
    return ''.join(random.choice(letters) for x in xrange(length))

def create_hash(name, pw, salt = None):
    if not salt:
        salt = create_salt()
    y = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, y)

def valid_pw(name, password, y):
    salt = y.split(',')[0]
    return y == create_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = create_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

#### blog pages

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p = self)

class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery('select * from Post order by created desc limit 10')
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render('permalink.html', post = post)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/login')
            
    def post(self):
        if not self.user:
            self.redirect('/blog')
            
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = 'Need subject and content, please!'
            self.render('newpost.html', subject=subject, content=content, error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_name(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_pw(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

#### become new member
class Signup(BlogHandler):
    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        
        params = dict(username = self.username,
                      email = self.email)

        if not valid_name(self.username):
            params['error_username'] = 'Not a valid username.'
            have_error = True

        if not valid_pw(self.password):
            params['error_password'] = 'Not a valid password.'
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = 'Your password did not match.'
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = 'Not a valid email.'
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()
        
    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
#### is name already taken
        u = User.by_name(self.username)
        if u:
            msg = 'That name is in use.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/blog')
            
class Login(BlogHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Login not valid'
            self.render('login.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
                               
