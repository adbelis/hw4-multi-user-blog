import os
import webapp2
import jinja2
import re
import hashlib
import hmac
import random
import time
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
    response.out.write(post.author)
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)
    

class MainPage(BlogHandler):
    def get(self):
        self.render('main.html')

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
        return cls(parent = users_key(),
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
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

#### blog pages

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    modified = db.DateTimeProperty(auto_now = True)
    author = db.StringProperty()
    likes = db.IntegerProperty(default = 0)
    
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p = self)

class Comment(db.Model):
    author = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    post_id = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self.__render_text = self.content.replace('\n', '<br>')
        return render_str('comment.html', c = self)

class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery('select * from Post order by created desc limit 10')
        self.render('front.html', posts = posts, username = self.user)

class PostPage(BlogHandler):
    def get(self, post_id,):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)
        comments = Comment.all().filter('post_id =', int(post_id))

        if not post:
            self.error(404)
            return

        post._render_text = post.content.replace('\n', '<br>')
        self.render('permalink.html', post = post, comments = comments)

    def post(self, post_id):
        comments = self.request.get('comment')
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        p.put()
        self.redirect('/blog/%s' % int(post_id)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/login')
            
    def post(self):
        if not self.user:
            self.redirect('/blog')
            
        author = self.user.name
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(),author = author,
                     subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = 'Need subject and content, please!'
            self.render('newpost.html', subject = subject,
                        content = content, error = error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_name(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
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
        
        params = dict(username=self.username,
                      email=self.email)

        if not valid_name(self.username):
            params['error_username'] = 'Not a valid username.'
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = 'Not a valid password.'
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = 'Passwords did not match.'
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
            self.redirect('/welcome')
            
class Login(BlogHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Login not valid'
            self.render('login.html', error = msg)

class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key) 
            if self.user.name == post.author:
                if post:
                    self.render('editpost.html', post=post)
                else:
                    self.error(404)
                    return
                
            else:
                self.write('You cannot Edit someone elses post!')
        else:
            return self.redirect('/login')

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user.name == post.author:
            if 'update' in self.request.POST:
                if subject and content:
                    update_value = Post.get_by_id(
                        int(post_id), parent=blog_key())
                    if update_value:
                        update_value.subject = subject
                        update_value.content = content
                        
                        update_value.put()
                        
                        self.redirect('/blog/%s' % str(update_value.key().id()))
                        
                    else:
                        return self.error(404)
                else:
                    error = 'Update your subject or content, please'
                    key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                    post = db.get(key)
                    self.render('/editpost.html', post=post)
            if 'cancel' in self.request.POST:
                update_value = Post.get_by_id(int(post_id), parent=blog_key())
                self.redirect('/blog/%s' % str(update_value.key().id()))
        else:
            self.write('You cannot Edit someone elses post!')
 
class PostComment(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            
            comments = db.GqlQuery('SELECT * FROM Comment WHERE postid =:1', str(post_id)) 
            self.render('comment.html', post=post, comments=comments)

        else:
            self.redirect('/login')

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')

        if 'submit' in self.request.POST:
            content = self.request.get('content')
            author = self.user.name

        if comment:
            c = Comment(postid=post_id, content=content, author=author) 
            c.put()
            time.sleep(0.1)
            return self.redirect('/blog/postcomment/%s' % post_id)
            
        if 'cancel' in self.request.POST:
            return self.redirect('/blog/%s' % str(post_id))

class EditComment(BlogHandler):
    def get(self, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            
            if self.user.name == comment.author:
                self.render('editcomment.html', comment=comment)
            else:
                self.write('You can not edit smoeone elses comments!')
        else:
            self.redirect('/login')

    def post(self, comment_id):
        content = self.request.get('content')
        commentVal = Comment.get_by_id(int(comment_id))
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if comment and self.user.name == comment.author:
            if 'update' in self.request.POST:
                if content:
                    commentVal.content = content
                    commentVal.put()
                    time.sleep(0.1)
                    return self.redirect('/blog/postcomment/%s' % str(commentVal.postid))

            if 'delete' in self.request.POST:
                if content:
                    commentVal.content = content
                    commentVal.delete()
                    time.sleep(0.1)
                    return self.redirect('/blog/postcomment/%s' % str(commentVal.postid))

            if 'cancel' in self.request.POST:
                if content:
                    time.sleep(0.1)
                    return self.redirect('/blog/postcomment/%s' % str(commentVal.postid))

        else:
            self.write('You cannot edit someone elses comments!')

class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            
            if self.user.name == post.author:
                if post:
                    self.render('deletepost.html', post=post)
                else:
                    self.error(404)
                    
            else:
                self.write('You cannot Delete someone elses post!')
        else:
            self.redirect('/login')

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            
            if self.user.name == post.author:
                if post:
                    if 'delete' in self.request.POST:
                        delete_value = Post.get_by_id(int(post_id), parent=blog_key())
                        if delete_value:
                            delete_value.delete()
                            time.sleep(0.2)
                            self.redirect('/blog/newpost')
                        else:
                            return self.error(404)

                    if 'cancel' in self.request.POST:
                        self.redirect('/blog')
                else:
                    self.error(404)
                    return
            else:
                self.write('You cannot Delete someone elses post!')

        
class Like(BlogHandler):
    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return
            
            if self.user.name != post.author:
                if self.user.name in post.user_like:
                    post.user_like.remove(self.user.name)
                    post.like_count -= 1
                    post.put()
                    time.sleep(0.2)
                    self.redirect('/postcomment/%s' % post_id)
                else:
                    post.user_like.append(self.user.name)
                    post.like_count += 1
                    post.put()
                    time.sleep(0.2)
                    self.redirect('/postcomment/%s' % post_id)
                
            if self.user.name == post.author:
                self.write('You cannot like your own post.')

        else:
            self.redirect('/login')


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
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/([0-9]+)/like', Like),
                               ('/blog/postcomment([0-9]+)', PostComment),
                               ('/blog/editcomment([0-9]+)', EditComment)
                               ],
                              debug=True)
                               
