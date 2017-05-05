import webapp2
import jinja2
import time
import os
import re
import hashlib
import hmac
import random
import string
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),"template")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

secret = "fcgvbhn45-562xcvbn"

def make_secure_val(val):
    return hmac.new(secret,val).hexdigest()

def valid_username(username):
    return username and USER_RE.match(username)

def valid_password(password):
    return password and PASS_RE.match(password)

def valid_email(email):
    return not email or EMAIL_RE.match(email)

def users_key(group='default'):
    return db.Key.from_path('users', group)

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

def make_salt(self):
    t = ''.join(random.choice(string.letters)for x in xrange(5))
    return make_secure_val(t)

class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def logout(self):
        self.response.headers.add_header('Set-Cookie','username=;path=/')

    def set_cookie(self, username):
        self.response.headers.add_header('Set-Cookie','username=%s; path=/'%str(username))

    def get_cookie(self):
        cookie = self.request.cookies.get('username')
        return cookie


class Database(db.Model):
    title = db.StringProperty(required = True)
    post = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.StringProperty(required = True)

    @classmethod
    def put_data(cls,title="", post="", author = ""):
        obj = Database(parent=blog_key(), title=title, post= post, author = author)
        obj.put()


class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def put_data(cls,username="", password="",email=""):
        obj = User(parent=users_key(),username=username, password=password,email=email)
        obj.put()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls,name):
        i = User.all().filter('username =', name).get()
        return i
   
    @classmethod
    def by_pass(cls,password):
        h = make_secure_val(password)
        j = User.all().filter('password =', h).get()
        return j
 
    @classmethod
    def login(cls, username, password):
        u = cls.by_name(username)
        p = cls.by_pass(password)
        if u and p:
            return u


class Like(db.Model):
    post_id = db.IntegerProperty(required = True)
    name = db.StringProperty(required = True)    

    @classmethod
    def get_likes(cls, _id):
        i = Like.all().filter('post_id = ', _id)
        return i.count()

    @classmethod
    def put_data(cls, post_id, name):
        obj = Like( post_id= post_id, name = name)
        obj.put()

    @classmethod
    def by_name(cls, u, _id):
        i = db.GqlQuery('SELECT * FROM Like WHERE post_id=:1 and name =:2', _id, u)
        return i.count()


class Unlike(db.Model):
    post_id = db.IntegerProperty(required = True)
    name = db.StringProperty(required = True)    

    @classmethod
    def get_unlikes(cls, _id):
        i = Unlike.all().filter('post_id = ', _id)
        return i.count()

    @classmethod
    def put_data(cls, post_id, name):
        obj = Unlike( post_id= post_id, name = name)
        obj.put()

    @classmethod
    def by_name(cls, u, _id):
        i = db.GqlQuery('SELECT * FROM Unlike WHERE post_id=:1 and name =:2', _id, u)
        return i.count()


class Comment(db.Model):
    post_id = db.IntegerProperty(required = True)
    name = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    post = db.StringProperty(required = True)

    @classmethod
    def put_data(cls, post_id, name, post):
        obj = Comment( post_id= post_id, name = name, post=post)
        obj.put()


class Signup(Handler):
    def get(self):
        t = self.get_cookie()
        if t:
            self.redirect("/blog/welcome")
        else:
            self.render("signup.html")
    def post(self):
        error = False
        password = self.request.get("password")
        verify = self.request.get("verify")
        username = self.request.get("username")
        email = self.request.get("email")
        params = dict(username = username, email = email) 
        if not valid_username(username):
            params["error_username"] = "That's not a valid username."
            error = True
        if not valid_password(password):
            params["error_password"] = "That's not a valid password."
            error = True
        elif password != verify:
            params["error_verify"] = "Your passwords didn't match."
            error = True
        if not valid_email(email):
            params["error_email"] = "That's not a valid email."
            error = True
        u = User.by_name(username)
        if u:
            params["user_exist"] = "This user already exist."
            error = True
        if error:
            self.render("signup.html", **params)
        else:
            self.set_cookie(username)
            passw = make_secure_val(password)
            User.put_data(username=username, password=passw,email=email)
            self.redirect('/blog/welcome')


class Welcome(Handler):
    def get(self):
        t = self.get_cookie()
        p = Database.all().filter('author =', t).order('-created')
        if t:
            self.render("user.html", username = t, p = p)


class Blog(Handler):
    def get(self):
        obj = Database.all().order('-created')
        self.render("home.html",database = obj)

 
class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect("/blog")


class Login(Handler):
    def get(self):
        t = self.get_cookie()
        if t:
            self.redirect('/blog/welcome')
        else:
            self.render("login.html")
    def post(self):
        u = self.get_cookie()
        if not u:
            self.redirect('/blog/login')
        username = self.request.get("username")
        password = self.request.get("password")
        i = User.login(username, password)
        if i:
            self.set_cookie(i.username)
            self.redirect('/blog/welcome')
        else:
            self.render("login.html",error="Username or password is wrong.")


class Newpost(Handler):
    def get(self):
        self.render("newpost.html")
    def post(self):
        u = self.get_cookie()
        if not u:
            self.redirect('/blog/login')
        else:
            title = self.request.get('title')
            post = self.request.get('post')
            u = self.get_cookie()
            if title and post:
                Database.put_data( title=title, post=post, author = u)
                self.redirect('/blog/welcome')
            else:
                error = "We need both fields to be filled."
                self.render("newpost.html",error = error,title= title, post = post)


class PostPage(Handler):
    def get(self,id):
        key = db.Key.from_path('Database',int( id ),parent = blog_key())
        t = db.get(key)
        if t:
            l = Like.get_likes(int(id))
            ul = Unlike.get_unlikes(int(id))
            obj = db.GqlQuery('SELECT * FROM Comment WHERE post_id=:1 order by created desc', int(id))
            self.render("postpage.html", post = t, l=l, ul= ul, comments = obj)
        else:
            self.redirect('/blog')

    def post(self, id):
        u = self.get_cookie()
        if not u:
            self.redirect('/blog/login')
        else:
            key = db.Key.from_path('Database',int( id ),parent = blog_key())
            t = db.get(key)
            l = Like.get_likes(int(id))
            obj = db.GqlQuery('SELECT * FROM Comment WHERE post_id=:1 order by created desc', int(id))
            ul = Unlike.get_unlikes(int(id))        
            if self.request.get('like'):
                a = Like.by_name(str(u) , int(id))
                if t.author == u or a == 1:
                    if t.author == u:
                        self.render("postpage.html",post = t, msg="You cannot like your post", l = l,ul = ul,  comments = obj)
                    else:
                        self.render("postpage.html",post = t, msg="You already liked this post", l = l, ul = ul,comments = obj)
                else:
                    self.redirect('/blog/post/%s/like'%t.key().id())

            if self.request.get('unlike'):
                a = Unlike.by_name(str(u) , int(id))
                if t.author == u or a == 1:
                    if t.author == u:
                        self.render("postpage.html",post = t, msg="You cannot unlike your post", l=l, ul = ul, comments = obj)
                    else:
                        self.render("postpage.html",post = t, msg="You already unliked this post", l=l, ul = ul, comments = obj)
                else:
                    self.redirect('/blog/post/%s/unlike'%t.key().id())

            
            if self.request.get('delete'):
                if t.author == u:
                    t.delete()
                    time.sleep(0.1)
                    self.redirect('/blog')
                else:
                    self.render("postpage.html",post = t, msg="You cannot delete this post", 
                                        l=l, ul = ul, comments = obj)
            
            if self.request.get('comments'):
                if self.request.get('comment'):
                    Comment.put_data(post_id = int(id), name = u, post = self.request.get('comment'))
                    self.redirect('/blog/post/%s'%(t.key().id()))
                else:
                    self.render("postpage.html",post = t, msg="You had left the comment box empty.", 
                                        l=l, ul = ul, comments = obj)

            if self.request.get('edit'):
                if t.author == u:
                    self.redirect('/blog/post/%s/edit'%(t.key().id()))
                else:
                    self.render("postpage.html",post = t, msg="You cannot edit this post", 
                                        l=l, ul = ul, comments = obj)


class LikeHandler(Handler):
    def get(self,id):
        key = db.Key.from_path('Database',int( id ),parent = blog_key())
        t = db.get(key)
        if t:
            u = self.get_cookie()
            if not u:
            	self.redirect('/blog/login')
            else:
            	Like.put_data(post_id = int(id), name = u)
            	self.redirect('/blog/post/%s'%t.key().id())       
        else:
            self.redirect('/blog')                    


class UnlikeHandler(Handler):
    def get(self,id):
        key = db.Key.from_path('Database',int( id ),parent = blog_key())
        t = db.get(key)
        if t:
            u = self.get_cookie()
            if not u:
            	self.redirect('/blog/login')
            else:
            	Unlike.put_data(post_id = int(id), name = u)
            	self.redirect('/blog/post/%s'%t.key().id())       
        else:
            self.redirect('/blog')
                    

class EditPost(Handler):
    def get(self, id):
        key = db.Key.from_path('Database',int( id ),parent = blog_key())
        t = db.get(key)
        if t:
            u = self.get_cookie()
            if not u:
                self.redirect('/blog/login')
            else:
                self.render("editpost.html", p = t)         
        else:
            self.redirect('/blog')
    def post(self, id):
        key = db.Key.from_path('Database',int( id ),parent = blog_key())
        t = db.get(key)
        if not t:
            self.redirect('/blog')
        else:
            u = self.get_cookie()
            if not u:
                self.redirect('/blog/login')
            i = self.request.get('cancel')
            if i:
                self.redirect('/blog/post/%s'%t.key().id())
            if u == t.author:
                title = self.request.get('title')
                post = self.request.get('post')
                if title and post:
                    t.title = title
                    t.post = post
                    t.put()
                    self.redirect('/blog/post/%s'%t.key().id())
                else:
                    error = "Both fields should be filled"
                    self.render("editpost.html",error = error,p = t)
            else:
                self.redirect('/blog')
            

class EditComment(Handler):
    def get(self, id):
        key = db.Key.from_path('Comment',int( id ))
        t = db.get(key)
        if not t:
            self.redirect('/blog')
        else:
            u = self.get_cookie()
            if not u:
                self.redirect('/blog/login')       
            u = self.get_cookie()
            if u == t.name:
                self.render("editcomment.html", p = t)
            else:
                l = Like.get_likes(int(id))
                ul = Unlike.get_unlikes(int(id))
                obj = Comment.all().order('-created')
                self.render("postpage.html", post = t,msg3="You cannot edit this comment", l=l, ul= ul, comments = obj)

    def post(self, id):
        u = self.get_cookie()
        key = db.Key.from_path('Comment',int( id ))
        t = db.get(key)
        if not t:
            self.redirect('/blog')
        else:
            if not u:
                self.redirect('/blog/login')
            i = self.request.get('cancel')
            if i:
                self.redirect('/blog')
            if u == t.name:
                comment = self.request.get('comment')
                if comment:
                    t.post = comment
                    t.put()
                    self.redirect('/blog')
                else:
                    error = "Fields should not be blank"
                    self.render("editcomment.html",error = error,p = t)
            else:
                self.redirect('/blog')
            


class DeleteComment(Handler):
    def get(self, id):
        key = db.Key.from_path('Comment',int( id ))
        t = db.get(key)
        if not t:
            self.redirect('/blog')
        else:
            u = self.get_cookie()
            if not u:
                self.redirect('/blog/login')       
            u = self.get_cookie()
            if u == t.name:
                self.render("deletecomment.html", p = t)
            else:
                l = Like.get_likes(int(id))
                ul = Unlike.get_unlikes(int(id))
                obj = Comment.all().order('-created')
                self.render("postpage.html", post = t,msg3="You cannot delete this comment", l=l, ul= ul, comments = obj)

    def post(self, id):
        u = self.get_cookie()
        key = db.Key.from_path('Comment',int( id ))
        t = db.get(key)
        if t:
            if not u:
                self.redirect('/blog/login')
            else:
                u = self.get_cookie()
                if not u:
                    self.redirect('/blog/login')
                if u == t.name:
                    l = Like.get_likes(int(id))
                    ul = Unlike.get_unlikes(int(id))
                    obj = Comment.all().order('-created')
                    if self.request.get('Yes'):
                        t.delete()
                        time.sleep(0.1)
        self.redirect('/blog')


app = webapp2.WSGIApplication([
    ('/blog', Blog),
    ('/blog/login', Login),
    ('/blog/signup', Signup),
    ('/blog/welcome',Welcome),
    ('/blog/logout', Logout),
    ('/blog/post/([0-9]+)/like', LikeHandler),
    ('/blog/post/([0-9]+)/unlike', UnlikeHandler),
    ('/blog/post/([0-9]+)', PostPage),
    ('/blog/post/([0-9]+)/edit', EditPost),
    ('/blog/post/([0-9]+)/editcomment', EditComment),
    ('/blog/post/([0-9]+)/deletecomment', DeleteComment),
    ('/blog/newpost', Newpost)
], debug=True)
