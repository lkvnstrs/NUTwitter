from flask import (Flask, request, session, url_for, redirect,
                   render_template, abort, g, flash)
from flask.ext.sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib
import uuid

# CONFIG #
DATABASE = 'sqlite:///./nu_twitter.db'
SECRET_KEY = 'shhdonttell' # flask.session requires this
PER_PAGE = 30
DEBUG = True

# APP #
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE
app.config['DEBUG'] = DEBUG
app.config['SECRET_KEY'] = SECRET_KEY
db = SQLAlchemy(app)

# CONTROLLER #

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        user = db.session.query(User).filter_by(id=session['user_id']).first()
        if user is not None:
            g.user = user


@app.route('/')
def timeline():
    """Shows a users timeline or redirect to the splash page.

       Shows posts by the user and his/her followers
    """
    if not g.user:
        return render_template('splash.html')

    # Get a list of the logged-in user's id and his/her followings
    # This is probably the hardest database thing you'll have to do
    # for this project, so ask many questions
    user_id = session['user_id']

    all_followers = db.session.query(followers).filter_by(who_id=user_id)
    follower_ids = [f.whom_id for f in all_followers.all()]

    # We want to return the user's posts as well
    follower_ids.append(user_id)

    posts = db.session.query(Post).filter(Post.user_id.in_(follower_ids))
    posts = posts.order_by(Post.pub_date.desc())
    posts = posts.limit(PER_PAGE)
    return render_template('timeline.html', posts=posts.all())


@app.route('/<username>')
def user_timeline(username):
    """Displays a user's tweets
    """
    profile_user = db.session.query(User).filter_by(username=username.lower()).first()

    if profile_user is None:
        abort(404)

    if g.user:
        followed = is_following(profile_user, g.user)
    else:
        followed = False

    num_followers = len(db.session.query(followers).filter_by(whom_id=profile_user.id).all())
    num_followings = len(db.session.query(followers).filter_by(who_id=profile_user.id).all())

    posts = profile_user.posts.order_by(Post.pub_date.desc()).limit(PER_PAGE)

    template_data = dict(
        posts=posts,
        followed=followed,
        profile_user=profile_user,
        followers=num_followers,
        followings=num_followings,)

    return render_template('timeline.html', **template_data)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in
    """
    if g.user is not None:
        return redirect(url_for('timeline'))

    error = None
    if request.method == 'POST':
        username = request.form['username'].lower()
        user = db.session.query(User).filter_by(username=username).first()
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user.password_digest, user.salt,
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('Logged in')
            session['user_id'] = user.id
            return redirect(url_for('timeline'))

    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user
    """
    if g.user:
        return redirect(url_for('timeline'))

    errors = []
    if request.method == 'POST':

        # Check username
        if not request.form['username']:
            errors.append('You have to enter a username')

        user = db.session.query(User).filter_by(username=request.form['username'].lower())
        if user.exists() is True:
            errors.append('That username is already taken')

        # Check email
        if not request.form['email']:
            errors.append('You have to enter an email address')
        else:
            if '@' not in request.form['email']:
                errors.append('Invalid email address')

            user = db.session.query(User).filter_by(email=request.form['email'].lower())
            if user.exists() is True:
                errors.append('That email is already in use')

        # Check password
        if not request.form['password']:
            errors.append('You have to enter a password')
        elif request.form['password'] != request.form['confirmpassword']:
            errors.append('The two passwords do not match')

        # Register the user if there are no errors
        if len(errors) == 0:
            user = create_user(request.form['username'].lower(),
                               request.form['email'].lower(),
                               request.form['password'])
            flash('You were successfully registered')

            # Redirect to the login
            return redirect(url_for('login'))

    return render_template('register.html', errors=errors)


@app.route('/logout')
def logout():
    """Logs the user out
    """
    #flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('timeline'))


@app.route('/<username>/follow')
def follow_user(username):
    """Follows the given user
    """
    if not g.user:
        abort(401)

    user_to_follow = db.session.query(User).filter_by(username=username).first()
    if user_to_follow is None:
        abort(404)

    if not is_following(g.user, user_to_follow):
        g.user.followed.append(user_to_follow)
        db.session.add(g.user)
        db.session.commit()
        flash('You are now following %s' % username)
    else:
        flash('You are already following %s' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Unfollows the given user"""
    if not g.user:
        abort(401)

    user_to_follow = db.session.query(User).filter_by(username=username).first()
    if user_to_follow is None:
        abort(404)

    if is_following(g.user, user_to_follow):
        g.user.followed.remove(user_to_follow)
        db.session.add(g.user)
        db.session.commit()
        flash('You are no longer following %s' % username)
    else:
        flash('You are not currently following %s' % username)

    return redirect(url_for('user_timeline', username=username))


@app.route('/add_message', methods=['POST'])
def add_post():
    """Registers a new message for the user.
    """
    if 'user_id' not in session:
        abort(401)

    if request.form['text']:
        create_post(g.user, request.form['text'])
        flash('Posted!')
    return redirect(url_for('timeline'))


# USEFUL METHODS #
def create_user(username, email, password):
    """Creates a user
    """
    password_digest, salt = digest_password(password)
    user = User(username, email, password_digest, salt)
    db.session.add(user)
    db.session.commit()
    return user


def create_post(user, body, pub_date=None):
    """Creates a post
    """
    post = Post(user, body, pub_date)
    db.session.add(post)
    db.session.commit()
    return post


def digest_password(pw):
    """Hashes the password. Returns the hashed password and the salt used
    """
    salt = uuid.uuid4().hex
    return (hashlib.sha512(pw + salt).hexdigest(), salt)


def check_password_hash(digest, salt, pw):
    """Checks a given password against the digest in the database
    """
    return (hashlib.sha512(pw + salt).hexdigest() == digest)


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address
    """
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (hashlib.md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


def format_datetime(timestamp):
    """Format a timestamp for display
    """
    return timestamp.strftime('%d/%m/%Y\n%H:%M')


def is_following(follower_user, followed_user):
    """Checks if follower_user is following followed_user
    """
    return follower_user.followed.filter(followers.c.whom_id == followed_user.id).count() > 0


# JINJA FILTERS #
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url

# MODELS #

followers = db.Table('followers',
        db.Column('who_id', db.Integer, db.ForeignKey('user.id')),
        db.Column('whom_id', db.Integer, db.ForeignKey('user.id'))
)


class User(db.Model):
    """A user table
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(150), unique=True)
    password_digest = db.Column(db.String(128))
    salt = db.Column(db.String(32))
    followed = db.relationship('User',
        secondary = followers,
        primaryjoin = (followers.c.who_id == id),
        secondaryjoin = (followers.c.whom_id == id),
        backref = db.backref('followers', lazy = 'dynamic'),
        lazy = 'dynamic')

    def __init__(self, username, email, password_digest, salt):
        self.username = username
        self.email = email
        self.password_digest = password_digest
        self.salt = salt

    def __repr__(self):
        return '<User %r>' % self.username


class Post(db.Model):
    """A post table
    """
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    pub_date = db.Column(db.DateTime)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('posts', lazy='dynamic'))

    def __init__(self, user, body, pub_date=None):
        self.body = body

        if pub_date is None:
            pub_date = datetime.utcnow()

        self.pub_date = pub_date
        self.user = user

    def __repr__(self):
        return '<Post %r>' % self.id


if __name__ == '__main__':
    db.create_all()
    app.run(host='0.0.0.0', port=5000)
