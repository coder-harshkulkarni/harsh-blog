from datetime import date
from functools import wraps

import sqlalchemy
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# login Manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Gravatar
gravatar = Gravatar(app)


# admin decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id == 1:
                return f(*args, **kwargs)
            else:
                return abort(403)

    return decorated_function


# CONFIGURE TABLES
class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = db.relationship('BlogPost', backref='author', lazy='dynamic')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    text = db.Column(db.String, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'))
    parent_post = db.relationship('BlogPost', backref='comments')


with app.app_context():
    db.create_all()


@app.route('/')
def get_all_posts():
    with app.app_context():
        posts = db.session.query(BlogPost).all()
        return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            with app.app_context():
                try:
                    new_user = User(name=form.username.data,
                                    password=generate_password_hash(password=form.password.data, salt_length=8),
                                    email=form.email.data)
                    db.session.add(new_user)
                    db.session.commit()
                    login_user(new_user)
                    return redirect(url_for("get_all_posts"))
                except sqlalchemy.except_all():
                    flash('email already exists.')
                    return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=['Post', 'GET'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            with app.app_context():
                user = User.query.filter_by(email=form.email.data).first()
                if user:
                    if check_password_hash(user.password, form.password.data):
                        login_user(user)
                        return redirect(url_for("get_all_posts"))
                    else:
                        flash("Password is incorrect, please try again.")
                        return redirect(url_for("login"))
                else:
                    flash("The email does not exist, please try again.")
                    return redirect(url_for("login"))
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", 'GET'])
def show_post(post_id):
    form = CommentForm()
    with app.app_context():
        if request.method == 'POST':
            if current_user.is_authenticated:
                if form.validate_on_submit():
                    with app.app_context():
                        new_comment = Comment(
                            text=form.text.data,
                            author=current_user,
                            parent_post=BlogPost.query.get(post_id)
                        )
                        db.session.add(new_comment)
                        db.session.commit()
                    return redirect(url_for("show_post", post_id=post_id))
            else:
                flash('You need to register for comment on the post.')
                return redirect(url_for("login"))
        requested_post = BlogPost.query.get(post_id)
        return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST', 'GET'])
@admin_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        with app.app_context():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                date=date.today().strftime("%B %d, %Y"))
            db.session.add(new_post)
            db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_required
def edit_post(post_id):
    with app.app_context():
        post = BlogPost.query.get(post_id)
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            author=post.author,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    with app.app_context():
        post_to_delete = BlogPost.query.get(post_id)
        db.session.delete(post_to_delete)
        db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
