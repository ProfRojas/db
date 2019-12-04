from . import db
from .models import User
from .forms import LoginForm, SignupForm
from flask_login import login_required, logout_user, current_user, login_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, render_template, make_response, session, redirect, flash, url_for
from flask import current_app as app
from . import login_manager


#@app.route("/")
#def home():
#    username = request.args.get('user')
#    email = request.args.get('email')
#    if username and email:
#        existing_user = User.query.filter(User.username== username or User.email == email).first()
#        if existing_user:
#            return make_response(f'{username} ({email}) already created!')
#        new_user = User(username=username,
#                        email=email)  # Create an instance of the User class
#        db.session.add(new_user)  # Adds new User record to database
#        db.session.commit()  # Commits all changes
#    return make_response(f"{new_user} successfully created!")


# ----------------------
@app.route('/', methods=['GET'])
@login_required
def dashboard():
    """Serve logged in Dashboard."""
    # session['redis_test'] = 'This is a session variable.'
    return render_template('dashboard.html',
                           title='Flask-Session Tutorial.',
                           current_user=current_user,
                           body="You are now logged in!")


@app.route('/session', methods=['GET'])
@login_required
def session_view():
    """Route which displays session variable value."""
    return render_template('session.html',
                           title='Flask-Session Tutorial.',
                           session_variable=str(session['redis_test']))

# ----------------------
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    """User login page."""
    # Bypass Login screen if user is logged in
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    login_form = LoginForm(request.form)
    # POST: Create user and redirect them to the app
    if request.method == 'POST':
        if login_form.validate():
            # Get Form Fields
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            if user:
                if user.check_password(password=password):
                    login_user(user)
                    next = request.args.get('next')
                    return redirect(next or url_for('dashboard'))
                return redirect(url_for('dashboard'))
            flash('Invalid email/password combination')
            return redirect(url_for('login_page'))
    # GET: Serve Log-in page
    return render_template('login.html',
                           form=LoginForm(),
                           title='Log in | Flask-Login Tutorial.',
                           body="Log in with your User account.")


@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    """User sign-up page."""
    signup_form = SignupForm(request.form)
    # POST: Sign user in
    if request.method == 'POST':
        if signup_form.validate():
            # Get Form Fields
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            existing_user = User.query.filter_by(email=email).first()
            if existing_user is None:
                user = User(username=username,
                            email=email,
                            password=generate_password_hash(password, method='sha256'))
                db.session.add(user)
                db.session.commit()
                login_user(user)
                return redirect(url_for('dashboard'))
            flash('A user already exists with that email address.')
            return redirect(url_for('signup_page'))
    # GET: Serve Sign-up page
    return render_template('/signup.html',
                           title='Create an Account | Flask-Login Tutorial.',
                           form=SignupForm(),
                           body="Sign up for a user account.")
@app.route("/logout")
@login_required
def logout_page():
    """User log-out logic."""
    logout_user()
    return redirect(url_for('login_page'))

@login_manager.user_loader
def load_user(user_id):
    """Check if user is logged-in on every page load."""
    if user_id is not None:
        return User.query.get(user_id)
    return None

