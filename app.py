from flask import Flask, render_template, request, session, redirect, url_for
from flask_session import Session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired
from flask_wtf import RecaptchaField
from authlib.integrations.flask_client import OAuth
import random

app = Flask(__name__)
app.secret_key = 'supersecret'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Konfigurasi reCAPTCHA Google
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LcCrCErAAAAADuF-L3v-JnrAzGg_epY4yiOPZmv'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LcCrCErAAAAALeCG5Bhg2VmH9ueo_OXa9CeZ1Rc'

# OAuth2 - Google
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='488643671182-ch3meqo5grcnte0hnr03npmd9sp0v6q8.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'}
)

# Form login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')

@app.route('/')
def index():
    return 'Welcome! <a href="/login">Login</a> | <a href="/login/google">Login with Google</a>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if form.username.data == 'admin' and form.password.data == '1234':
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            session['username'] = form.username.data
            print(f"[DEBUG] OTP for {form.username.data}: {otp}")
            return redirect(url_for('otp'))
    return render_template('login.html', form=form)

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        if user_otp == session.get('otp'):
            session['authenticated'] = True
            return redirect(url_for('dashboard'))
        return 'OTP salah, coba lagi!'
    return render_template('otp.html')

@app.route('/login/google')
def login_google():
    redirect_uri = 'http://localhost:5000/authorize/google'

    return google.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    user = google.parse_id_token(token)
    session['authenticated'] = True
    session['username'] = user['email']
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if session.get('authenticated'):
        return f"Welcome, {session['username']}! <a href='/logout'>Logout</a>"
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
