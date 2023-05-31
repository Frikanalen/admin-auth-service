import logging
import os
import json_log_formatter
import sys

from flask import Flask, request, redirect, session, render_template
from werkzeug.security import check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

formatter = json_log_formatter.JSONFormatter()

json_handler = logging.StreamHandler()
json_handler.setFormatter(formatter)

logger = logging.getLogger('my_json')
logger.addHandler(json_handler)
logger.setLevel(logging.INFO)


if os.getenv('ENV') == 'dev':
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO, handlers=[json_handler])

app = Flask(__name__)

with open('/data/secret_key', 'r') as f:
    app.secret_key = f.read().strip()

login_url = os.getenv('LOGIN_URL', None)
if not login_url:
    logging.error("Missing mandatory environment variable LOGIN_URL, quitting!")
    sys.exit(4)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

user_db = {}


class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == '/data/users':
            logger.info('User database changed, reloading')
            load_user_db()

def load_user_db():
    global user_db
    with open('/data/users', 'r') as f:
        user_db = {}
        for line in f:
            username, password = line.strip().split(':', 1)
            user_db[username] = password
        if not user_db:
            logger.warning('No users in database!')

def validate_user(username, password):
    return username in user_db and check_password_hash(user_db[username], password)

logger.info('Loading user database')
load_user_db()

event_handler = FileChangeHandler()
observer = Observer()
observer.schedule(event_handler, path='/data', recursive=False)
observer.start()

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        with open('user_db.txt', 'r') as f:
            for line in f:
                username, password = line.strip().split(':')
                if form.username.data == username and check_password_hash(password, form.password.data):
                    session['username'] = form.username.data
                    logger.info('User logged in', extra={'user': form.username.data})
                    return redirect(request.args.get('next') or url_for('index'))
            logger.warning('Invalid login attempt', extra={'user': form.username.data})
            return 'Invalid username or password'
    return render_template('login.html', form=form)

@app.route('/auth', methods=['GET'])
def auth():
    if 'username' in session:
        logger.info('Valid session', extra={'user': session['username']})
        return '', 200
    else:
        logger.warning('Invalid session, redirecting to login')
        return redirect('https://login.admin.frikanalen.no', code=302)

@app.route('/healthz', methods=['GET'])
def healthz():
    return '', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

