# Login decorator
from functools import wraps
from flask import redirect, url_for, session as login_session, flash

def login_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        if 'logged_in' not in login_session:
            flash('Login needed for this function')
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorator