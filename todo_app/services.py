import re
from flask_jwt_extended import get_jwt_identity
from flask_limiter.util import get_remote_address

from config import FROM_EMAIL, SENDGRID_API_KEY
from .models import User
from .db import *
import os
from werkzeug.security import generate_password_hash,check_password_hash
from datetime import datetime,timedelta
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_field_present(data):
    required_fields = ['username','email', 'password']
    for field in required_fields:
        if field not in data:
            return False
    return True
def is_login_field_present(data):
    required_fields = ['email', 'password']
    for field in required_fields:
        if field not in data:
            return False
    return True
def required_field_present(data):
    required_fields = ['title','description']
    count = 0
    for field in required_fields:
        if required_fields[0] in data:
            count += 1
        elif required_fields[1] in data:
            count += 1
    if count ==2 or count ==1:
        return True
    elif count <2:
        return False
    else:
        return False

def bootstrap_admin():
    if not User.query.filter_by(role="admin").first():
        admin = User(username="superadmin",
                     email="admin@gmail.com",
                     password=generate_password_hash("admin_password", method='pbkdf2:sha256',salt_length=16),
                     role="admin")
        db.session.add(admin)
        db.session.commit()

def send_otp_email(to_email,otp):
    body = f"your otp is {otp}"
    message = Mail(
        from_email=FROM_EMAIL,
        to_emails=to_email,
        subject='Your password reset otp',
        plain_text_content= body
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        if 200 <= response.status_code < 300:
            return True
        else:
            return False

    except Exception as e:
        print("SendGrid error:", e)
        return False



