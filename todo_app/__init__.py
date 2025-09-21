from flask import Flask
from config import *
from .db import *
from flask_jwt_extended import create_access_token,create_refresh_token,JWTManager,jwt_required,get_jwt_identity
from datetime import datetime,timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from . import services
from .services import bootstrap_admin
from flask_migrate import Migrate
from dotenv import load_dotenv

limiter = Limiter(
    key_func=get_remote_address,
    app=None,
    default_limits=["200 per day", "50 per hour"]
)

def create_app():
    app = Flask(__name__)
    app.config.from_object("config")
    load_dotenv(dotenv_path='todo_app/keys.env')
    app.config['SECRET_KEY']=os.getenv("JWT_SECRET_KEY")
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=3)  # 1 hour access tokens
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
    jwt = JWTManager(app)
    db.init_app(app)
    migrate = Migrate(app,db)
    def user_rate_limit_key():
        try:
            user_id = get_jwt_identity()
            return str(user_id) if user_id else get_remote_address()
        except:
            return get_remote_address()
    limiter._key_func = user_rate_limit_key
    limiter.init_app(app)
    from .routes import main
    app.register_blueprint(main)
    with app.app_context():
        db.create_all()
        bootstrap_admin()



    return app







