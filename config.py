import os
import certifi
from dotenv import load_dotenv

os.environ['SSL_CERT_FILE'] = certifi.where()
load_dotenv(dotenv_path='todo_app/api_key.env')
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("SENDGRID_FROM_EMAIL")

MYSQL_HOST = "localhost"
MYSQL_USER = "Axe"
MYSQL_PASSWORD = "7861"
MYSQL_DB = "flaskalchemy"


# SQLAlchemy style connection
SQLALCHEMY_DATABASE_URI = (
    f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}/{MYSQL_DB}"
)
SQLALCHEMY_TRACK_MODIFICATIONS = False

