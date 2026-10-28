from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_cors import CORS

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.session_protection = "strong"
cors = CORS()
