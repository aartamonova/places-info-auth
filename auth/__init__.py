from flask import Flask
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy

from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

api = Api(app)
jwt = JWTManager(app)

from auth.auth_resource import AuthResource, AccountResource, RegisterResource, AccountListResource, TokenResource, \
    TokenValidateResource, CodeResource, OauthTokenResource, OauthTokenValidateResource

api.add_resource(AuthResource, '/auth')
api.add_resource(CodeResource, '/auth/code')
api.add_resource(OauthTokenResource, '/oauth/token')
api.add_resource(TokenResource, '/token/get')
api.add_resource(TokenValidateResource, '/token/validate')
api.add_resource(OauthTokenValidateResource, '/oauth/token/validate')
api.add_resource(AccountListResource, '/accounts')
api.add_resource(RegisterResource, '/register')
api.add_resource(AccountResource, '/account/<int:account_id>')

# Migration
from auth import auth_model
