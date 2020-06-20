import datetime
import os

root_dir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    # Database settings
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(root_dir, 'auth_data.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Expiration settings
    ACCESS_TOKEN_EXPIRATION = datetime.timedelta(hours=240)
    REFRESH_TOKEN_EXPIRATION = datetime.timedelta(hours=240)
    CODE_EXPIRATION = datetime.timedelta(minutes=1)

    # Other settings
    KNOWN_APPS = ['gui', 'gateway']
    JSON_AS_ASCII = False
    SECRET_KEY = 'places-info-secret-key'
