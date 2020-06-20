from flask_jwt_extended import create_access_token, decode_token, create_refresh_token

from auth import db
from config import Config


class Account(db.Model):
    __tablename__ = 'accounts'

    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(20))
    admin = db.Column(db.Integer)
    password_hash = db.Column(db.String(128))
    access_token = db.Column(db.String(512))
    refresh_token = db.Column(db.String(512))
    code = db.Column(db.String(512))


class Token(db.Model):
    __tablename__ = 'tokens'
    id = db.Column(db.Integer, primary_key=True)
    source_app = db.Column(db.String(64))
    request_app = db.Column(db.String(64))
    access_token = db.Column(db.String(512))


class AccountData:
    @staticmethod
    def get_by_id(account_id):
        try:
            db.session.commit()
            account = Account.query.filter_by(id=int(account_id)).first()
        except:
            return None
        return account

    @staticmethod
    def get_all():
        accounts = Account.query.all()
        return accounts

    @staticmethod
    def get_by_login(login):
        try:
            db.session.commit()
            account = Account.query.filter_by(login=login).first()
        except:
            return None
        return account

    @staticmethod
    def get_by_token(access_token):
        try:
            decoded_token = decode_token(access_token)
        except:
            # ExpiredSignatureError
            decoded_token = None

        if decoded_token:
            account = AccountData.get_by_login(decoded_token['identity'])
            if account:
                return account
        return None

    @staticmethod
    def check_password(login, password_hash):
        account = AccountData.get_by_login(login)
        if account:
            saved_password = account.password_hash
            if saved_password == password_hash:
                return account
        return None

    @staticmethod
    def create(login, password_hash):
        old_account = AccountData.get_by_login(login=login)
        if not old_account:
            account = Account(login=login, password_hash=password_hash, admin=0)
            if account:
                db.session.add(account)
                db.session.commit()
                return account
        return None

    @staticmethod
    def generate_access_token(login):
        try:
            encoded_token = create_access_token(identity=login, expires_delta=Config.ACCESS_TOKEN_EXPIRATION)
        except:
            encoded_token = None
        return encoded_token

    @staticmethod
    def generate_refresh_token(login):
        try:
            encoded_token = create_refresh_token(identity=login, expires_delta=Config.REFRESH_TOKEN_EXPIRATION)
        except:
            encoded_token = None
        return encoded_token

    @staticmethod
    def generate_code(login):
        try:
            encoded_token = create_access_token(identity=login, expires_delta=Config.CODE_EXPIRATION)
        except:
            encoded_token = None
        return encoded_token

    @staticmethod
    def generate_oauth_token_and_save(login):
        account = AccountData.get_by_login(login)
        if account:
            access_token = AccountData.generate_access_token(login)
            refresh_token = AccountData.generate_refresh_token(login)
            try:
                account.access_token = access_token
                account.refresh_token = refresh_token
                account.code = None
                db.session.commit()
            except:
                return None
            else:
                return access_token, refresh_token
        return None

    @staticmethod
    def decode_jwt(encoded_token):
        try:
            decoded_token = decode_token(encoded_token)
        except:
            # ExpiredSignatureError
            decoded_token = None

        if decoded_token:
            return decoded_token['identity']
        return None

    @staticmethod
    def generate_code_and_save(login):
        account = AccountData.get_by_login(login)
        if account:
            code = AccountData.generate_access_token(login)
            try:
                account.code = code
                db.session.commit()
            except:
                return None
            else:
                return code
        return None

    @staticmethod
    def is_code_valid(code):
        login = AccountData.decode_jwt(code)
        if not login:
            return False

        account = AccountData.get_by_login(login)
        if not account:
            return False

        if str(code) != str(account.code):
            return False

        return True

    @staticmethod
    def delete_token(account):
        if account:
            account.access_token = None
            account.refresh_token = None
            account.code = None
            try:
                db.session.commit()
            except:
                pass
            else:
                return True
        return False

    @staticmethod
    def is_token_valid(app_token):
        login = AccountData.decode_jwt(app_token)
        if not login:
            return False

        account = AccountData.get_by_login(login)
        if not account:
            return False

        if str(app_token) != str(account.access_token):
            return False

        return True

    @staticmethod
    def is_refresh_token_valid(app_token):
        login = AccountData.decode_jwt(app_token)
        if not login:
            return False

        account = AccountData.get_by_login(login)
        if not account:
            return False

        if str(app_token) != str(account.refresh_token):
            return False

        return True


class TokenData:
    @staticmethod
    def get_by_apps(source_app, request_app):
        try:
            db.session.commit()
            token = Token.query.filter_by(source_app=source_app, request_app=request_app).first()
        except:
            return None
        return token

    @staticmethod
    def generate_access_token(source_app):
        try:
            encoded_token = create_access_token(identity=source_app, expires_delta=Config.ACCESS_TOKEN_EXPIRATION)
        except:
            encoded_token = None
        return encoded_token

    @staticmethod
    def generate_token_and_save(source_app, request_app):
        access_token = TokenData.generate_access_token(source_app)
        if not access_token:
            return None

        old_token = TokenData.get_by_apps(source_app, request_app)
        if old_token:
            old_token.access_token = access_token
            db.session.commit()
            return old_token
        else:
            token = Token(source_app=source_app, request_app=request_app, access_token=access_token)
            if not token:
                return None
            db.session.add(token)
            db.session.commit()
            return token

    @staticmethod
    def validate_token(source_app, request_app, access_token):
        token = TokenData.get_by_apps(source_app, request_app)
        try:
            decode_token(token.access_token)
        except:
            # ExpiredSignatureError
            return False

        if not token:
            return False
        if token.access_token == access_token:
            return True
        return False
