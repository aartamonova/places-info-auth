import datetime
import json
import logging

from flask import make_response, jsonify, request
from flask_api.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_500_INTERNAL_SERVER_ERROR, \
    HTTP_404_NOT_FOUND
from flask_restful import fields, Resource, marshal

from auth.auth_model import AccountData, TokenData
from config import Config

account_fields = {'id': fields.Integer,
                  'login': fields.String,
                  'admin': fields.Integer}

account_list_fields = {'count': fields.Integer,
                       'accounts': fields.List(fields.Nested(account_fields))}

logging.basicConfig(filename="log_data.log", level=logging.WARNING, filemode='w',
                    format='%(asctime)s - %(levelname)s - %(message)s')


class AccountResource(Resource):
    @staticmethod
    def get(account_id):
        account = AccountData.get_by_id(account_id)

        logging.warning('Поиск пользователя с id %s' % account_id)

        if not account:
            return make_response(jsonify({'error': 'The account with the selected id does not exist'}),
                                 HTTP_404_NOT_FOUND)
        else:
            try:
                make_response(marshal(account, account_fields), HTTP_200_OK)
            except:
                return make_response(jsonify({'error': 'Corrupted database data'}), HTTP_500_INTERNAL_SERVER_ERROR)
            return make_response(marshal(account, account_fields), HTTP_200_OK)


class AccountListResource(Resource):
    @staticmethod
    def get():
        accounts = AccountData.get_all()
        logging.warning('Запрос на получение всех пользователей')

        if not accounts:
            return make_response(jsonify({'error': 'The account database is empty'}), HTTP_404_NOT_FOUND)
        else:
            try:
                content = marshal({'count': len(accounts), 'accounts': [marshal(a, account_fields) for a in accounts]},
                                  account_list_fields)
            except:
                return make_response({'error': 'Corrupted database data'}, HTTP_500_INTERNAL_SERVER_ERROR)

            return make_response(content, HTTP_200_OK)


class AuthResource(Resource):
    @staticmethod
    def get():
        try:
            login = request.args.get('login', type=str)
            password_hash = request.args.get('password_hash', type=str)
        except:
            return make_response(jsonify({'error': 'Invalid format auth data'}), HTTP_400_BAD_REQUEST)

        logging.warning('Запрос на проверку пароля пользователя %s' % login)

        account = AccountData.check_password(login, password_hash)
        if not account:
            return make_response(jsonify({'error': 'Invalid login or password'}), HTTP_403_FORBIDDEN)

        try:
            response = make_response(marshal(account, account_fields), HTTP_200_OK)
        except:
            return make_response(jsonify({'error': 'Corrupted database data'}), HTTP_500_INTERNAL_SERVER_ERROR)
        return response


class CodeResource(Resource):
    @staticmethod
    def get():
        try:
            login = request.args.get('login', type=str)
            password_hash = request.args.get('password_hash', type=str)
        except:
            return make_response(jsonify({'error': 'Invalid format auth data'}), HTTP_400_BAD_REQUEST)

        account = AccountData.check_password(login, password_hash)
        if not account:
            return make_response(jsonify({'error': 'Invalid login or password'}), HTTP_403_FORBIDDEN)

        logging.warning('Запрос на генерацию кода для пользователя %s' % login)

        code = AccountData.generate_code_and_save(login)
        if not code:
            return make_response(jsonify({'error': 'Authorization failed'}), HTTP_403_FORBIDDEN)

        try:
            data = {'code': code}
            return make_response(json.dumps(data), HTTP_200_OK)
        except:
            return make_response(jsonify({'error': 'Corrupted database data'}), HTTP_500_INTERNAL_SERVER_ERROR)


# Выдать токен по коду или рефреш токену
class OauthTokenResource(Resource):
    @staticmethod
    def post():
        try:
            grant_type = json.loads(request.data.decode("utf-8"))['grant_type']
        except:
            return make_response({'error': 'Invalid request data'}, HTTP_400_BAD_REQUEST)

        if grant_type == 'authorization_code':
            try:
                code = json.loads(request.data.decode("utf-8"))['code']
            except:
                return make_response({'error': 'Invalid request data'}, HTTP_400_BAD_REQUEST)

            is_code_valid = AccountData.is_code_valid(code)
            if not is_code_valid:
                return make_response({'error': 'Invalid code'}, HTTP_403_FORBIDDEN)

            # сгенерировать токен и рефреш токен и положить их в базу данных
            login = AccountData.get_by_token(code).login
            logging.warning('Запрос на генерацию токена %s' % login)
            if login:
                access_token, refresh_token = AccountData.generate_oauth_token_and_save(login)
                if access_token and refresh_token:
                    expires_in = (datetime.datetime.now() + Config.ACCESS_TOKEN_EXPIRATION).strftime(
                        "%Y-%m-%d %H:%M:%S")
                    args = {'access_token': access_token,
                            'token_type': 'access_token',
                            'refresh_token': refresh_token,
                            'expires_in': expires_in}
                    return make_response(args, HTTP_200_OK)
        return make_response({'error': 'Invalid request data'}, HTTP_403_FORBIDDEN)


class RegisterResource(Resource):
    @staticmethod
    def post():
        try:
            data = json.loads(request.data.decode("utf-8"))
            login = data['login']
            password_hash = data['password_hash']
        except:
            return make_response(jsonify({'error': 'Invalid account data'}), HTTP_400_BAD_REQUEST)

        logging.warning('Запрос на регистрацию нового пользователя %s' % login)
        account = AccountData.create(login, password_hash)
        if not account:
            return make_response(jsonify({'error': 'The account not created'}), HTTP_404_NOT_FOUND)
        else:
            return make_response(jsonify({'info': 'The account was created successfully'}), HTTP_200_OK)


class TokenResource(Resource):
    @staticmethod
    def get():
        try:
            source_app = request.args.get('source_app', type=str)
            request_app = request.args.get('request_app', type=str)
        except:
            return make_response(jsonify({'error': 'Invalid format data'}), HTTP_400_BAD_REQUEST)

        if source_app not in Config.KNOWN_APPS:
            make_response(jsonify({'error': 'Authorization error'}), HTTP_403_FORBIDDEN)

        logging.warning('Запрос на генерацию токена')
        token = TokenData.generate_token_and_save(source_app, request_app)
        if token:
            data = {'access_token': token.access_token}
            return make_response(json.dumps(data), HTTP_200_OK)

        return make_response(jsonify({'error': 'Authorization error'}), HTTP_403_FORBIDDEN)


class TokenValidateResource(Resource):
    @staticmethod
    def get():
        try:
            source_app = request.args.get('source_app', type=str)
            request_app = request.args.get('request_app', type=str)
            access_token = request.args.get('access_token', type=str)
        except:
            return make_response(jsonify({'error': 'Invalid format data'}), HTTP_400_BAD_REQUEST)

        logging.warning('Запрос на проверку токена от приложения %s' % source_app)
        is_token_valid = TokenData.validate_token(source_app, request_app, access_token)
        if is_token_valid:
            return make_response(jsonify({'message': 'Token is valid'}), HTTP_200_OK)

        return make_response(jsonify({'error': 'Token is invalid'}), HTTP_403_FORBIDDEN)


class OauthTokenValidateResource(Resource):
    @staticmethod
    def get():
        try:
            access_token = request.args.get('access_token', type=str)
        except:
            return make_response(jsonify({'error': 'Invalid format data'}), HTTP_400_BAD_REQUEST)

        logging.warning('Запрос на проверку oauth токена')

        is_token_valid = AccountData.is_token_valid(access_token)
        if is_token_valid:
            return make_response(jsonify({'message': 'Token is valid'}), HTTP_200_OK)

        return make_response(jsonify({'error': 'Token is invalid'}), HTTP_403_FORBIDDEN)
