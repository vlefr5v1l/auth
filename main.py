import hashlib
import base64
import hmac
import json
from token import OP
from typing import Optional
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response

from users import users

app = FastAPI()

SECRET_KEY = '48b14941ddca9f14acf5405e2785d438788dfa76260457a6b45c6186df6a36f7'
PASSWORD_SALT = '976e3672c048a775ff47ec6cb8421e75d566e30031cb7535a9cd9a8392bbf24d'

def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password+ PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return password_hash == stored_password_hash




def sign_data(data: str) -> str:
    '''
    Подписывает cookie файлы username
    '''
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r', encoding='utf-8') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    return Response(f'Привет {users[valid_username]["name"]}', media_type='text/html')


@app.post('/login')
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    print('user us ', user, 'password', password)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success":False,
                "message": 'Я вас не знаю'
                        }), 
                        media_type='application/json')
    response = Response(
        json.dumps({
            'success': True,
            'message': f'Ваш логин {username}, пароль {password}'
        }),
        media_type='application/json')
    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    response.set_cookie(key='username', value=username_signed)
    return response