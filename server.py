# тест комитта
import base64
import hmac
import hashlib

from typing import Optional
from os import name
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response
from starlette.routing import request_response


app = FastAPI()

SECRET_KEY = "5e5a93bdfea79fae4edd6468902e5d89756dc25736d1de2b5d9f3b5d24e1d6cf"
PASSWORD_SALT = '59f3e9a8ac6ad2c2a1bff25483a915af4a51c06d1186623953f5cd4f37e05777'

def sign_data(data: str) -> str:
    """Возваращает подписанные данные"""
    return hmac.new(
        SECRET_KEY.encode(), 
        msg=data.encode(), 
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_usrname_from_signed_string(username_signed: str) -> Optional[str]:
    """Возваращает username из Подписанных Cookies"""
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return password_hash == stored_password_hash



users = {
    'ilaya@yandex.ru':{
        'name': 'ilya@user.com',
        'password': 'ef0abeffebcf7aa8ccd16fe71e0c6e2fff266d90d3a1b89756bc681cfef8ca13',
        'balance': 100000
    },
    'petr@kek.ru':{
        'name': 'Пётр',
        'password': '42caaf48d14e8fdecf67ddd824d2d37d547a17d5de8599400adbac14aa5a5dec',
        'balance': 555555
    }
}

@app.get('/')
def index_page(username : Optional[str] = Cookie(default = None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_usrname_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key="username") 
        return response
    try: 
        user = users[valid_username]        
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key="username")
        return response
    return Response(f"Привет, {users[valid_username]['name']}!", media_type='text/html')


@app.post("/login")
def process_login_page(username : str = Form(...), password : str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response('Я вас не знаю!', media_type='text/html') 

    response = Response(f"Привет {user['name']}, Баланс {user['balance']}", media_type="text/html")
    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username) 
    response.set_cookie(key="username", value=username_signed)
    return response
