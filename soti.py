import requests
import os
from dotenv import load_dotenv

load_dotenv()

PATH_DEVICE = os.getenv("PATH_DEVICE")

def login():
    LOGIN_KEY = os.getenv("LOGIN_KEY")
    LOGIN_URL = os.getenv("LOGIN_URL")

    login_headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {LOGIN_KEY}'
        }

    login_body = {
        'grant_type': os.getenv("GRANT_TYPE"),
        'username': os.getenv("USERNAME"),
        'password': os.getenv("PASSWORD")
    }

    response_login = requests.post(LOGIN_URL, headers=login_headers, data=login_body)
    return response_login.json()["access_token"]


def lista_equipamentos():
    PATH_FOLDER = os.getenv("PATH_FOLDER")
    get_devices = f"{PATH_DEVICE}?path={PATH_FOLDER}&take=60"
    return requests.get(get_devices, headers=request_headers).json()


def cadastro_usuario_soti(deviceId, customAttributeName, dado):
    url = f"{PATH_DEVICE}/{deviceId}/customAttributes/{customAttributeName}"
    return requests.put(url, headers=request_headers, data=dado)


def alterar_pasta_soti(deviceId, usuario):
    if usuario == "operador":
        usuario = "'\\\\\\\\Quebeck\\\\Testes\\\\ControleAtivos\\\\Operador'"
    elif usuario == "administrador":
        usuario = "'\\\\\\\\Quebeck\\\\Testes\\\\ControleAtivos\\\\Administrador'"
    url = f"{PATH_DEVICE}/{deviceId}/parentPath"
    return requests.put(url, headers=request_headers, data=usuario)


request_key = login()

request_headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {request_key}',
    'Accept': 'application/json'
}



