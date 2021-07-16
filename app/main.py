import os
import os
import random
import string
import time
import urllib
from datetime import timedelta, datetime, date
from json import JSONEncoder
from secrets import compare_digest

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi_login import LoginManager
from fastapi_login.exceptions import InvalidCredentialsException
# from gunicorn.app.base import BaseApplication
# from gunicorn.glogging import Logger
from loguru import logger
from passlib.context import CryptContext

# from starlette import status


load_dotenv(dotenv_path=".env")
tags_metadata = [
    {
        "name": "Auth",
        "description": "Token-based authorization/authentication.",
    },
]

app = FastAPI(
    name="Login Page App Template",
    title="Integration Audit Tool",
    version="0.0.1",
    openapi_tags=tags_metadata
)

SECRET = os.getenv('SECRET')
manager = LoginManager(
    SECRET,
    token_url='/integration-audit-tool/auth/login',
    use_cookie=True
)
manager.cookie_name = "audit-access"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/integration-audit-tool/auth/token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)




user_store = {
    'users': {
        'karl@karlmarxindustries.com': {
            'name': 'Karl Marx',
            'hashed_password': os.getenv('HASHED_PASS')
        }
    }
}


def query_user(user_id: str):
    """
    Get a user from the db
    :param user_id: E-Mail of the user
    :return: None or the user object
    """
    return user_store['users'].get(user_id)


app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


# jinja custom filters
def is_list(value):
    return isinstance(value, list)


@app.middleware("http")
async def log_with_processing_time(request: Request, call_next):
    idem = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    logger.debug(f"rid={idem} start request path={request.url.path}")
    start_time = time.time()

    response = await call_next(request)

    process_time = (time.time() - start_time) * 1000
    formatted_process_time = "{0:.2f}".format(process_time)
    logger.debug(
        f"rid={idem} \
          completed_in={formatted_process_time}ms \
          status_code={response.status_code}"
    )
    response.headers["X-Processing-Time"] = formatted_process_time
    if ("html" in request.headers['accept'] or "html" in request.headers[
        'Accept']) and response.status_code == status.HTTP_401_UNAUTHORIZED:
        response = templates.TemplateResponse("login.j2.html", {"request": request,
                                                                "original_path": urllib.parse.quote_plus(
                                                                    request.url.path)})

    return response


@manager.user_loader
def query_user(user_id: str):
    return user_store['users'][user_id]


@app.post('/auth/login', tags=['Auth'])
def login(get_cookie: bool = False, data: OAuth2PasswordRequestForm = Depends(),
          original_path: str = "/docs"):
    email = data.username
    password = data.password

    try:
        user = query_user(email)
    except KeyError:
        raise InvalidCredentialsException
    if not user:
        # you can return any response or error of your choice
        raise InvalidCredentialsException
    # elif password != user['password']:
    elif compare_digest(get_password_hash(password), user['hashed_password']):
        raise InvalidCredentialsException

    access_token = manager.create_access_token(
        data={'sub': email},
        expires=timedelta(hours=8)
    )
    if get_cookie:
        resp = RedirectResponse(url=f"{original_path}", status_code=status.HTTP_302_FOUND)
        manager.set_cookie(resp, access_token)
        # manager.set_cookie(resp, access_token)
        # resp.status_code = 200
        return resp
    else:
        return {"access_token": access_token, "token_type": "bearer"}


@app.get('/auth/logout', response_class=HTMLResponse, include_in_schema=False, tags=["Auth"])
def protected_route(request: Request, user=Depends(manager)):
    resp = RedirectResponse(url="/docs", status_code=status.HTTP_302_FOUND)
    manager.set_cookie(resp, "")
    return resp


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def loginwithCreds(request: Request, response_class: HTMLResponse):
    return RedirectResponse(url=f"/docs", status_code=status.HTTP_302_FOUND)



# subclass JSONEncoder
class DateTimeEncoder(JSONEncoder):
    # Override the default method
    def default(self, obj):
        if isinstance(obj, (date, datetime)):
            return obj.isoformat()


if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8001)
