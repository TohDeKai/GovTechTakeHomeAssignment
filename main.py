# Importing necessary packages
from lib2to3.pgen2 import token
import jwt
from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise import fields
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.contrib.fastapi import register_tortoise
from tortoise.models import Model
from passlib.hash import bcrypt

app = FastAPI()

JWT_SECRET = "Hello world"

class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique = True)
    password_hash = fields.CharField(128)

    @classmethod
    async def get_user(cls, username):
        return cls.get(username = username)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)
    
User_Pydantic = pydantic_model_creator(User, name = "User")
UserIn_Pydantic = pydantic_model_creator(User, name = "UserIn", exclude_readonly = True)

@app.post("/users", response_model= User_Pydantic)
async def create_user(user: UserIn_Pydantic):
    user_obj = User(username = user.username, password_hash = bcrypt.hash(user.password_hash))
    await user_obj.save()
    return await User_Pydantic.from_tortoise_orm(user_obj)

ouath2_scheme = OAuth2PasswordBearer(tokenUrl = "token")

async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user

# Endpoint to be called to generate token
# Token will represent who is logged in
@app.post("/token")
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)

    if not user:
        return {"error" : "invalid credentials"}
    
    user_obj = await User_Pydantic.from_tortoise_orm(user)

    token = jwt.encode(user_obj.dict(), JWT_SECRET)

    return {"access_token" : token, "token_type" : "bearer"}

register_tortoise(
    app,
    db_url = "sqlite://db.sqlite3",
    modules = {"models" : ["main"]},
    generate_schemas = True,
    add_exception_handlers = True
)

