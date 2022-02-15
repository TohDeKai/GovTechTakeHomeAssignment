# Importing necessary packages
from pickle import TRUE
from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise import fields
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.contrib.fastapi import register_tortoise
from tortoise.models import Model
from passlib.hash import bcrypt

app = FastAPI()

class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique = TRUE)
    password_hash = fields.CharField(128)

    @classmethod
    async def get_user(cls, username):
        return cls.get(username = username)

    def verify_password(gself, password):
        return bcrypt.verify(password, self.password_hash)
    
User_Pydantic = pydantic_model_creator(User, name = "User")
UserIn_Pydantic = pydantic_model_creator(User, name = "UserIn", exclude_readonly = True)

@app.post("/users", response_model= User_Pydantic)
async def create_user(user: UserIn_Pydantic):
    user_obj = User(username = user.username, password_hash = bcrypt.hash(user.password_hash))
    await user_obj.save()
    return await User_Pydantic.from_tortoise_orm(user_obj)

ouath2_scheme = OAuth2PasswordBearer(tokenUrl = "token")

register_tortoise(
    app,
    db_url = "sqlite://db.sqlite3",
    modules = {"models" : ["main"]},
    generate_schemas = True,
    add_exception_handlers = True
)



# Endpoint to be called to generate token
# Token will represent who is logged in
@app.post("/token")
async def token(form_data: OAuth2PasswordRequestForm = Depends()):
    return {"access_token" : form_data.username + "token"}

# Endpoint for app to do something with the token
@app.get('/')
async def index(token: str = Depends(ouath2_scheme)):
    return {"the_token " : token }