# Importing necessary packages
from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

app = FastAPI()

ouath2_scheme = OAuth2PasswordBearer(tokenUrl = "token")

# Endpoint to be called to generate token
# Token will represent who is logged in
@app.post("/token")
async def token(form_data: OAuth2PasswordRequestForm = Depends()):
    return {"access_token" : form_data.username + "token"}

# Endpoint for app to do something with the token
@app.get('/')
async def index(token: str = Depends(ouath2_scheme)):
    return {"the_token " : token }