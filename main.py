import apps 
import sys
from pathlib import Path
from typing import Dict

from fastapi import FastAPI,Depends,status,BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import apps.supabase
from sib_api_v3_sdk import Configuration, ApiClient
import sib_api_v3_sdk
from sib_api_v3_sdk.api.transactional_emails_api import TransactionalEmailsApi
from sib_api_v3_sdk.models import SendSmtpEmail,SendSmtpEmailTo

# project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

app = FastAPI(title="Testing Authentication")
app.add_middleware(
    CORSMiddleware
)

import os
from supabase import create_client, Client

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

@app.get("/", tags=["home"])
async def root()->Dict[str,str]:
    return {"status":"ok"}

# testing users here with get request --------------- initial testing apis if connected with supabase or not
@app.get("/users")
def allUsers_route():
    try:
        users = supabase.table("users").select("*").execute()
        print(f"Query response: {users}")  # Add debugging
        return users
    except Exception as e:
        print(f"Error: {e}")
        return {"error": str(e)}
    
import random
from pydantic import BaseModel,EmailStr

class UsersSchema(BaseModel):
    email:EmailStr

@app.post("/users", status_code=status.HTTP_200_OK)
def createUser(user:UsersSchema):
    id=random.randint(0,1000000)
    user = supabase.table("users").insert({
        "id":id,
        "email":user.email
    }).execute()
    return user
# ------------------------------------------

@app.post("/auth/signup", tags=["auth"], summary="Register a new user")
async def signup_route(user_data: apps.supabase.UserSignup):
    return await apps.supabase.signup(user_data)

configuration = Configuration()
configuration.api_key['api-key']= os.environ.get("BREVO_KEY")

api_client = ApiClient(configuration)
api_instance = TransactionalEmailsApi(api_client)

class EmailSchema(BaseModel):
    email:str 

@app.post("/send-email")
async def send_email(email:EmailSchema,background_tasks: BackgroundTasks):
    def send():
        email_data = SendSmtpEmail(
            to=[SendSmtpEmailTo(email=email.email)],
            subject="Test Email from FastAPI",
            html_content="<html><body><h1>This is a test email from FastAPI using Brevo!</h1></body></html>",
            sender={"email": "hexaalif2020@gmail.com"}
        )
        api_instance.send_transac_email(email_data)
    
    background_tasks.add_task(send)
    return {"message": "Email sent via Brevo"}





@app.post("/auth/signin", tags=["auth"], summary="login a user")
async def signin_route(user_credentials: apps.supabase.UserSignIn):
    return await apps.supabase.signin(user_credentials)

@app.post("/auth/signout", tags=["auth"], summary="log the current user")
async def signout_route(current_user= Depends(apps.supabase.get_current_user)):
    return await apps.supabase.signout(current_user)

@app.get("/auth/me", tags=["auth"], summary="get current user")
def getLoggedInUser(current_user=Depends(apps.supabase.get_current_user)):
    return{
        "token": current_user
    }

# testing token if exists
@app.get("/auth/test-auth", tags=["auth"], summary="Test authentication")
async def test_auth(current_user = Depends(apps.supabase.get_current_user)):
    return {"message": "Authentication successful", "user": current_user.user.email}

@app.post("/auth/reset-password", tags=["auth"], summary="request password reset")
async def request_reset_route(reset_req: apps.supabase.PasswordResetRequest):
    return await apps.supabase.request_password_reset(reset_req)

@app.post("/auth/reset-confirm", tags=["auth"], summary="confirm password reset")
async def confirm_reset_route(reset_data: apps.supabase.PasswordResetConfirm):
    return await apps.supabase.confirm_password_rest(reset_data)

