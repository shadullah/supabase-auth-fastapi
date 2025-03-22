import os
from supabase import create_client, Client
from dotenv import load_dotenv
load_dotenv('.env')
import random

from pydantic import BaseModel,EmailStr
from typing import Optional
from fastapi import HTTPException,status,Depends
from fastapi.security import OAuth2PasswordBearer

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)


class UserSignup(BaseModel):
    email:EmailStr
    password:str
    confirm_password: Optional[str]= None

class UserSignIn(BaseModel):
    email:EmailStr
    password:str 

class Token(BaseModel):
    access_token:str 
    token_type:str 

def get_supabase()->Client:
    if not url or not key:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Supabase configuration is missing")
    return create_client(url,key)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/signin")

async def get_current_user(token:str = Depends(oauth2_scheme)):
    client=get_supabase()
    try:
        user = client.auth.get_user(token)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inavlid Authentication credentials", headers={"WWW-Authenticate":"Bearer"})
        return user 
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inavlid Authentication credentials", headers={"WWW-Authenticate":"Bearer"})
    
async def signup(user_data: UserSignup):
    client=get_supabase()
    
    if user_data.confirm_password and user_data.password != user_data.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password don't match")
    try:
        auth_response = client.auth.sign_up({
            "email":user_data.email,
            "password":user_data.password
        })

        # if auth_response.user:
        #     user_id=random.randint(0,1000000)
            
        #     client.table("users").insert({
        #         "id": user_id,
        #         "email":user_data.email
        #     }).execute()

        if auth_response.user and not auth_response.session:
            return {
                "message":"Registration successful. please check you mail",
                "user_id":auth_response.user.id,
                "email":auth_response.user.email
            }
        elif auth_response.user and auth_response.session:
            return {
            "access_token": auth_response.session.access_token,
            "token_type":"bearer"
        }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Registration failed: "
            )

        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"registration failed: {str(e)}"
        )

async def signin(user_credentials: UserSignIn):
    client = get_supabase()

    try: 
        auth_response = client.auth.sign_in_with_password({
            "email":user_credentials.email,
            "password":user_credentials.password,
        })

        return {
            "email":user_credentials.email,
            "access_token": auth_response.session.access_token,
            "token_type":"bearer"
        }
    except Exception as e:
        print(f"Debug - {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid email or password or {str(e)}"
        )
    
async def signout(current_user):
    client = get_supabase()
    try:
        client.auth.sign_out()
        return {"message":"Successfully Logged out"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Logout failed: {str(e)}"
        )
    
class PasswordResetRequest(BaseModel):
    email:EmailStr

class PasswordResetConfirm(BaseModel):
    token:str 
    password:str 
    confirm_password:str 

async def request_password_reset(reset_req: PasswordResetRequest):
    client = get_supabase()
    try:
        response = client.auth.reset_password_email(reset_req.email)
        print(response)
        return {"message": "If your email is registered, then check your email inbox"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Email sending error: {str(e)}"
        )
    
async def confirm_password_rest(reset_data: PasswordResetConfirm):
    client=get_supabase()
    if reset_data.password != reset_data.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password don't match")
    try:
        client.auth.set_session(reset_data.token,reset_data.token)
        response = client.auth.update_user(
            {
                "password": reset_data.password
            }
        )
        print(response)
        return {
            "message":"Password reset successful"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"password reset error: {str(e)}"
        )
