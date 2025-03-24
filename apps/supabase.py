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

async def test_supabase_auth():
    try:
        client = get_supabase()
        
        is_initialized = client is not None and client.auth is not None

        # Check if we can access auth configuration
        # This won't actually return sensitive data but will verify connection
        project_id = "unknown"
        if url:
            # The URL format is typically https://{project-id}.supabase.co
            parts = url.replace("https://", "").split(".")
            if len(parts) > 0:
                project_id = parts[0]
        
        # Try to get more info if possible
        try:
            session = client.auth.get_session()
            session_info = "Available" if session else "Not available"
        except:
            session_info = "Error accessing session"
        
        return {
            "status": "connected" if is_initialized else "error",
            "message": "Successfully connected to Supabase Auth",
            "client_initialized": is_initialized,
            "project_id": project_id,
            "project_url": url,
            "session_info": session_info
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to connect to Supabase Auth: {str(e)}"
        }

async def get_current_user(token:str = Depends(oauth2_scheme)):
    client=get_supabase()
    try:
        user = client.auth.get_user(token)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inavlid Authentication credentials", headers={"WWW-Authenticate":"Bearer"})
        return user 
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inavlid Authentication credentials", headers={"WWW-Authenticate":"Bearer"})
    
# sign up function here
async def signup(user_data: UserSignup):
    client=get_supabase()
    
    if user_data.confirm_password and user_data.password != user_data.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password don't match")
    try:
        auth_response = client.auth.sign_up({
            "email":user_data.email,
            "password":user_data.password,
            "options":{
                "redirectTo":"https://arbigobot.com/sign-in"
            }
        })

        if auth_response.user:
            return {
                "message":"Registration successful",
                "user_id":auth_response.user.id,
                "email":auth_response.user.email,
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Registration failed: Please try again"
            )

        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"registration failed: {str(e)}"
        )
    
class VerifyEmailRequest(BaseModel):
    email: str
    token: str

async def verify_email_token(email: str, token: str):
    client = get_supabase()
    try:
        response = client.auth.verify_otp(
            email=email,
            token=token,
            type="email"
        )
        return response is not None
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=f"Email verification failed: {str(e)}"
        )
    #     decoded_token = jwt.decode(token, jwt_key, algorithms=["HS256"])
    #     user = await User.find_one({"email": decoded_token['email']})
    #     if user and not user.email_confirmed:
    #         # Mark user as confirmed
    #         user.email_confirmed = True
    #         await user.save()
    #         return True
    #     return False

    # except jwt.ExpiredSignatureError:
    #     return False
    # except jwt.DecodeError:
    #     return False


# sign in function here
async def signin(user_credentials: UserSignIn):
    client = get_supabase()

    try: 
        auth_response = client.auth.sign_in_with_password({
            "email":user_credentials.email,
            "password":user_credentials.password,
        })

        print(auth_response.session)

        return {
            "email":user_credentials.email,
            "access_token": auth_response.session.access_token,
            "token_type":"bearer"
        }
    except Exception as e:
        print(f"Debug - {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"credentials invalid or {str(e)}"
        )
    
# sign out function here
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

async def request_password_reset(reset_req: PasswordResetRequest):
    client = get_supabase()
    try:
        response = client.auth.reset_password_for_email(reset_req.email)
        print(response)
        return {"messages": "If your email is registered, then check your email inbox"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Email sending error: {str(e)}"
        )
    
class PasswordResetConfirm(BaseModel):
    token: str
    password: str
    confirmPassword: str

async def confirm_password_rest(reset_data: PasswordResetConfirm):
    client=get_supabase()
    if reset_data.password != reset_data.confirmPassword:
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
