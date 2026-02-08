
from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators

from database.models.accounts import UserGroupEnum


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    def check_password_length(cls, v):
        accounts_validators.validate_password_strength(v)
        return v

    @field_validator("email")
    def check_email_address(cls, v):
        accounts_validators.validate_email(v)
        return v


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserResetPassword(BaseModel):
    email: EmailStr


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserActivateRequestSchema(UserResetPassword):
    token: str


class ResetPasswordCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class AccessTokenResponse(BaseModel):
    access_token: str
