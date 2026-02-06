import string

from pydantic import BaseModel, EmailStr, field_validator, Field

from database import accounts_validators

from database.models.accounts import UserGroupEnum


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str
    group: UserGroupEnum = None

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
