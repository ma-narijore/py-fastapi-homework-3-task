import bcrypt

from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)

router = APIRouter()
salt = bcrypt.gensalt()

@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register(
        data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == data.email)
    )
    if result.scalar_one_or_none():
        raise HTTPException(409, "User already exists")

    try:
        hashed_password = bcrypt.hashpw(
            data.password.encode(),
            bcrypt.gensalt()
        ).decode()

        group_name = data.group or UserGroupEnum.USER

        result = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == group_name)
        )
        group = result.scalar_one()

        user = UserModel(
            email=data.email,
            password=hashed_password,
            group=group
        )

        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user


    except:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"An error occurred during user creation."
        )

