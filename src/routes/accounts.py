import bcrypt
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserResetPassword,
    TokenSchema,
    UserLoginRequestSchema,
    ResetPasswordCompleteRequestSchema,
    UserActivateRequestSchema,
    RefreshTokenRequest,
    AccessTokenResponse,
)
from security.interfaces import JWTAuthManagerInterface
from security.utils import generate_secure_token

router = APIRouter()
salt = bcrypt.gensalt()


# ----------------- Helper functions -----------------
async def get_user_by_email(db: AsyncSession, email: str, load_tokens: bool = False):
    query = select(UserModel).where(UserModel.email == email)
    if load_tokens:
        query = query.options(
            selectinload(UserModel.activation_token),
            selectinload(UserModel.password_reset_token),
        )
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def get_user_group(db: AsyncSession, name: str = "user"):
    result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == name))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=500, detail=f"User group '{name}' not found.")
    return group


async def validate_token(token_obj, provided_token, token_type="Token"):
    if not token_obj or token_obj.token != provided_token:
        raise HTTPException(status_code=400, detail=f"Invalid {token_type}.")
    if token_obj.expires_at and token_obj.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail=f"{token_type} expired.")


# ----------------- Routes -----------------
@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    existing_user = await get_user_by_email(db, data.email)
    if existing_user:
        raise HTTPException(status_code=409, detail="User already exists")

    group = await get_user_group(db)
    token = ActivationTokenModel(
        token=generate_secure_token(),
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    user = UserModel(email=data.email, group=group, activation_token=token)
    user.password = data.password  # hashed via setter

    try:
        async with db.begin():
            db.add(user)
        await db.refresh(user)
        return user
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )


@router.post("/activate")
async def activate(data: UserActivateRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, data.email, load_tokens=True)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.activation_token:
        raise HTTPException(status_code=400, detail="No activation token")

    await validate_token(
        user.activation_token, data.activation_token, token_type="Activation token"
    )

    try:
        async with db.begin():
            user.is_active = True
            await db.delete(user.activation_token)
        return {"message": "User account activated successfully."}
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="Failed to activate user account.")


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def password_reset(data: UserResetPassword, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, data.email)
    if user and user.is_active:
        token_obj = PasswordResetTokenModel(
            token=generate_secure_token(),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            user=user,
        )
        user.password_reset_token = token_obj
        try:
            async with db.begin():
                db.add(token_obj)
        except SQLAlchemyError:
            raise HTTPException(
                status_code=500, detail="Failed to generate password reset token."
            )

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/")
async def reset_password_complete(
    data: ResetPasswordCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_email(db, data.email, load_tokens=True)
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_obj = user.password_reset_token
    try:
        await validate_token(token_obj, data.token, token_type="Password reset token")
    except HTTPException:
        if token_obj:
            async with db.begin():
                await db.delete(token_obj)
        raise

    try:
        async with db.begin():
            user.password = data.password
            await db.delete(token_obj)
        await db.refresh(user)
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="Failed to reset password.")


@router.post("/login/", response_model=TokenSchema)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = await get_user_by_email(db, data.email)
    if not user or not user.verify_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        payload = {"user_id": user.id, "email": user.email}
        access_token = jwt_manager.create_access_token(payload)
        refresh_token_str = jwt_manager.create_refresh_token(payload)

        # Rotate refresh token: remove old if exists
        if existing := await db.execute(
            select(RefreshTokenModel).filter_by(user_id=user.id)
        ):
            old_token = existing.scalar_one_or_none()
            if old_token:
                async with db.begin():
                    await db.delete(old_token)

        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token_str,
            days_valid=settings.LOGIN_TIME_DAYS,
        )
        async with db.begin():
            db.add(refresh_token)
        await db.refresh(refresh_token)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token.token,
            "token_type": "bearer",
        }
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="Login failed.")


@router.post("/refresh/", response_model=AccessTokenResponse)
async def refresh_access_token(
    body: RefreshTokenRequest,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
):
    refresh_token = body.refresh_token

    try:
        payload = jwt_manager.decode_refresh_token(refresh_token)
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid token payload.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    result = await db.execute(select(RefreshTokenModel).filter_by(token=refresh_token))
    db_token = result.scalar_one_or_none()
    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    result = await db.execute(select(UserModel).filter_by(id=user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if db_token.user_id != user_id:
        raise HTTPException(status_code=400, detail="Token does not match user.")

    new_access_token = jwt_manager.create_access_token(
        {"user_id": user.id, "email": user.email}
    )
    return {"access_token": new_access_token}
