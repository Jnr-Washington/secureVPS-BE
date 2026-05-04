import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from models.user import User, Session
from core.security import hash_password, verify_password, create_access_token
from core.exceptions import credentials_exception, duplicate_email_exception
from core.config import settings


async def register_user(email: str, password: str, db: AsyncSession) -> User:
    result = await db.execute(select(User).where(User.email == email))
    if result.scalar_one_or_none():
        raise duplicate_email_exception
    user = User(email=email, hashed_password=hash_password(password))
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def login_user(email: str, password: str, db: AsyncSession) -> tuple[str, str]:
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(password, user.hashed_password):
        raise credentials_exception
    return await _create_tokens(user.id, db)


async def refresh_session(refresh_token: str, db: AsyncSession) -> tuple[str, str]:
    result = await db.execute(select(Session).where(Session.refresh_token == refresh_token))
    session = result.scalar_one_or_none()
    if not session or session.expires_at < datetime.now(timezone.utc):
        raise credentials_exception
    user_id = session.user_id
    await db.delete(session)
    await db.commit()
    return await _create_tokens(user_id, db)


async def logout_user(refresh_token: str, db: AsyncSession) -> None:
    await db.execute(delete(Session).where(Session.refresh_token == refresh_token))
    await db.commit()


async def _create_tokens(user_id: str, db: AsyncSession) -> tuple[str, str]:
    access_token = create_access_token(user_id)
    refresh_token = str(uuid.uuid4())
    session = Session(
        user_id=user_id,
        refresh_token=refresh_token,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(session)
    await db.commit()
    return access_token, refresh_token
