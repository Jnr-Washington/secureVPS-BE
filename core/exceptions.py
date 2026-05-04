from fastapi import HTTPException, status

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid or expired credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

duplicate_email_exception = HTTPException(
    status_code=status.HTTP_409_CONFLICT,
    detail="Email already registered",
)
