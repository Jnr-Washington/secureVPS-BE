from urllib.parse import quote_plus
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    POSTGRES_USER: str = "securevps"
    POSTGRES_PASSWORD: str = "securevps_pass"
    POSTGRES_DB: str = "securevps_db"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432

    JWT_SECRET: str = "a8d337adcae3ee1a9f90bb7a3f23fc04"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    model_config = {"env_file": ".env", "extra": "ignore"}

    @property
    def DATABASE_URL(self) -> str:
        user = quote_plus(self.POSTGRES_USER)
        password = quote_plus(self.POSTGRES_PASSWORD)
        return (
            f"postgresql+asyncpg://{user}:{password}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


settings = Settings()
