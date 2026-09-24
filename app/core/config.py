from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    app_name: str = "AIPEN"
    host: str = "127.0.0.1"
    port: int = 8000
    data_dir: Path = Path("data")
    database_name: str = "aipen.db"

    @property
    def database_path(self) -> Path:
        return self.data_dir / self.database_name


settings = Settings()
