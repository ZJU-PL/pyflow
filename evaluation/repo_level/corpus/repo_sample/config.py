from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    token_secret: str
    max_retries: int = 3


def load_settings() -> Settings:
    data_root = Path(os.environ.get("REPO_SAMPLE_DATA", "/tmp/repo_sample"))
    secret = os.environ.get("REPO_SAMPLE_SECRET", "dev-only-secret")
    retries = int(os.environ.get("REPO_SAMPLE_RETRIES", "3"))
    return Settings(data_dir=data_root, token_secret=secret, max_retries=retries)
