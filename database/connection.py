import os
import ssl
import logging
from contextlib import contextmanager
from urllib.parse import quote_plus, urlsplit, urlunsplit, parse_qsl, urlencode

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from database.base import Base

load_dotenv()

logger = logging.getLogger(__name__)


def _ssl_connect_args():
    """
    Aiven MySQL requires TLS. PyMySQL does not understand ssl-mode=REQUIRED
    on the URL, so the CA certificate is passed as a connect argument.
    """
    ca_path = os.getenv("SSL_CA", "certs/ca.pem")
    ca_abs = os.path.abspath(ca_path)
    if os.path.isfile(ca_abs):
        ctx = ssl.create_default_context(cafile=ca_abs)
        logger.info("MySQL TLS enabled with CA file %s", ca_abs)
    else:
        ctx = ssl.create_default_context()
        logger.warning("SSL_CA file not found at %s; using default trust store.", ca_abs)
    return {"ssl": ctx}


def _normalize_mysql_url(url: str) -> str:
    """Turn an Aiven Service URI into a SQLAlchemy PyMySQL URL."""
    url = url.strip()
    if url.startswith("mysql://"):
        url = "mysql+pymysql://" + url[len("mysql://"):]

    parts = urlsplit(url)
    query = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key.lower() not in {"ssl-mode", "ssl_mode", "sslmode"}
    ]
    if "charset" not in {key for key, _ in query}:
        query.append(("charset", "utf8mb4"))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def _mysql_url_from_parts() -> str | None:
    db_user = os.getenv("DB_USER", "").strip()
    db_host = os.getenv("DB_HOST", "").strip()
    db_name = os.getenv("DB_NAME", "").strip()
    if not (db_user and db_host and db_name):
        return None

    db_password = quote_plus(os.getenv("DB_PASSWORD", ""))
    db_port = os.getenv("DB_PORT", "3306").strip() or "3306"
    user = quote_plus(db_user)
    return (
        f"mysql+pymysql://{user}:{db_password}@{db_host}:{db_port}/{db_name}"
        "?charset=utf8mb4"
    )


def _create_mysql_engine(mysql_url: str):
    safe_target = urlsplit(mysql_url).hostname or "mysql"
    eng = create_engine(
        mysql_url,
        future=True,
        echo=False,
        pool_pre_ping=True,
        pool_recycle=3600,
        pool_size=5,
        max_overflow=10,
        isolation_level="READ COMMITTED",
        connect_args=_ssl_connect_args(),
    )
    with eng.connect() as conn:
        conn.execute(text("SELECT 1"))
    logger.info("Connected successfully to MySQL at %s.", safe_target)
    return eng


def build_engine():
    """
    Uses Aiven/MySQL when DATABASE_URL or DB_HOST/DB_USER/DB_NAME are set.
    SQLite is used only when no MySQL settings exist. A failed MySQL
    connection is not hidden behind SQLite, so tables are not created
    in the wrong database.
    """
    db_url = (os.getenv("DATABASE_URL") or "").strip()

    # The Aiven Service URI belongs in DATABASE_URL and overrides the split DB_* vars.
    if db_url.startswith(("mysql://", "mysql+pymysql://")):
        mysql_url = _normalize_mysql_url(db_url)
    else:
        mysql_url = _mysql_url_from_parts()

    if mysql_url:
        try:
            return _create_mysql_engine(mysql_url)
        except Exception as exc:
            logger.error(
                "MySQL connection failed (%s). Refusing SQLite fallback because "
                "MySQL settings are present. Check Render env vars and SSL_CA.",
                exc,
            )
            raise

    if not db_url:
        db_url = "sqlite:///cybershield.db"

    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    if db_url.startswith("sqlite"):
        logger.info("Using SQLite database (no MySQL settings found).")
        return create_engine(
            db_url,
            future=True,
            echo=False,
            connect_args={"check_same_thread": False},
        )

    return create_engine(
        db_url,
        future=True,
        echo=False,
        pool_pre_ping=True,
        pool_recycle=3600,
    )

engine = build_engine()

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False
)

@contextmanager
def get_db_session():
    """
    ACID Compliant Database Session Context Manager.
    Guarantees automatic rollback on error and proper session closure.
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Transaction rollback triggered due to error: {e}")
        raise e
    finally:
        session.close()

def init_db():
    """
    Initializes database tables according to defined SQLAlchemy models.
    """
    try:
        # Import all models to ensure metadata registration
        import models
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables verified and initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database tables: {e}")
        raise e