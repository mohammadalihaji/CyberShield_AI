import os
import logging
from contextlib import contextmanager
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from database.base import Base

load_dotenv()

logger = logging.getLogger(__name__)

def build_engine():
    """
    Builds the SQLAlchemy engine using MySQL configuration if available,
    or falls back gracefully to SQLite if MySQL is unreachable.
    """
    db_url = os.getenv("DATABASE_URL")
    
    # If DB_USER or DB_HOST is explicitly set, attempt MySQL URL
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD", "")
    db_host = os.getenv("DB_HOST", "localhost")
    db_port = os.getenv("DB_PORT", "3306")
    db_name = os.getenv("DB_NAME", "cybershield_ai")
    
    if db_user and db_name:
        mysql_url = f"mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}?charset=utf8mb4"
        try:
            eng = create_engine(
                mysql_url,
                future=True,
                echo=False,
                pool_pre_ping=True,
                pool_recycle=3600,
                pool_size=10,
                max_overflow=20,
                isolation_level="READ COMMITTED"
            )
            # Test connectivity
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info(f"Connected successfully to MySQL Database '{db_name}' at {db_host}.")
            return eng
        except Exception as e:
            logger.warning(f"MySQL connection to {db_host} failed ({e}). Falling back to configured DATABASE_URL or SQLite.")

    if not db_url:
        db_url = "sqlite:///cybershield.db"

    # SQLite / standard URL initialization
    if db_url.startswith("sqlite"):
        eng = create_engine(
            db_url,
            future=True,
            echo=False,
            connect_args={"check_same_thread": False}
        )
    else:
        eng = create_engine(
            db_url,
            future=True,
            echo=False,
            pool_pre_ping=True,
            pool_recycle=3600
        )
    return eng

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