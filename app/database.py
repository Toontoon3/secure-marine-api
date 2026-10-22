from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.pool import NullPool
import logging

from app.config import settings

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Engine                                                              #
#                                                                      #
#  The engine is the core connection to PostgreSQL. It manages a      #
#  pool of persistent connections so the app does not open a new      #
#  TCP connection on every single request (which would be slow).      #
# ------------------------------------------------------------------ #

def _build_engine():
    """
    Build the SQLAlchemy engine with settings from config.
    Uses NullPool during testing so each test gets a clean connection.
    """
    connect_args = {}

    # PostgreSQL-specific: set a statement timeout so runaway queries
    # cannot hold the database hostage
    connect_args["options"] = "-c statement_timeout=30000"  # 30 seconds

    engine = create_engine(
        settings.DATABASE_URL,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        pool_pre_ping=True,      # test connections before using them
                                 # (drops stale connections automatically)
        echo=settings.DB_ECHO,   # log SQL — set True in .env for debugging
        connect_args=connect_args,
    )
    return engine


# engine = _build_engine()

import os
if os.environ.get("TESTING") != "true":
    engine = _build_engine()
else:
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


# ------------------------------------------------------------------ #
#  Session factory                                                     #
#                                                                      #
#  SessionLocal is a factory — calling SessionLocal() creates a new   #
#  database session. Sessions are the unit of work: all queries and   #
#  writes within one request share the same session and are           #
#  committed or rolled back together.                                  #
# ------------------------------------------------------------------ #

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,   # we control commits manually
    autoflush=False,    # we control flushes manually
    expire_on_commit=False,  # keep objects usable after commit
)


# ------------------------------------------------------------------ #
#  Base model class                                                    #
#                                                                      #
#  All ORM models (User, Dataset, AuditLog) inherit from Base.        #
#  SQLAlchemy uses this inheritance to know which classes are          #
#  database tables.                                                    #
# ------------------------------------------------------------------ #

class Base(DeclarativeBase):
    """
    Base class for all ORM models.

    Import this in every model file:
        from app.database import Base

    Then inherit from it:
        class User(Base):
            __tablename__ = "users"
            ...
    """
    pass


# ------------------------------------------------------------------ #
#  Dependency — get_db()                                              #
#                                                                      #
#  FastAPI calls this function for every request that needs the DB.   #
#  It creates a session, yields it to the endpoint, then closes it    #
#  when the request is done — even if an error occurred.             #
#                                                                      #
#  Usage in any endpoint:                                              #
#      from app.database import get_db                                 #
#      def my_endpoint(db: Session = Depends(get_db)):                #
#          user = db.query(User).first()                               #
# ------------------------------------------------------------------ #

def get_db():
    """
    Yield a database session for one request then close it.

    The try/finally block guarantees the session is always closed,
    even if an unhandled exception occurs inside the endpoint.
    This prevents connection leaks.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        # Roll back any uncommitted changes if something went wrong
        db.rollback()
        raise
    finally:
        db.close()


# ------------------------------------------------------------------ #
#  Health check helper                                                 #
#                                                                      #
#  Used by the /health endpoint in main.py to verify the database     #
#  is reachable before reporting the service as healthy.              #
# ------------------------------------------------------------------ #

def check_database_connection() -> bool:
    """
    Return True if the database is reachable, False otherwise.
    Runs a lightweight SELECT 1 query.
    """
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False


# ------------------------------------------------------------------ #
#  Table creation helper                                               #
#                                                                      #
#  Creates all tables that don't exist yet. Used as a fallback        #
#  when Alembic migrations haven't been run. In production, always    #
#  use Alembic — never rely on create_all() there.                   #
# ------------------------------------------------------------------ #

def create_tables():
    """
    Create all tables defined in ORM models if they do not exist.

    Call this from main.py on startup (development only).
    In production, run: alembic upgrade head
    """
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables verified / created successfully.")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise