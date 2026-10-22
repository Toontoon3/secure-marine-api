import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app

# ------------------------------------------------------------------ #
#  Test database                                                       #
#                                                                      #
#  We use an in-memory SQLite database for tests.                     #
#  This means:                                                         #
#    - No PostgreSQL needed to run tests                              #
#    - Each test run starts with a clean database                     #
#    - Tests run fast — SQLite is in-memory                           #
#    - Tests never touch your real data                               #
# ------------------------------------------------------------------ #

TEST_DATABASE_URL = "sqlite://"   # empty string = pure in-memory

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,    # share one connection across threads
)

TestingSessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)


def override_get_db():
    """Replace the real DB session with a test session."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


# ------------------------------------------------------------------ #
#  Fixtures                                                            #
#                                                                      #
#  Fixtures are reusable setup functions. pytest injects them         #
#  automatically into any test function that declares them            #
#  as parameters.                                                      #
# ------------------------------------------------------------------ #

@pytest.fixture(scope="function")
def db():
    """
    Create a fresh database for each test function.
    Tables are created before the test and dropped after.
    This guarantees tests are fully isolated from each other.
    """
    Base.metadata.create_all(bind=engine)
    yield TestingSessionLocal()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    """
    Create a FastAPI TestClient with the test database injected.
    The real get_db() is replaced with override_get_db() so all
    database calls during tests go to SQLite, not PostgreSQL.
    """
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def registered_user(client):
    """
    Register a test user and return their data.
    Used by tests that need an existing account.
    """
    response = client.post("/auth/register", json={
        "email": "test@marine-institute.ie",
        "password": "T3stP@ssword123!",
        "full_name": "Test Researcher",
        "institution_id": "marine-institute-ireland",
    })
    assert response.status_code == 201
    return response.json()


@pytest.fixture
def auth_headers(client, registered_user):
    """
    Log in a test user and return Authorization headers.
    Used by tests that need an authenticated request.

    Usage in a test:
        def test_something(client, auth_headers):
            response = client.get("/auth/me", headers=auth_headers)
    """
    response = client.post("/auth/login", json={
        "email": "test@marine-institute.ie",
        "password": "T3stP@ssword123!",
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_csv(tmp_path):
    """
    Create a small temporary CSV file for upload tests.
    tmp_path is a pytest built-in that gives a temporary directory.
    """
    csv_file = tmp_path / "test_data.csv"
    csv_file.write_text(
        "depth_m,temperature_c,salinity_psu,latitude,longitude\n"
        "0,15.2,34.1,51.5,-8.3\n"
        "10,14.8,34.2,51.5,-8.3\n"
        "50,12.1,34.5,51.5,-8.3\n"
        "100,10.3,34.8,51.5,-8.3\n"
    )
    return csv_file