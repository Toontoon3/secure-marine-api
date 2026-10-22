import pytest


# ------------------------------------------------------------------ #
#  Registration tests                                                  #
# ------------------------------------------------------------------ #

class TestRegister:

    def test_register_success(self, client):
        """
        Happy path — valid data creates a new account.
        Confirms: 201 status, correct fields returned,
        password never appears in response.
        """
        response = client.post("/auth/register", json={
            "email": "goodness@marine-institute.ie",
            "password": "M@rineSecure2024!",
            "full_name": "Goodness Oluwayinka",
            "institution_id": "marine-institute-ireland",
        })

        assert response.status_code == 201
        data = response.json()

        # Correct fields returned
        assert data["email"] == "goodness@marine-institute.ie"
        assert data["full_name"] == "Goodness Oluwayinka"
        assert data["institution_id"] == "marine-institute-ireland"
        assert data["role"] == "researcher"
        assert data["is_active"] is True

        # UUID was generated
        assert "id" in data
        assert len(data["id"]) == 36   # UUID format

        # SECURITY: password must never appear in any response
        assert "password" not in data
        assert "hashed_password" not in data

    def test_register_duplicate_email(self, client):
        """
        Registering twice with the same email returns 409 Conflict.
        """
        payload = {
            "email": "duplicate@marine-institute.ie",
            "password": "M@rineSecure2024!",
        }
        client.post("/auth/register", json=payload)
        response = client.post("/auth/register", json=payload)

        assert response.status_code == 409
        assert "already exists" in response.json()["detail"].lower()

    def test_register_weak_password_too_short(self, client):
        """
        Password under 12 characters is rejected with 422.
        """
        response = client.post("/auth/register", json={
            "email": "test@marine.ie",
            "password": "Short1!",
        })
        assert response.status_code == 422

    def test_register_weak_password_no_special_char(self, client):
        """
        Password without a special character is rejected.
        """
        response = client.post("/auth/register", json={
            "email": "test@marine.ie",
            "password": "NoSpecialChar123",
        })
        assert response.status_code == 422

    def test_register_invalid_email(self, client):
        """
        Malformed email address is rejected with 422.
        """
        response = client.post("/auth/register", json={
            "email": "not-an-email",
            "password": "M@rineSecure2024!",
        })
        assert response.status_code == 422

    def test_register_email_normalised_to_lowercase(self, client):
        """
        Email is normalised to lowercase during registration.
        """
        response = client.post("/auth/register", json={
            "email": "GOODNESS@MARINE-INSTITUTE.IE",
            "password": "M@rineSecure2024!",
        })
        assert response.status_code == 201
        assert response.json()["email"] == "goodness@marine-institute.ie"


# ------------------------------------------------------------------ #
#  Login tests                                                         #
# ------------------------------------------------------------------ #

class TestLogin:

    def test_login_success(self, client, registered_user):
        """
        Happy path — correct credentials return JWT tokens.
        Confirms: 200 status, access_token present, token_type=bearer.
        """
        response = client.post("/auth/login", json={
            "email": "test@marine-institute.ie",
            "password": "T3stP@ssword123!",
        })

        assert response.status_code == 200
        data = response.json()

        # Tokens returned
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 1800   # 30 min in seconds

        # Token is a non-empty string
        assert isinstance(data["access_token"], str)
        assert len(data["access_token"]) > 20

        # User profile embedded in response
        assert "user" in data
        assert data["user"]["email"] == "test@marine-institute.ie"
        assert data["user"]["role"] == "researcher"

        # SECURITY: password never in response
        assert "password" not in data["user"]
        assert "hashed_password" not in data["user"]

    def test_login_wrong_password(self, client, registered_user):
        """
        Wrong password returns 401.
        Same error as wrong email — prevents user enumeration.
        """
        response = client.post("/auth/login", json={
            "email": "test@marine-institute.ie",
            "password": "WrongPassword999!",
        })
        assert response.status_code == 401
        assert "incorrect" in response.json()["detail"].lower()

    def test_login_wrong_email(self, client):
        """
        Non-existent email returns 401 — same message as wrong password.
        """
        response = client.post("/auth/login", json={
            "email": "nobody@nowhere.ie",
            "password": "M@rineSecure2024!",
        })
        assert response.status_code == 401
        # Same error message as wrong password — prevents enumeration
        assert "incorrect" in response.json()["detail"].lower()

    def test_login_same_error_for_bad_email_and_bad_password(
        self, client, registered_user
    ):
        """
        SECURITY TEST: wrong email and wrong password return identical
        error messages. An attacker cannot determine which was wrong.
        """
        bad_email_response = client.post("/auth/login", json={
            "email": "nonexistent@marine.ie",
            "password": "M@rineSecure2024!",
        })
        bad_pass_response = client.post("/auth/login", json={
            "email": "test@marine-institute.ie",
            "password": "WrongPassword999!",
        })

        assert bad_email_response.status_code == 401
        assert bad_pass_response.status_code == 401
        assert (
            bad_email_response.json()["detail"]
            == bad_pass_response.json()["detail"]
        )


# ------------------------------------------------------------------ #
#  Protected endpoint tests                                            #
# ------------------------------------------------------------------ #

class TestProtectedEndpoints:

    def test_get_me_authenticated(self, client, auth_headers):
        """
        GET /auth/me with a valid token returns user profile.
        """
        response = client.get("/auth/me", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@marine-institute.ie"
        assert "hashed_password" not in data

    def test_get_me_no_token(self, client):
        """
        GET /auth/me without a token returns 401.
        """
        response = client.get("/auth/me")
        assert response.status_code == 401

    def test_get_me_invalid_token(self, client):
        """
        GET /auth/me with a fake token returns 401.
        """
        response = client.get(
            "/auth/me",
            headers={"Authorization": "Bearer this.is.fake"}
        )
        assert response.status_code == 401

    def test_get_me_malformed_header(self, client):
        """
        Authorization header without 'Bearer' prefix returns 403.
        """
        response = client.get(
            "/auth/me",
            headers={"Authorization": "Token abc123"}
        )
        assert response.status_code in (401, 403)


# ------------------------------------------------------------------ #
#  Security header tests                                               #
# ------------------------------------------------------------------ #

class TestSecurityHeaders:

    def test_security_headers_present(self, client):
        """
        Every response must include the required security headers.
        This confirms the middleware is working correctly.
        """
        response = client.get("/health")

        assert response.headers.get("x-content-type-options") == "nosniff"
        assert response.headers.get("x-frame-options") == "DENY"
        assert response.headers.get("referrer-policy") == "no-referrer"
        assert "permissions-policy" in response.headers