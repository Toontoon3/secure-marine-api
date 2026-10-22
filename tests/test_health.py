class TestHealth:

    def test_health_check_returns_200(self, client):
        """
        GET /health always returns 200 with correct fields.
        Used by Render/Railway to know the app is alive.
        """
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["app"] == "Secure Marine Data API"
        assert "version" in data
        assert "environment" in data

    def test_root_returns_200(self, client):
        """
        GET / returns 200 with API info.
        """
        response = client.get("/")
        assert response.status_code == 200
        assert "app" in response.json()

    def test_404_returns_json(self, client):
        """
        Non-existent routes return clean JSON, not an HTML error page.
        Confirms the custom 404 handler is working.
        """
        response = client.get("/this-does-not-exist")

        assert response.status_code == 404
        data = response.json()
        assert "error" in data
        assert "detail" in data
        assert "status_code" in data
        # Must be JSON — not an HTML traceback
        assert response.headers["content-type"].startswith("application/json")