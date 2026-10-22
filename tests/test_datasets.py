import io
import pytest


# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #

def _upload_csv(client, headers, title="Test Dataset", is_public=False):
    """
    Helper to upload a small CSV file.
    Returns the response object.
    """
    csv_content = (
        b"depth_m,temperature_c,salinity_psu\n"
        b"0,15.2,34.1\n"
        b"10,14.8,34.2\n"
        b"50,12.1,34.5\n"
    )
    return client.post(
        "/datasets/upload",
        headers=headers,
        data={
            "title": title,
            "data_type": "ctd_profile",
            "region": "Celtic Sea",
            "is_public": str(is_public).lower(),
        },
        files={
            "file": ("test_data.csv", io.BytesIO(csv_content), "text/csv")
        },
    )


# ------------------------------------------------------------------ #
#  Upload tests                                                        #
# ------------------------------------------------------------------ #

class TestDatasetUpload:

    def test_upload_success(self, client, auth_headers):
        """
        Happy path — authenticated researcher uploads a valid CSV.
        Confirms: 201 status, metadata returned, file_path absent.
        """
        response = _upload_csv(client, auth_headers)

        assert response.status_code == 201
        data = response.json()

        assert data["title"] == "Test Dataset"
        assert data["data_type"] == "ctd_profile"
        assert data["region"] == "Celtic Sea"
        assert data["original_filename"] == "test_data.csv"
        assert data["mime_type"] == "text/csv"
        assert data["is_active"] is True

        # UUID generated
        assert "id" in data
        assert len(str(data["id"])) == 36

        # SECURITY: server file path must never be exposed
        assert "file_path" not in data

    def test_upload_requires_authentication(self, client):
        """
        Upload without a token returns 401.
        """
        csv_content = b"depth,temp\n0,15\n"
        response = client.post(
            "/datasets/upload",
            data={"title": "Test", "data_type": "other", "is_public": "false"},
            files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")},
        )
        assert response.status_code == 401

    def test_upload_rejects_wrong_file_type(self, client, auth_headers):
        """
        SECURITY TEST: uploading a .exe file is rejected with 400.
        File type validation protects the server from malicious uploads.
        """
        response = client.post(
            "/datasets/upload",
            headers=auth_headers,
            data={"title": "Malicious", "data_type": "other", "is_public": "false"},
            files={
                "file": (
                    "malware.exe",
                    io.BytesIO(b"MZ\x90\x00malicious content"),
                    "application/octet-stream",
                )
            },
        )
        # Should reject based on extension
        assert response.status_code in (400, 422)

    def test_upload_rejects_empty_file(self, client, auth_headers):
        """
        Empty file upload is rejected with 400.
        """
        response = client.post(
            "/datasets/upload",
            headers=auth_headers,
            data={"title": "Empty", "data_type": "other", "is_public": "false"},
            files={"file": ("empty.csv", io.BytesIO(b""), "text/csv")},
        )
        assert response.status_code == 400
        assert "empty" in response.json()["detail"].lower()


# ------------------------------------------------------------------ #
#  List datasets tests                                                 #
# ------------------------------------------------------------------ #

class TestDatasetList:

    def test_list_datasets_authenticated(self, client, auth_headers):
        """
        Authenticated user can list datasets.
        Confirms pagination fields are present.
        """
        response = client.get("/datasets/", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        assert "datasets" in data
        assert isinstance(data["datasets"], list)

    def test_list_datasets_unauthenticated(self, client):
        """
        Unauthenticated request to list datasets returns 401.
        """
        response = client.get("/datasets/")
        assert response.status_code == 401

    def test_list_shows_own_institution_datasets(
        self, client, auth_headers
    ):
        """
        After uploading, the dataset appears in the list.
        """
        _upload_csv(client, auth_headers, title="Visible Dataset")
        response = client.get("/datasets/", headers=auth_headers)

        assert response.status_code == 200
        titles = [d["title"] for d in response.json()["datasets"]]
        assert "Visible Dataset" in titles

    def test_list_pagination(self, client, auth_headers):
        """
        Pagination parameters are respected.
        """
        # Upload 3 datasets
        for i in range(3):
            _upload_csv(client, auth_headers, title=f"Dataset {i}")

        # Request page 1 with page_size=2
        response = client.get(
            "/datasets/?page=1&page_size=2",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 2
        assert len(data["datasets"]) <= 2


# ------------------------------------------------------------------ #
#  Download tests                                                      #
# ------------------------------------------------------------------ #

class TestDatasetDownload:

    def test_download_success(self, client, auth_headers):
        """
        Happy path — upload then download the same dataset.
        Confirms: 200 status, CSV content returned.
        """
        # Upload first
        upload_response = _upload_csv(client, auth_headers)
        assert upload_response.status_code == 201
        dataset_id = upload_response.json()["id"]

        # Download
        response = client.get(
            f"/datasets/{dataset_id}/download",
            headers=auth_headers,
        )
        assert response.status_code == 200
        # CSV content should be in the response body
        assert b"depth_m" in response.content

    def test_download_requires_authentication(self, client, auth_headers):
        """
        Download without a token returns 401.
        """
        upload_response = _upload_csv(client, auth_headers)
        dataset_id = upload_response.json()["id"]

        response = client.get(f"/datasets/{dataset_id}/download")
        assert response.status_code == 401

    def test_download_nonexistent_dataset(self, client, auth_headers):
        """
        Downloading a dataset that doesn't exist returns 404.
        """
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = client.get(
            f"/datasets/{fake_id}/download",
            headers=auth_headers,
        )
        assert response.status_code == 404


# ------------------------------------------------------------------ #
#  RBAC tests — the most important security tests                     #
# ------------------------------------------------------------------ #

class TestRBAC:

    def test_admin_audit_logs_denied_for_researcher(
        self, client, auth_headers
    ):
        """
        CRITICAL RBAC TEST: researcher role cannot access admin endpoints.
        A 403 Forbidden confirms RBAC is working correctly.

        This is the most important security test in the suite —
        it proves that role-based access control is actually enforced,
        not just declared.
        """
        response = client.get("/admin/audit-logs", headers=auth_headers)

        assert response.status_code == 403
        assert "forbidden" in response.json()["detail"].lower() or \
               "administrator" in response.json()["detail"].lower()

    def test_admin_users_denied_for_researcher(
        self, client, auth_headers
    ):
        """
        Researcher cannot list all users — admin only.
        """
        response = client.get("/admin/users", headers=auth_headers)
        assert response.status_code == 403

    def test_unauthenticated_cannot_access_admin(self, client):
        """
        Unauthenticated request to admin endpoint returns 401.
        """
        response = client.get("/admin/audit-logs")
        assert response.status_code == 401

    def test_researcher_can_upload(self, client, auth_headers):
        """
        Researcher role CAN upload datasets — confirming positive RBAC.
        """
        response = _upload_csv(client, auth_headers)
        assert response.status_code == 201

    def test_researcher_can_list_datasets(self, client, auth_headers):
        """
        Researcher role CAN list datasets.
        """
        response = client.get("/datasets/", headers=auth_headers)
        assert response.status_code == 200