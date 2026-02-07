"""
Tines API Client
Handles all HTTP communication with the Tines API.
"""

import os
import re
from typing import Any, Optional
import httpx
from dotenv import load_dotenv

load_dotenv()


class TinesAPIError(Exception):
    """Custom exception for Tines API errors that sanitizes sensitive data."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        # Sanitize any potential token leakage from error messages
        sanitized = re.sub(r'x-user-token["\s:]+[^"}\s]+', 'x-user-token: [REDACTED]', message)
        sanitized = re.sub(r'token["\s:=]+[A-Za-z0-9_-]{10,}', 'token: [REDACTED]', sanitized)
        self.status_code = status_code
        super().__init__(sanitized)


class TinesClient:
    """Client for interacting with the Tines API."""

    def __init__(
        self,
        tenant: Optional[str] = None,
        api_token: Optional[str] = None,
    ):
        self._tenant = tenant or os.getenv("TINES_TENANT")
        self._api_token = api_token or os.getenv("TINES_API_TOKEN")

        if not self._tenant:
            raise ValueError("TINES_TENANT environment variable is required")
        if not self._api_token:
            raise ValueError("TINES_API_TOKEN environment variable is required")

        # Validate tenant format to prevent injection
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$', self._tenant.replace('https://', '').replace('http://', '').split('/')[0]):
            raise ValueError("Invalid tenant format")

        # Normalize tenant URL - enforce HTTPS
        tenant_clean = self._tenant.replace('http://', '').replace('https://', '').rstrip('/')
        self._base_url = f"https://{tenant_clean}"
        self._api_url = f"{self._base_url}/api/v1"

    def _get_headers(self) -> dict[str, str]:
        """Get headers with token - don't store token in instance variable."""
        return {
            "x-user-token": self._api_token,
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
    ) -> dict[str, Any]:
        """Make an HTTP request to the Tines API."""
        # Validate endpoint to prevent path traversal
        if '..' in endpoint or endpoint.startswith('/'):
            endpoint = endpoint.lstrip('/')
        endpoint = re.sub(r'[^a-zA-Z0-9/_\-]', '', endpoint)

        url = f"{self._api_url}/{endpoint}"

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.request(
                    method=method,
                    url=url,
                    headers=self._get_headers(),
                    params=params,
                    json=json_data,
                )
                response.raise_for_status()

                if response.status_code == 204:
                    return {"success": True}

                return response.json()
        except httpx.HTTPStatusError as e:
            raise TinesAPIError(
                f"API request failed: {e.response.status_code}",
                status_code=e.response.status_code
            ) from None
        except httpx.RequestError as e:
            raise TinesAPIError(f"Request failed: {type(e).__name__}") from None

    # ==================== Stories ====================

    def list_stories(
        self,
        page: int = 1,
        per_page: int = 20,
        folder_id: Optional[int] = None,
        team_id: Optional[int] = None,
    ) -> dict[str, Any]:
        """List all stories."""
        params = {"page": page, "per_page": per_page}
        if folder_id:
            params["folder_id"] = folder_id
        if team_id:
            params["team_id"] = team_id
        return self._request("GET", "/stories", params=params)

    def get_story(self, story_id: int) -> dict[str, Any]:
        """Get a specific story by ID."""
        return self._request("GET", f"/stories/{story_id}")

    def create_story(
        self,
        name: str,
        description: Optional[str] = None,
        folder_id: Optional[int] = None,
        team_id: Optional[int] = None,
        keep_events_for: int = 604800,
    ) -> dict[str, Any]:
        """Create a new story."""
        data = {
            "name": name,
            "keep_events_for": keep_events_for,
        }
        if description:
            data["description"] = description
        if folder_id:
            data["folder_id"] = folder_id
        if team_id:
            data["team_id"] = team_id

        return self._request("POST", "/stories", json_data=data)

    def update_story(
        self,
        story_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        folder_id: Optional[int] = None,
        keep_events_for: Optional[int] = None,
    ) -> dict[str, Any]:
        """Update an existing story."""
        data = {}
        if name:
            data["name"] = name
        if description is not None:
            data["description"] = description
        if folder_id:
            data["folder_id"] = folder_id
        if keep_events_for:
            data["keep_events_for"] = keep_events_for

        return self._request("PUT", f"/stories/{story_id}", json_data=data)

    def delete_story(self, story_id: int) -> dict[str, Any]:
        """Delete a story."""
        return self._request("DELETE", f"/stories/{story_id}")

    def export_story(self, story_id: int) -> dict[str, Any]:
        """Export a story as JSON."""
        return self._request("GET", f"/stories/{story_id}/export")

    def import_story(
        self,
        story_data: dict,
        folder_id: Optional[int] = None,
        team_id: Optional[int] = None,
    ) -> dict[str, Any]:
        """Import a story from JSON."""
        data = {"data": story_data}
        if folder_id:
            data["folder_id"] = folder_id
        if team_id:
            data["team_id"] = team_id
        return self._request("POST", "/stories/import", json_data=data)

    # ==================== Actions (Agents) ====================

    def list_actions(self, story_id: int) -> dict[str, Any]:
        """List all actions in a story."""
        return self._request("GET", f"/stories/{story_id}/agents")

    def get_action(self, action_id: int) -> dict[str, Any]:
        """Get a specific action by ID."""
        return self._request("GET", f"/agents/{action_id}")

    def create_action(
        self,
        story_id: int,
        action_type: str,
        name: str,
        options: Optional[dict] = None,
        position: Optional[dict] = None,
        source_ids: Optional[list[int]] = None,
        receiver_ids: Optional[list[int]] = None,
    ) -> dict[str, Any]:
        """
        Create a new action in a story.

        action_type examples:
        - "Agents::HTTPRequestAgent" - HTTP Request
        - "Agents::EventTransformationAgent" - Event Transform
        - "Agents::TriggerAgent" - Webhook
        - "Agents::SendToStoryAgent" - Send to Story
        - "Agents::EmailAgent" - Send Email
        - "Agents::IMAPAgent" - Receive Email
        """
        data = {
            "story_id": story_id,
            "type": action_type,
            "name": name,
        }
        if options:
            data["options"] = options
        if position:
            data["position"] = position
        if source_ids:
            data["source_ids"] = source_ids
        if receiver_ids:
            data["receiver_ids"] = receiver_ids

        return self._request("POST", "/agents", json_data=data)

    def update_action(
        self,
        action_id: int,
        name: Optional[str] = None,
        options: Optional[dict] = None,
        position: Optional[dict] = None,
        source_ids: Optional[list[int]] = None,
        receiver_ids: Optional[list[int]] = None,
    ) -> dict[str, Any]:
        """Update an existing action."""
        data = {}
        if name:
            data["name"] = name
        if options:
            data["options"] = options
        if position:
            data["position"] = position
        if source_ids is not None:
            data["source_ids"] = source_ids
        if receiver_ids is not None:
            data["receiver_ids"] = receiver_ids

        return self._request("PUT", f"/agents/{action_id}", json_data=data)

    def delete_action(self, action_id: int) -> dict[str, Any]:
        """Delete an action."""
        return self._request("DELETE", f"/agents/{action_id}")

    def run_action(self, action_id: int, data: Optional[dict] = None) -> dict[str, Any]:
        """Manually run/trigger an action."""
        return self._request("POST", f"/agents/{action_id}/run", json_data=data or {})

    # ==================== Credentials ====================

    def list_credentials(
        self,
        page: int = 1,
        per_page: int = 20,
        team_id: Optional[int] = None,
    ) -> dict[str, Any]:
        """List all credentials."""
        params = {"page": page, "per_page": per_page}
        if team_id:
            params["team_id"] = team_id
        return self._request("GET", "/user_credentials", params=params)

    def get_credential(self, credential_id: int) -> dict[str, Any]:
        """Get a specific credential by ID."""
        return self._request("GET", f"/user_credentials/{credential_id}")

    def create_credential(
        self,
        name: str,
        mode: str,
        team_id: int,
        value: Optional[str] = None,
        jwt_payload: Optional[dict] = None,
        jwt_algorithm: Optional[str] = None,
        jwt_private_key: Optional[str] = None,
        jwt_auto_generate_time_claims: bool = True,
        oauth_url: Optional[str] = None,
        oauth_token_url: Optional[str] = None,
        oauth_client_id: Optional[str] = None,
        oauth_client_secret: Optional[str] = None,
        oauth_scope: Optional[str] = None,
        aws_authentication_type: Optional[str] = None,
        aws_access_key: Optional[str] = None,
        aws_secret_key: Optional[str] = None,
        aws_assumed_role_arn: Optional[str] = None,
        aws_assumed_role_external_id: Optional[str] = None,
        http_request_location_of_token: Optional[str] = None,
        http_request_options: Optional[dict] = None,
        mtls_client_certificate: Optional[str] = None,
        mtls_client_private_key: Optional[str] = None,
        mtls_root_certificate: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Create a new credential.

        mode options:
        - "TEXT" - Plain text secret
        - "JWT" - JWT token
        - "OAUTH" - OAuth2 client credentials
        - "AWS" - AWS credentials
        - "HTTP_REQUEST_AGENT" - HTTP request based
        - "MTLS" - Mutual TLS
        """
        data = {
            "name": name,
            "mode": mode,
            "team_id": team_id,
        }

        # Add mode-specific fields
        if value:
            data["value"] = value
        if jwt_payload:
            data["jwt_payload"] = jwt_payload
        if jwt_algorithm:
            data["jwt_algorithm"] = jwt_algorithm
        if jwt_private_key:
            data["jwt_private_key"] = jwt_private_key
        if jwt_auto_generate_time_claims is not None:
            data["jwt_auto_generate_time_claims"] = jwt_auto_generate_time_claims
        if oauth_url:
            data["oauth_url"] = oauth_url
        if oauth_token_url:
            data["oauth_token_url"] = oauth_token_url
        if oauth_client_id:
            data["oauth_client_id"] = oauth_client_id
        if oauth_client_secret:
            data["oauth_client_secret"] = oauth_client_secret
        if oauth_scope:
            data["oauth_scope"] = oauth_scope
        if aws_authentication_type:
            data["aws_authentication_type"] = aws_authentication_type
        if aws_access_key:
            data["aws_access_key"] = aws_access_key
        if aws_secret_key:
            data["aws_secret_key"] = aws_secret_key
        if aws_assumed_role_arn:
            data["aws_assumed_role_arn"] = aws_assumed_role_arn
        if aws_assumed_role_external_id:
            data["aws_assumed_role_external_id"] = aws_assumed_role_external_id
        if http_request_location_of_token:
            data["http_request_location_of_token"] = http_request_location_of_token
        if http_request_options:
            data["http_request_options"] = http_request_options
        if mtls_client_certificate:
            data["mtls_client_certificate"] = mtls_client_certificate
        if mtls_client_private_key:
            data["mtls_client_private_key"] = mtls_client_private_key
        if mtls_root_certificate:
            data["mtls_root_certificate"] = mtls_root_certificate

        return self._request("POST", "/user_credentials", json_data=data)

    def update_credential(
        self,
        credential_id: int,
        **kwargs,
    ) -> dict[str, Any]:
        """Update an existing credential."""
        return self._request(
            "PUT", f"/user_credentials/{credential_id}", json_data=kwargs
        )

    def delete_credential(self, credential_id: int) -> dict[str, Any]:
        """Delete a credential."""
        return self._request("DELETE", f"/user_credentials/{credential_id}")

    # ==================== Teams ====================

    def list_teams(self, page: int = 1, per_page: int = 20) -> dict[str, Any]:
        """List all teams."""
        return self._request("GET", "/teams", params={"page": page, "per_page": per_page})

    def get_team(self, team_id: int) -> dict[str, Any]:
        """Get a specific team by ID."""
        return self._request("GET", f"/teams/{team_id}")

    # ==================== Folders ====================

    def list_folders(
        self,
        page: int = 1,
        per_page: int = 20,
        team_id: Optional[int] = None,
    ) -> dict[str, Any]:
        """List all folders."""
        params = {"page": page, "per_page": per_page}
        if team_id:
            params["team_id"] = team_id
        return self._request("GET", "/folders", params=params)

    def get_folder(self, folder_id: int) -> dict[str, Any]:
        """Get a specific folder by ID."""
        return self._request("GET", f"/folders/{folder_id}")

    def create_folder(
        self,
        name: str,
        team_id: int,
        parent_id: Optional[int] = None,
    ) -> dict[str, Any]:
        """Create a new folder."""
        data = {"name": name, "team_id": team_id}
        if parent_id:
            data["parent_id"] = parent_id
        return self._request("POST", "/folders", json_data=data)

    # ==================== Events ====================

    def list_events(
        self,
        story_id: int,
        page: int = 1,
        per_page: int = 20,
    ) -> dict[str, Any]:
        """List events for a story."""
        return self._request(
            "GET",
            f"/stories/{story_id}/events",
            params={"page": page, "per_page": per_page},
        )

    def get_event(self, event_id: int) -> dict[str, Any]:
        """Get a specific event by ID."""
        return self._request("GET", f"/events/{event_id}")

    # ==================== Global Resources ====================

    def list_global_resources(
        self,
        page: int = 1,
        per_page: int = 20,
        team_id: Optional[int] = None,
    ) -> dict[str, Any]:
        """List all global resources."""
        params = {"page": page, "per_page": per_page}
        if team_id:
            params["team_id"] = team_id
        return self._request("GET", "/global_resources", params=params)

    def get_global_resource(self, resource_id: int) -> dict[str, Any]:
        """Get a specific global resource by ID."""
        return self._request("GET", f"/global_resources/{resource_id}")

    def create_global_resource(
        self,
        name: str,
        value: str,
        team_id: int,
    ) -> dict[str, Any]:
        """Create a new global resource."""
        return self._request(
            "POST",
            "/global_resources",
            json_data={"name": name, "value": value, "team_id": team_id},
        )

    def update_global_resource(
        self,
        resource_id: int,
        name: Optional[str] = None,
        value: Optional[str] = None,
    ) -> dict[str, Any]:
        """Update a global resource."""
        data = {}
        if name:
            data["name"] = name
        if value:
            data["value"] = value
        return self._request("PUT", f"/global_resources/{resource_id}", json_data=data)

    def delete_global_resource(self, resource_id: int) -> dict[str, Any]:
        """Delete a global resource."""
        return self._request("DELETE", f"/global_resources/{resource_id}")

    # ==================== Action Types ====================

    def list_action_types(self) -> dict[str, Any]:
        """List all available action types."""
        return self._request("GET", "/agent_types")
