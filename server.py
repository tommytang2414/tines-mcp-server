"""
Tines MCP Server
Provides MCP tools for interacting with the Tines security automation platform.

Security Features:
- All API calls wrapped with error handling to prevent info leakage
- Input validation on all parameters
- Logging set to WARNING to prevent token exposure
- Consistent error responses
"""

import json
import logging
from functools import wraps
from typing import Any

from mcp.server.fastmcp import FastMCP
from tines_client import TinesClient, TinesAPIError

# Security: Configure logging to WARNING level to avoid logging sensitive data
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("tines-mcp")

# Security: Disable httpx debug logging to prevent token leakage
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# Initialize MCP server
mcp = FastMCP("tines")

# Initialize Tines client (will use env vars)
client: TinesClient | None = None


def get_client() -> TinesClient:
    """Get or create the Tines client."""
    global client
    if client is None:
        client = TinesClient()
    return client


def format_response(data: Any) -> str:
    """Format response data as JSON string."""
    return json.dumps(data, indent=2)


def safe_json_loads(json_str: str | None, field_name: str = "data") -> Any:
    """Safely parse JSON with proper error handling."""
    if not json_str:
        return None
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {field_name}: {e.msg}") from None


def validate_positive_int(value: int, field_name: str = "id") -> int:
    """Validate that an integer is positive."""
    if value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def validate_pagination(page: int, per_page: int) -> tuple[int, int]:
    """Validate pagination parameters."""
    if page < 1:
        page = 1
    if per_page < 1:
        per_page = 1
    if per_page > 100:
        per_page = 100  # Security: Limit max page size
    return page, per_page


def validate_string(value: str | None, field_name: str, required: bool = False) -> str | None:
    """Validate string input."""
    if value is None:
        if required:
            raise ValueError(f"{field_name} is required")
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    value = value.strip()
    if required and not value:
        raise ValueError(f"{field_name} cannot be empty")
    return value if value else None


def handle_api_call(func):
    """Decorator to handle API errors consistently and prevent info leakage."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except TinesAPIError as e:
            return json.dumps({"error": str(e), "status_code": e.status_code})
        except ValueError as e:
            return json.dumps({"error": f"Validation error: {e}"})
        except Exception:
            # Security: Never expose internal error details
            return json.dumps({"error": "An unexpected error occurred"})
    return wrapper


# ==================== Stories ====================


@mcp.tool()
@handle_api_call
def list_stories(
    page: int = 1,
    per_page: int = 20,
    folder_id: int | None = None,
    team_id: int | None = None,
) -> str:
    """
    List all stories in your Tines tenant.

    Args:
        page: Page number for pagination (default: 1)
        per_page: Number of stories per page (default: 20, max: 100)
        folder_id: Optional folder ID to filter by
        team_id: Optional team ID to filter by

    Returns:
        JSON list of stories with their IDs, names, and metadata
    """
    page, per_page = validate_pagination(page, per_page)
    if folder_id is not None:
        validate_positive_int(folder_id, "folder_id")
    if team_id is not None:
        validate_positive_int(team_id, "team_id")
    result = get_client().list_stories(page, per_page, folder_id, team_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def get_story(story_id: int) -> str:
    """
    Get detailed information about a specific story.

    Args:
        story_id: The ID of the story to retrieve

    Returns:
        JSON object with story details including actions
    """
    validate_positive_int(story_id, "story_id")
    result = get_client().get_story(story_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def create_story(
    name: str,
    description: str = "",
    folder_id: int | None = None,
    team_id: int | None = None,
    keep_events_for: int = 604800,
) -> str:
    """
    Create a new story in Tines.

    Args:
        name: Name of the story
        description: Optional description
        folder_id: Optional folder ID to create the story in
        team_id: Optional team ID
        keep_events_for: Event retention period in seconds (default: 7 days)

    Returns:
        JSON object with the created story details
    """
    name = validate_string(name, "name", required=True)
    if folder_id is not None:
        validate_positive_int(folder_id, "folder_id")
    if team_id is not None:
        validate_positive_int(team_id, "team_id")
    if keep_events_for < 0:
        raise ValueError("keep_events_for must be non-negative")
    result = get_client().create_story(
        name, description or None, folder_id, team_id, keep_events_for
    )
    return format_response(result)


@mcp.tool()
@handle_api_call
def update_story(
    story_id: int,
    name: str | None = None,
    description: str | None = None,
    folder_id: int | None = None,
    keep_events_for: int | None = None,
) -> str:
    """
    Update an existing story.

    Args:
        story_id: The ID of the story to update
        name: New name for the story
        description: New description
        folder_id: New folder ID
        keep_events_for: New event retention period in seconds

    Returns:
        JSON object with the updated story details
    """
    validate_positive_int(story_id, "story_id")
    if name is not None:
        name = validate_string(name, "name")
    if folder_id is not None:
        validate_positive_int(folder_id, "folder_id")
    if keep_events_for is not None and keep_events_for < 0:
        raise ValueError("keep_events_for must be non-negative")
    result = get_client().update_story(
        story_id, name, description, folder_id, keep_events_for
    )
    return format_response(result)


@mcp.tool()
@handle_api_call
def delete_story(story_id: int) -> str:
    """
    Delete a story.

    Args:
        story_id: The ID of the story to delete

    Returns:
        Success confirmation
    """
    validate_positive_int(story_id, "story_id")
    result = get_client().delete_story(story_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def export_story(story_id: int) -> str:
    """
    Export a story as JSON for backup or sharing.

    Args:
        story_id: The ID of the story to export

    Returns:
        JSON export of the story including all actions
    """
    validate_positive_int(story_id, "story_id")
    result = get_client().export_story(story_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def import_story(
    story_json: str,
    folder_id: int | None = None,
    team_id: int | None = None,
) -> str:
    """
    Import a story from JSON.

    Args:
        story_json: JSON string of the story to import (from export_story)
        folder_id: Optional folder ID to import into
        team_id: Optional team ID

    Returns:
        JSON object with the imported story details
    """
    story_data = safe_json_loads(story_json, "story_json")
    if not story_data:
        raise ValueError("story_json is required")
    if folder_id is not None:
        validate_positive_int(folder_id, "folder_id")
    if team_id is not None:
        validate_positive_int(team_id, "team_id")
    result = get_client().import_story(story_data, folder_id, team_id)
    return format_response(result)


# ==================== Actions ====================


@mcp.tool()
@handle_api_call
def list_actions(story_id: int) -> str:
    """
    List all actions in a story.

    Args:
        story_id: The ID of the story

    Returns:
        JSON list of actions with their IDs, names, and types
    """
    validate_positive_int(story_id, "story_id")
    result = get_client().list_actions(story_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def get_action(action_id: int) -> str:
    """
    Get detailed information about a specific action.

    Args:
        action_id: The ID of the action to retrieve

    Returns:
        JSON object with action details including options
    """
    validate_positive_int(action_id, "action_id")
    result = get_client().get_action(action_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def create_action(
    story_id: int,
    action_type: str,
    name: str,
    options: str | None = None,
    position_x: int = 0,
    position_y: int = 0,
    source_ids: str | None = None,
    receiver_ids: str | None = None,
) -> str:
    """
    Create a new action in a story.

    Args:
        story_id: The ID of the story to add the action to
        action_type: Type of action. Common types:
            - "Agents::HTTPRequestAgent" - HTTP Request
            - "Agents::EventTransformationAgent" - Event Transform
            - "Agents::TriggerAgent" - Webhook trigger
            - "Agents::SendToStoryAgent" - Send to Story
            - "Agents::EmailAgent" - Send Email
            - "Agents::IMAPAgent" - Receive Email
            - "Agents::WebhookAgent" - Receive webhook
        name: Name for the action
        options: JSON string of action-specific options
        position_x: X position on canvas (default: 0)
        position_y: Y position on canvas (default: 0)
        source_ids: JSON array of action IDs that feed into this action
        receiver_ids: JSON array of action IDs this action feeds into

    Returns:
        JSON object with the created action details
    """
    validate_positive_int(story_id, "story_id")
    name = validate_string(name, "name", required=True)
    action_type = validate_string(action_type, "action_type", required=True)
    options_dict = safe_json_loads(options, "options")
    position = {"x": position_x, "y": position_y}
    sources = safe_json_loads(source_ids, "source_ids")
    receivers = safe_json_loads(receiver_ids, "receiver_ids")

    result = get_client().create_action(
        story_id, action_type, name, options_dict, position, sources, receivers
    )
    return format_response(result)


@mcp.tool()
@handle_api_call
def update_action(
    action_id: int,
    name: str | None = None,
    options: str | None = None,
    position_x: int | None = None,
    position_y: int | None = None,
    source_ids: str | None = None,
    receiver_ids: str | None = None,
) -> str:
    """
    Update an existing action.

    Args:
        action_id: The ID of the action to update
        name: New name for the action
        options: JSON string of new options
        position_x: New X position on canvas
        position_y: New Y position on canvas
        source_ids: JSON array of new source action IDs
        receiver_ids: JSON array of new receiver action IDs

    Returns:
        JSON object with the updated action details
    """
    validate_positive_int(action_id, "action_id")
    if name is not None:
        name = validate_string(name, "name")
    options_dict = safe_json_loads(options, "options")
    position = None
    if position_x is not None or position_y is not None:
        position = {"x": position_x or 0, "y": position_y or 0}
    sources = safe_json_loads(source_ids, "source_ids")
    receivers = safe_json_loads(receiver_ids, "receiver_ids")

    result = get_client().update_action(
        action_id, name, options_dict, position, sources, receivers
    )
    return format_response(result)


@mcp.tool()
@handle_api_call
def delete_action(action_id: int) -> str:
    """
    Delete an action.

    Args:
        action_id: The ID of the action to delete

    Returns:
        Success confirmation
    """
    validate_positive_int(action_id, "action_id")
    result = get_client().delete_action(action_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def run_action(action_id: int, data: str | None = None) -> str:
    """
    Manually trigger an action with optional input data.

    Args:
        action_id: The ID of the action to run
        data: Optional JSON string of input data

    Returns:
        JSON object with the run result
    """
    validate_positive_int(action_id, "action_id")
    data_dict = safe_json_loads(data, "data")
    result = get_client().run_action(action_id, data_dict)
    return format_response(result)


# ==================== Credentials ====================


@mcp.tool()
@handle_api_call
def list_credentials(
    page: int = 1,
    per_page: int = 20,
    team_id: int | None = None,
) -> str:
    """
    List all credentials in your Tines tenant.

    Args:
        page: Page number for pagination (default: 1)
        per_page: Number of credentials per page (default: 20, max: 100)
        team_id: Optional team ID to filter by

    Returns:
        JSON list of credentials (values are masked)
    """
    page, per_page = validate_pagination(page, per_page)
    if team_id is not None:
        validate_positive_int(team_id, "team_id")
    result = get_client().list_credentials(page, per_page, team_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def get_credential(credential_id: int) -> str:
    """
    Get information about a specific credential.

    Args:
        credential_id: The ID of the credential

    Returns:
        JSON object with credential details (value is masked)
    """
    validate_positive_int(credential_id, "credential_id")
    result = get_client().get_credential(credential_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def create_text_credential(name: str, value: str, team_id: int) -> str:
    """
    Create a new text-based credential.

    Args:
        name: Name for the credential
        value: The secret value
        team_id: Team ID for the credential

    Returns:
        JSON object with the created credential details
    """
    validate_positive_int(team_id, "team_id")
    name = validate_string(name, "name", required=True)
    if not value:
        raise ValueError("value is required")
    result = get_client().create_credential(
        name=name,
        mode="TEXT",
        team_id=team_id,
        value=value,
    )
    return format_response(result)


@mcp.tool()
@handle_api_call
def create_oauth_credential(
    name: str,
    team_id: int,
    token_url: str,
    client_id: str,
    client_secret: str,
    scope: str = "",
) -> str:
    """
    Create a new OAuth2 credential.

    Args:
        name: Name for the credential
        team_id: Team ID for the credential
        token_url: OAuth token URL
        client_id: OAuth client ID
        client_secret: OAuth client secret
        scope: OAuth scope (optional)

    Returns:
        JSON object with the created credential details
    """
    validate_positive_int(team_id, "team_id")
    name = validate_string(name, "name", required=True)
    token_url = validate_string(token_url, "token_url", required=True)
    client_id = validate_string(client_id, "client_id", required=True)
    if not client_secret:
        raise ValueError("client_secret is required")
    result = get_client().create_credential(
        name=name,
        mode="OAUTH",
        team_id=team_id,
        oauth_token_url=token_url,
        oauth_client_id=client_id,
        oauth_client_secret=client_secret,
        oauth_scope=scope or None,
    )
    return format_response(result)


@mcp.tool()
@handle_api_call
def delete_credential(credential_id: int) -> str:
    """
    Delete a credential.

    Args:
        credential_id: The ID of the credential to delete

    Returns:
        Success confirmation
    """
    validate_positive_int(credential_id, "credential_id")
    result = get_client().delete_credential(credential_id)
    return format_response(result)


# ==================== Teams ====================


@mcp.tool()
@handle_api_call
def list_teams(page: int = 1, per_page: int = 20) -> str:
    """
    List all teams in your Tines tenant.

    Args:
        page: Page number for pagination (default: 1)
        per_page: Number of teams per page (default: 20, max: 100)

    Returns:
        JSON list of teams
    """
    page, per_page = validate_pagination(page, per_page)
    result = get_client().list_teams(page, per_page)
    return format_response(result)


@mcp.tool()
@handle_api_call
def get_team(team_id: int) -> str:
    """
    Get information about a specific team.

    Args:
        team_id: The ID of the team

    Returns:
        JSON object with team details
    """
    validate_positive_int(team_id, "team_id")
    result = get_client().get_team(team_id)
    return format_response(result)


# ==================== Folders ====================


@mcp.tool()
@handle_api_call
def list_folders(
    page: int = 1,
    per_page: int = 20,
    team_id: int | None = None,
) -> str:
    """
    List all folders in your Tines tenant.

    Args:
        page: Page number for pagination (default: 1)
        per_page: Number of folders per page (default: 20, max: 100)
        team_id: Optional team ID to filter by

    Returns:
        JSON list of folders
    """
    page, per_page = validate_pagination(page, per_page)
    if team_id is not None:
        validate_positive_int(team_id, "team_id")
    result = get_client().list_folders(page, per_page, team_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def get_folder(folder_id: int) -> str:
    """
    Get information about a specific folder.

    Args:
        folder_id: The ID of the folder

    Returns:
        JSON object with folder details
    """
    validate_positive_int(folder_id, "folder_id")
    result = get_client().get_folder(folder_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def create_folder(name: str, team_id: int, parent_id: int | None = None) -> str:
    """
    Create a new folder.

    Args:
        name: Name for the folder
        team_id: Team ID for the folder
        parent_id: Optional parent folder ID for nested folders

    Returns:
        JSON object with the created folder details
    """
    name = validate_string(name, "name", required=True)
    validate_positive_int(team_id, "team_id")
    if parent_id is not None:
        validate_positive_int(parent_id, "parent_id")
    result = get_client().create_folder(name, team_id, parent_id)
    return format_response(result)


# ==================== Events ====================


@mcp.tool()
@handle_api_call
def list_events(story_id: int, page: int = 1, per_page: int = 20) -> str:
    """
    List events (executions) for a story.

    Args:
        story_id: The ID of the story
        page: Page number for pagination (default: 1)
        per_page: Number of events per page (default: 20, max: 100)

    Returns:
        JSON list of events with their data and status
    """
    validate_positive_int(story_id, "story_id")
    page, per_page = validate_pagination(page, per_page)
    result = get_client().list_events(story_id, page, per_page)
    return format_response(result)


@mcp.tool()
@handle_api_call
def get_event(event_id: int) -> str:
    """
    Get detailed information about a specific event.

    Args:
        event_id: The ID of the event

    Returns:
        JSON object with event details
    """
    validate_positive_int(event_id, "event_id")
    result = get_client().get_event(event_id)
    return format_response(result)


# ==================== Global Resources ====================


@mcp.tool()
@handle_api_call
def list_global_resources(
    page: int = 1,
    per_page: int = 20,
    team_id: int | None = None,
) -> str:
    """
    List all global resources in your Tines tenant.

    Args:
        page: Page number for pagination (default: 1)
        per_page: Number of resources per page (default: 20, max: 100)
        team_id: Optional team ID to filter by

    Returns:
        JSON list of global resources
    """
    page, per_page = validate_pagination(page, per_page)
    if team_id is not None:
        validate_positive_int(team_id, "team_id")
    result = get_client().list_global_resources(page, per_page, team_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def get_global_resource(resource_id: int) -> str:
    """
    Get a specific global resource.

    Args:
        resource_id: The ID of the resource

    Returns:
        JSON object with resource details
    """
    validate_positive_int(resource_id, "resource_id")
    result = get_client().get_global_resource(resource_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def create_global_resource(name: str, value: str, team_id: int) -> str:
    """
    Create a new global resource.

    Args:
        name: Name for the resource
        value: Value for the resource (can be JSON string for complex data)
        team_id: Team ID for the resource

    Returns:
        JSON object with the created resource details
    """
    name = validate_string(name, "name", required=True)
    validate_positive_int(team_id, "team_id")
    if not value:
        raise ValueError("value is required")
    result = get_client().create_global_resource(name, value, team_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def update_global_resource(
    resource_id: int,
    name: str | None = None,
    value: str | None = None,
) -> str:
    """
    Update a global resource.

    Args:
        resource_id: The ID of the resource to update
        name: New name for the resource
        value: New value for the resource

    Returns:
        JSON object with the updated resource details
    """
    validate_positive_int(resource_id, "resource_id")
    if name is not None:
        name = validate_string(name, "name")
    result = get_client().update_global_resource(resource_id, name, value)
    return format_response(result)


@mcp.tool()
@handle_api_call
def delete_global_resource(resource_id: int) -> str:
    """
    Delete a global resource.

    Args:
        resource_id: The ID of the resource to delete

    Returns:
        Success confirmation
    """
    validate_positive_int(resource_id, "resource_id")
    result = get_client().delete_global_resource(resource_id)
    return format_response(result)


# ==================== Action Types ====================


@mcp.tool()
@handle_api_call
def list_action_types() -> str:
    """
    List all available action types in Tines.

    Returns:
        JSON list of action types that can be used when creating actions
    """
    result = get_client().list_action_types()
    return format_response(result)


# ==================== Drafts (Change Control) ====================


@mcp.tool()
@handle_api_call
def list_drafts(story_id: int) -> str:
    """
    List all drafts for a story with change control enabled.

    Args:
        story_id: The ID of the story

    Returns:
        JSON list of drafts
    """
    validate_positive_int(story_id, "story_id")
    result = get_client().list_drafts(story_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def get_draft(story_id: int, draft_id: int) -> str:
    """
    Get detailed information about a specific draft.

    Args:
        story_id: The ID of the story
        draft_id: The ID of the draft

    Returns:
        JSON object with draft details
    """
    validate_positive_int(story_id, "story_id")
    validate_positive_int(draft_id, "draft_id")
    result = get_client().get_draft(story_id, draft_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def create_draft(
    story_id: int,
    name: str,
    description: str = "",
) -> str:
    """
    Create a new draft from a live story for testing changes.

    Use this when making changes to stories with Change Control enabled.
    The draft is a copy of the live story that you can modify and test.

    Args:
        story_id: The ID of the story to create a draft from
        name: Name for the draft (e.g., "Add new webhook action")
        description: Optional description of the changes

    Returns:
        JSON object with the created draft details including draft_id
    """
    validate_positive_int(story_id, "story_id")
    name = validate_string(name, "name", required=True)
    result = get_client().create_draft(story_id, name, description or None)
    return format_response(result)


@mcp.tool()
@handle_api_call
def delete_draft(story_id: int, draft_id: int) -> str:
    """
    Delete/discard a draft without publishing it.

    Args:
        story_id: The ID of the story
        draft_id: The ID of the draft to delete

    Returns:
        Success confirmation
    """
    validate_positive_int(story_id, "story_id")
    validate_positive_int(draft_id, "draft_id")
    result = get_client().delete_draft(story_id, draft_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def publish_draft(story_id: int, draft_id: int) -> str:
    """
    Publish a draft to make it the live version of the story.

    This replaces the current live story with the draft's content.
    Use this after testing your changes in the draft.

    Args:
        story_id: The ID of the story
        draft_id: The ID of the draft to publish

    Returns:
        JSON object with the published story details
    """
    validate_positive_int(story_id, "story_id")
    validate_positive_int(draft_id, "draft_id")
    result = get_client().publish_draft(story_id, draft_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def list_draft_actions(story_id: int, draft_id: int) -> str:
    """
    List all actions in a draft.

    Args:
        story_id: The ID of the story
        draft_id: The ID of the draft

    Returns:
        JSON list of actions in the draft
    """
    validate_positive_int(story_id, "story_id")
    validate_positive_int(draft_id, "draft_id")
    result = get_client().get_draft_agents(story_id, draft_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def create_draft_action(
    story_id: int,
    draft_id: int,
    action_type: str,
    name: str,
    options: str | None = None,
    position_x: int = 0,
    position_y: int = 0,
    source_ids: str | None = None,
    receiver_ids: str | None = None,
) -> str:
    """
    Create a new action in a draft.

    Args:
        story_id: The ID of the story
        draft_id: The ID of the draft
        action_type: Type of action (e.g., "Agents::HTTPRequestAgent")
        name: Name for the action
        options: JSON string of action-specific options
        position_x: X position on canvas (default: 0)
        position_y: Y position on canvas (default: 0)
        source_ids: JSON array of action IDs that feed into this action
        receiver_ids: JSON array of action IDs this action feeds into

    Returns:
        JSON object with the created action details
    """
    validate_positive_int(story_id, "story_id")
    validate_positive_int(draft_id, "draft_id")
    name = validate_string(name, "name", required=True)
    action_type = validate_string(action_type, "action_type", required=True)
    options_dict = safe_json_loads(options, "options")
    position = {"x": position_x, "y": position_y}
    sources = safe_json_loads(source_ids, "source_ids")
    receivers = safe_json_loads(receiver_ids, "receiver_ids")

    result = get_client().create_draft_agent(
        story_id, draft_id, action_type, name, options_dict, position, sources, receivers
    )
    return format_response(result)


@mcp.tool()
@handle_api_call
def update_draft_action(
    story_id: int,
    draft_id: int,
    action_id: int,
    name: str | None = None,
    options: str | None = None,
    position_x: int | None = None,
    position_y: int | None = None,
    source_ids: str | None = None,
    receiver_ids: str | None = None,
) -> str:
    """
    Update an action in a draft.

    Args:
        story_id: The ID of the story
        draft_id: The ID of the draft
        action_id: The ID of the action to update
        name: New name for the action
        options: JSON string of new options
        position_x: New X position on canvas
        position_y: New Y position on canvas
        source_ids: JSON array of new source action IDs
        receiver_ids: JSON array of new receiver action IDs

    Returns:
        JSON object with the updated action details
    """
    validate_positive_int(story_id, "story_id")
    validate_positive_int(draft_id, "draft_id")
    validate_positive_int(action_id, "action_id")
    if name is not None:
        name = validate_string(name, "name")
    options_dict = safe_json_loads(options, "options")
    position = None
    if position_x is not None or position_y is not None:
        position = {"x": position_x or 0, "y": position_y or 0}
    sources = safe_json_loads(source_ids, "source_ids")
    receivers = safe_json_loads(receiver_ids, "receiver_ids")

    result = get_client().update_draft_agent(
        story_id, draft_id, action_id, name, options_dict, position, sources, receivers
    )
    return format_response(result)


@mcp.tool()
@handle_api_call
def delete_draft_action(story_id: int, draft_id: int, action_id: int) -> str:
    """
    Delete an action from a draft.

    Args:
        story_id: The ID of the story
        draft_id: The ID of the draft
        action_id: The ID of the action to delete

    Returns:
        Success confirmation
    """
    validate_positive_int(story_id, "story_id")
    validate_positive_int(draft_id, "draft_id")
    validate_positive_int(action_id, "action_id")
    result = get_client().delete_draft_agent(story_id, draft_id, action_id)
    return format_response(result)


@mcp.tool()
@handle_api_call
def run_draft_action(
    story_id: int,
    draft_id: int,
    action_id: int,
    data: str | None = None,
) -> str:
    """
    Run/test an action in a draft.

    Use this to test actions before publishing the draft to live.

    Args:
        story_id: The ID of the story
        draft_id: The ID of the draft
        action_id: The ID of the action to run
        data: Optional JSON string of input data

    Returns:
        JSON object with the run result
    """
    validate_positive_int(story_id, "story_id")
    validate_positive_int(draft_id, "draft_id")
    validate_positive_int(action_id, "action_id")
    data_dict = safe_json_loads(data, "data")
    result = get_client().run_draft_agent(story_id, draft_id, action_id, data_dict)
    return format_response(result)


# ==================== Entry Point ====================

if __name__ == "__main__":
    mcp.run()
