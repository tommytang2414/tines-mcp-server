# Tines MCP Server

A Model Context Protocol (MCP) server for interacting with the Tines security automation platform.

## Features

- **Stories**: List, create, update, delete, import/export stories
- **Actions**: Create, update, delete, and run actions within stories
- **Credentials**: Manage text and OAuth credentials
- **Teams & Folders**: Organize your Tines workspace
- **Events**: View story execution history
- **Global Resources**: Manage shared resources across stories

## Security

- API tokens are stored in `.env` file (never committed to git)
- All API calls use HTTPS
- Error messages are sanitized to prevent token leakage
- Input validation on all parameters

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/tines-mcp-server.git
cd tines-mcp-server
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Credentials

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` with your Tines credentials:

```
TINES_TENANT=your-company.tines.com
TINES_API_TOKEN=your-api-token-here
```

**To get your API token:**
1. Log in to Tines
2. Go to your Profile (top-right corner)
3. Navigate to **API Tokens**
4. Create a new token with appropriate permissions
5. Copy the token immediately (it won't be shown again)

### 4. Configure Claude Desktop

Add this to your Claude Desktop config file:

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "tines": {
      "command": "python",
      "args": ["/path/to/tines-mcp-server/server.py"]
    }
  }
}
```

> **Note**: Update the path to match your actual installation location.

### 5. Restart Claude Desktop

After configuring, restart Claude Desktop to load the MCP server.

## Available Tools

### Stories
| Tool | Description |
|------|-------------|
| `list_stories` | List all stories |
| `get_story` | Get story details |
| `create_story` | Create a new story |
| `update_story` | Update a story |
| `delete_story` | Delete a story |
| `export_story` | Export story as JSON |
| `import_story` | Import story from JSON |

### Actions
| Tool | Description |
|------|-------------|
| `list_actions` | List actions in a story |
| `get_action` | Get action details |
| `create_action` | Create a new action |
| `update_action` | Update an action |
| `delete_action` | Delete an action |
| `run_action` | Manually trigger an action |

### Credentials
| Tool | Description |
|------|-------------|
| `list_credentials` | List all credentials |
| `get_credential` | Get credential details |
| `create_text_credential` | Create a text credential |
| `create_oauth_credential` | Create an OAuth credential |
| `delete_credential` | Delete a credential |

### Teams & Folders
| Tool | Description |
|------|-------------|
| `list_teams` | List all teams |
| `get_team` | Get team details |
| `list_folders` | List all folders |
| `get_folder` | Get folder details |
| `create_folder` | Create a new folder |

### Events
| Tool | Description |
|------|-------------|
| `list_events` | List story events |
| `get_event` | Get event details |

### Global Resources
| Tool | Description |
|------|-------------|
| `list_global_resources` | List all global resources |
| `get_global_resource` | Get resource details |
| `create_global_resource` | Create a resource |
| `update_global_resource` | Update a resource |
| `delete_global_resource` | Delete a resource |

### Utilities
| Tool | Description |
|------|-------------|
| `list_action_types` | List available action types |

## Common Action Types

When creating actions, use these type strings:

| Type | Description |
|------|-------------|
| `Agents::HTTPRequestAgent` | Make HTTP requests |
| `Agents::EventTransformationAgent` | Transform event data |
| `Agents::TriggerAgent` | Scheduled trigger |
| `Agents::WebhookAgent` | Receive webhooks |
| `Agents::SendToStoryAgent` | Send data to another story |
| `Agents::EmailAgent` | Send emails |
| `Agents::IMAPAgent` | Receive emails |
| `Agents::JavaScriptAgent` | Run JavaScript code |
| `Agents::PythonAgent` | Run Python code |

## Example Usage

Once configured, you can ask Claude to:

- "List all my Tines stories"
- "Create a new story called 'Phishing Response'"
- "Add an HTTP Request action to story ID 123"
- "Show me the events for story 456"
- "Export story 789 so I can back it up"

## License

MIT
