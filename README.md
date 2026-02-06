# MCP Inspector for Burp Suite

A comprehensive Burp Suite extension for security testing Model Context Protocol (MCP) servers.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Burp Suite](https://img.shields.io/badge/Burp%20Suite-orange.svg)
![Python](https://img.shields.io/badge/python-Jython-blue.svg)
![Version](https://img.shields.io/badge/version-2.0-green.svg)

## Overview

MCP Inspector provides a full-featured interface for security testing MCP servers, with native Burp integration including Repeater-style request editing, **Virtual Proxy for bridging SSE to Burp tools**, and intelligent JSON handling for nested MCP responses.

## Features

### Core Functionality
- **Full MCP Protocol Support**: HTTP, Server-Sent Events (SSE), and WebSocket transport
- **Session Management**: Automatic session ID handling and connection state tracking
- **Request Editor**: Native Burp message editors with Raw/Hex/Pretty tabs
- **History Navigation**: 50-request rolling history with forward/back buttons
- **Smart JSON Unescaping**: Automatically extract nested/escaped JSON from responses

### MCP-Specific Features
- **Tools Browser**: Interactive table showing all available tools with parameters
- **Resources Browser**: View and test MCP resources
- **Prompts Browser**: Access and execute MCP prompts
- **Schema-Aware**: Pre-fills request parameters based on tool schemas

### Virtual Proxy (Key Feature)
The **Virtual Proxy** bridges MCP's SSE transport to Burp's HTTP-centric tools:

- **Send to Repeater**: Right-click any tool → "Send to Repeater" to test with full Burp capability
- **Send to Intruder**: Fuzz MCP tool parameters using Burp Intruder
- **Active Scan**: Run Burp's scanner against MCP tool calls
- **Automatic Bridging**: Converts HTTP requests to SSE/MCP calls and returns responses

**How it works:**
1. Virtual Proxy runs on `127.0.0.1:8899` (configurable)
2. HTTP POST requests are converted to MCP JSON-RPC calls
3. Responses from the MCP server are returned as HTTP responses
4. Burp tools (Repeater, Intruder, Scanner) work seamlessly

### Advanced Features
- **Custom Headers**: Configure authentication tokens and API keys
- **Configurable Timeouts**: Adjust request and SSE timeout behavior
- **Progress Tracking**: Monitor long-running MCP operations
- **Theme Support**: Automatically adapts UI for dark/light mode
- **Verbose Logging Toggle**: Control log verbosity for high-throughput testing
- **Persistent Proxy Indicator**: Status bar shows proxy state with click-to-navigate

## Installation

### From BApp Store (Recommended)
1. Open Burp Suite
2. Go to **Extender > BApp Store**
3. Search for "MCP Inspector"
4. Click **Install**

### Manual Installation
1. Download `mcp_inspector.py` from this repository
2. Open Burp Suite
3. Go to **Extender > Extensions**
4. Click **Add**
5. Set **Extension type** to **Python**
6. Select the downloaded file
7. Click **Next**

## Requirements

- **Burp Suite**: Professional or Community Edition
- **Java**: Version 11 or higher (for HTTP/2 and WebSocket support)
- **Jython**: Bundled with Burp Suite

## Usage

### Quick Start

1. **Open the extension**
   - Navigate to the **MCP Inspector** tab in Burp

2. **Connect to an MCP server**
   - Enter endpoint: `https://example.com/mcp`
   - Select transport: SSE, WebSocket, or Auto
   - Click "Connect"

3. **Browse available tools**
   - Tools automatically load after connection
   - View parameters and descriptions in the Tools tab

4. **Execute a request**
   - Right-click any tool → "Send to Request Editor"
   - Modify parameters as needed
   - Click "Send"

5. **Use Virtual Proxy for Burp tools**
   - Go to "Virtual Proxy" tab
   - Click "Start Proxy"
   - Right-click any tool → "Send to Repeater"

### Virtual Proxy Usage

#### Testing with Repeater
1. Start the Virtual Proxy (port 8899 default)
2. Right-click a tool → "Send to Repeater"
3. Modify the JSON body in Repeater
4. Send the request - response comes from MCP server

#### Fuzzing with Intruder
1. Start the Virtual Proxy
2. Send a tool call to Intruder
3. Set payload positions in the JSON parameters
4. Run the attack - each payload goes through MCP

#### Scanning
1. Start the Virtual Proxy
2. Right-click a tool → "Send to Repeater" → "Do active scan"
3. Burp Scanner tests the MCP endpoint through the proxy

### Custom Authentication

1. Click "Headers" button
2. Add authentication headers:
   ```
   Authorization: Bearer your-token-here
   X-API-Key: your-key
   ```
3. Click OK

### Timeout Configuration

1. Click "Settings" button
2. Configure:
   - **Request Timeout**: Initial timeout per request
   - **Reset on Progress**: Auto-extend timeout on progress events
   - **Max Total Timeout**: Hard limit for long operations

## Screenshots

![MCP Inspector Main Interface](https://raw.githubusercontent.com/Manjesh24/MCP-Inspector/master/images/MCP%20Inspector.jpg)
![MCP Inspector Tools](https://raw.githubusercontent.com/Manjesh24/MCP-Inspector/master/images/MCP%20Inspector%20-%202.jpg)

### Main Interface
The extension provides a tabbed interface with:
- **Tools**: Browse and test available MCP tools
- **Request Editor**: Full Burp Repeater-style functionality
- **Resources**: Access MCP resources
- **Prompts**: Work with MCP prompts
- **Virtual Proxy**: Bridge MCP to Burp Repeater/Intruder/Scanner
- **Logs**: Protocol-level debugging with verbose toggle

### Status Bar
Color-coded status indicators:
- **Gray [*]**: Ready
- **Orange [~]**: Working/Processing
- **Green [+]**: Success
- **Red [X]**: Error
- **Green PROXY: ON**: Virtual Proxy running (click to navigate)

## Troubleshooting

### Common Issues

**Extension won't load**
- Ensure Python/Jython is enabled in Burp (Extender > Options)
- Check Java version is 11+ (`java -version`)
- Review error output in Extender > Errors tab

**Connection fails**
- Verify MCP endpoint URL is correct
- Check if custom headers/authentication is required
- Review Logs tab for detailed error messages

**SSE not working**
- Some MCP servers use polling instead of SSE
- Check Server Info tab for SSE endpoint status
- Increase timeout settings if operations are slow

**Virtual Proxy issues**
- Ensure port 8899 is not in use by another application
- Check that you're connected to an MCP server first
- Review proxy logs in the Virtual Proxy tab

### Debug Logging
1. Go to **Logs** tab
2. Enable "Verbose" checkbox for detailed logging
3. All MCP protocol operations are logged with timestamps

## Changelog

### v2.0
- Added Virtual Proxy for Burp Repeater/Intruder/Scanner integration
- Added WebSocket transport support
- Added verbose logging toggle
- Added persistent proxy status indicator
- Improved UI with better theme support
- Performance optimizations for high-throughput testing

### v1.0
- Initial release with SSE support
- Tools, Resources, Prompts browsers
- Request history navigation

## License

MIT License - See LICENSE file for details

## Author

**Manjesh S**

## Acknowledgments

- Built for the [Model Context Protocol](https://modelcontextprotocol.io/) specification
- Uses Burp Suite Extender API
- Integrates native Burp message editors for consistent UX

---

**Made with ❤️ for the security testing community**
