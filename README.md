# MCP Inspector for Burp Suite

A comprehensive Burp Suite extension for testing and debugging Model Context Protocol (MCP) servers.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Burp Suite](https://img.shields.io/badge/Burp%20Suite-orange.svg)
![Python](https://img.shields.io/badge/python-2.7%20%7C%203.x-blue.svg)

## Overview

MCP Inspector provides a full-featured interface for security testing MCP servers, with native Burp integration including Repeater-style request editing, history management, and intelligent JSON handling for nested MCP responses.

## Features

### Core Functionality
- **Full MCP Protocol Support**: HTTP and Server-Sent Events (SSE) transport
- **Session Management**: Automatic session ID handling and connection state tracking
- **Request Editor**: Native Burp message editors with Raw/Hex/Pretty tabs
- **History Navigation**: 50-request rolling history with forward/back buttons
- **Smart JSON Unescaping**: Automatically extract nested/escaped JSON from responses

### MCP-Specific Features
- **Tools Browser**: Interactive table showing all available tools with parameters
- **Resources Browser**: View and test MCP resources
- **Prompts Browser**: Access and execute MCP prompts
- **Auto-Discovery**: Automatically lists tools after connection
- **Schema-Aware**: Pre-fills request parameters based on tool schemas

### Advanced Features
- **Custom Headers**: Configure authentication tokens and API keys
- **Configurable Timeouts**: Adjust request and SSE timeout behavior
- **Progress Tracking**: Monitor long-running MCP operations
- **Theme Support**: Automatically adapts UI for dark/light mode
- **Detailed Logging**: Protocol-level debugging information

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
- **Java**: Version 11 or higher (for HTTP/2 support)
- **Python**: Jython support enabled in Burp (bundled with Burp)

## Usage

### Quick Start

1. **Open the extension**
   - Navigate to the **MCP Inspector** tab in Burp
2. **Connect to an MCP server**
   - Enter endpoint: https://example.com/mcp
   - Click "Connect"
3. **Browse available tools**
   - Tools automatically load after connection
   - View parameters and descriptions in the Tools tab

4. **Execute a request**
   - Right-click any tool → "Send to Request Editor"
   - Modify parameters as needed
   - Click "Send"

5. **Handle complex responses**
   - Click "Unescape JSON" to extract nested JSON

### Advanced Usage

#### Custom Authentication

1. Click "Headers" button
2. Add authentication headers:
   - Authorization: Bearer your-token-here
   - X-API-Key: your-key
3. Click OK

#### Timeout Configuration

1. Click "Timeouts" button
2. Configure:
   - Request Timeout: Initial timeout per request
   - Reset on Progress: Auto-extend timeout on progress events
   - Max Total Timeout: Hard limit for long operations

#### Right-Click Context Menu
- **Tools Tab**: Send to Request Editor, Copy Tool Name
- **Resources Tab**: Send to Request Editor, Copy URI


## Screenshots
![alt text](https://raw.githubusercontent.com/Manjesh24/MCP-Inspector/master/images/MCP%20Inspector.jpg)
![alt text](https://raw.githubusercontent.com/Manjesh24/MCP-Inspector/master/images/MCP%20Inspector%20-%202.jpg)

### Main Interface
The extension provides a tabbed interface with:
- **Tools**: Browse and test available MCP tools
- **Request Editor**: Full Burp Repeater functionality
- **Resources**: Access MCP resources
- **Prompts**: Work with MCP prompts
- **Server Info**: Connection and capability details
- **Logs**: Protocol-level debugging

### Status Bar
Color-coded status indicators:
- **Gray [*]**: Ready
- **Orange [~]**: Working/Processing
- **Green [+]**: Success
- **Red [X]**: Error


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

**Unescape JSON not working**
- Check Logs tab for detailed processing information
- Some responses may not contain escaped JSON
- Try manually formatting in Raw tab

### Debug Logging
Enable detailed logging:
1. Go to **Logs** tab
2. All MCP protocol operations are logged with timestamps
3. Status changes and errors are clearly marked

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Built for the [Model Context Protocol](https://modelcontextprotocol.io/) specification
- Uses Burp Suite Extender API
- Integrates native Burp message editors for consistent UX


---

**Made with ❤️ for the security testing community**

