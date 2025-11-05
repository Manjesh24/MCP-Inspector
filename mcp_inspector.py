# -*- coding: utf-8 -*-
# MCP Inspector
# Author : Manjesh S

from burp import IBurpExtender, ITab, IMessageEditorController
from javax.swing import (JPanel, JButton, JTextField, JLabel,
                         JScrollPane, JTable, JOptionPane, JTextArea,
                         JTabbedPane, JCheckBox, JSpinner, SpinnerNumberModel, 
                         BorderFactory, JSplitPane, JComboBox, DefaultComboBoxModel,
                         SwingUtilities, JPopupMenu, JMenuItem, Box, UIManager)
from java.awt import BorderLayout, Dimension, FlowLayout, GridLayout, Font, Color, GridBagLayout, GridBagConstraints, Insets
from javax.swing.table import DefaultTableModel
from java.awt.event import MouseAdapter
import json
import threading
import traceback
import re
import time

from java.net.http import HttpClient, HttpRequest, HttpResponse
from java.net import URI
from java.time import Duration
from java.nio.charset import StandardCharsets
from java.io import BufferedReader, InputStreamReader
from java.net import URL

class BurpExtender(IBurpExtender, ITab, IMessageEditorController):
    """MCP Inspector - Burp Suite Extension """
    
    def __init__(self):
        self.session_id = None
        self.initializing = False
        self.tools = []
        self.resources = []
        self.prompts = []
        self.server_capabilities = {}
        self.protocol_version = None
        self.sse_thread = None
        self.sse_running = False
        self.pending_requests = {}
        self.sse_endpoint = None
        self.custom_headers = {}
        self.last_progress_time = {}
        self.request_history = []
        self.history_index = -1
        
        # Settings
        self.request_timeout = 30
        self.reset_on_progress = True
        self.max_total_timeout = 300

    def registerExtenderCallbacks(self, callbacks):
        """Extender API entry point"""
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("MCP Inspector")
        self._init_ui()
        callbacks.addSuiteTab(self)

        self.http_client = HttpClient.newBuilder() \
            .version(HttpClient.Version.HTTP_2) \
            .connectTimeout(Duration.ofSeconds(30)) \
            .build()

    def _get_theme_colors(self):
        """Detect theme and return appropriate colors"""
        bg = UIManager.getColor("Panel.background")
        if bg:
            brightness = (bg.getRed() * 299 + bg.getGreen() * 587 + bg.getBlue() * 114) / 1000
            is_dark = brightness < 128
        else:
            is_dark = False
        
        if is_dark:
            return {
                "status_bg": Color(40, 40, 40),
                "status_border": Color(60, 60, 60),
                "indicator_ready": Color(80, 80, 80),
                "indicator_working": Color(100, 70, 30),
                "indicator_success": Color(30, 80, 30),
                "indicator_error": Color(100, 40, 40),
                "text_normal": Color(220, 220, 220),
                "text_working": Color(255, 180, 100),
                "text_success": Color(100, 255, 100),
                "text_error": Color(255, 100, 100)
            }
        else:
            return {
                "status_bg": Color(245, 245, 245),
                "status_border": Color(200, 200, 200),
                "indicator_ready": Color(220, 220, 220),
                "indicator_working": Color(255, 230, 180),
                "indicator_success": Color(200, 255, 200),
                "indicator_error": Color(255, 200, 200),
                "text_normal": Color.BLACK,
                "text_working": Color(150, 100, 0),
                "text_success": Color(0, 100, 0),
                "text_error": Color.RED
            }

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())
        self.theme_colors = self._get_theme_colors()

        # Top connection panel
        top_panel = JPanel(BorderLayout())
        
        # Connection controls
        conn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.url_field = JTextField("https://localhost/mcp", 40)
        self.connect_btn = JButton("Connect", actionPerformed=self._on_connect_click)
        self.disconnect_btn = JButton("Disconnect", actionPerformed=self._on_disconnect_click)
        self.disconnect_btn.setEnabled(False)
        self.headers_btn = JButton("Headers", actionPerformed=self._edit_headers)
        self.settings_btn = JButton("Timeouts", actionPerformed=self._edit_settings)
        
        conn_panel.add(JLabel("Endpoint:"))
        conn_panel.add(self.url_field)
        conn_panel.add(self.connect_btn)
        conn_panel.add(self.disconnect_btn)
        conn_panel.add(self.headers_btn)
        conn_panel.add(self.settings_btn)
        
        # Prominent status bar
        status_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.status_label = JLabel("Ready - Configure endpoint and click Connect")
        self.status_label.setFont(Font("SansSerif", Font.BOLD, 14))
        self.status_indicator = JLabel(" [*] ")
        self.status_indicator.setFont(Font("SansSerif", Font.BOLD, 14))
        self.status_indicator.setForeground(Color.GRAY)
        self.status_indicator.setOpaque(True)
        self.status_indicator.setBackground(self.theme_colors["indicator_ready"])
        status_panel.add(self.status_indicator)
        status_panel.add(self.status_label)
        status_panel.setBackground(self.theme_colors["status_bg"])
        status_panel.setBorder(BorderFactory.createLineBorder(self.theme_colors["status_border"]))
        
        top_panel.add(conn_panel, BorderLayout.NORTH)
        top_panel.add(status_panel, BorderLayout.SOUTH)
        self.panel.add(top_panel, BorderLayout.NORTH)

        # Main tabs
        main_tabs = JTabbedPane()

        tools_panel = self._create_tools_tab()
        main_tabs.addTab("Tools", tools_panel)

        editor_panel = self._create_editor_tab()
        main_tabs.addTab("Request Editor", editor_panel)

        resources_panel = self._create_resources_tab()
        main_tabs.addTab("Resources", resources_panel)

        prompts_panel = self._create_prompts_tab()
        main_tabs.addTab("Prompts", prompts_panel)

        info_panel = self._create_info_tab()
        main_tabs.addTab("Server Info", info_panel)

        logs_panel = self._create_logs_tab()
        main_tabs.addTab("Logs", logs_panel)

        self.panel.add(main_tabs, BorderLayout.CENTER)

    def _create_tools_tab(self):
        panel = JPanel(BorderLayout())
        
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.list_tools_btn = JButton("List Tools", actionPerformed=self._list_tools)
        self.refresh_tools_btn = JButton("Refresh", actionPerformed=self._list_tools)
        btn_panel.add(self.list_tools_btn)
        btn_panel.add(self.refresh_tools_btn)
        btn_panel.add(JLabel("  Right-click a tool to send to Request Editor"))
        
        self.tools_model = DefaultTableModel(["Name", "Parameters", "Description"], 0)
        self.tools_table = JTable(self.tools_model)
        self.tools_table.getColumnModel().getColumn(0).setPreferredWidth(200)
        self.tools_table.getColumnModel().getColumn(1).setPreferredWidth(250)
        self.tools_table.getColumnModel().getColumn(2).setPreferredWidth(400)
        
        class ToolMouseHandler(MouseAdapter):
            def __init__(self, extender):
                self.extender = extender
            
            def mousePressed(self, event):
                if event.isPopupTrigger():
                    self.showMenu(event)
            
            def mouseReleased(self, event):
                if event.isPopupTrigger():
                    self.showMenu(event)
            
            def showMenu(self, event):
                row = self.extender.tools_table.rowAtPoint(event.getPoint())
                if row >= 0:
                    self.extender.tools_table.setRowSelectionInterval(row, row)
                    tool_name = self.extender.tools_model.getValueAt(row, 0)
                    
                    popup = JPopupMenu()
                    send_item = JMenuItem("Send to Request Editor")
                    send_item.addActionListener(lambda e: self.extender._send_tool_to_editor(tool_name))
                    popup.add(send_item)
                    
                    copy_item = JMenuItem("Copy Tool Name")
                    copy_item.addActionListener(lambda e: self.extender._copy_to_clipboard(tool_name))
                    popup.add(copy_item)
                    
                    popup.show(event.getComponent(), event.getX(), event.getY())
        
        self.tools_table.addMouseListener(ToolMouseHandler(self))
        tools_scroll = JScrollPane(self.tools_table)
        
        panel.add(btn_panel, BorderLayout.NORTH)
        panel.add(tools_scroll, BorderLayout.CENTER)
        
        return panel

    def _create_editor_tab(self):
        panel = JPanel(BorderLayout())
        
        # Top controls
        top = JPanel(FlowLayout(FlowLayout.LEFT))
        
        self.history_back_btn = JButton("<", actionPerformed=self._history_back)
        self.history_back_btn.setToolTipText("Previous request")
        self.history_back_btn.setEnabled(False)
        top.add(self.history_back_btn)
        
        self.history_forward_btn = JButton(">", actionPerformed=self._history_forward)
        self.history_forward_btn.setToolTipText("Next request")
        self.history_forward_btn.setEnabled(False)
        top.add(self.history_forward_btn)
        
        top.add(Box.createHorizontalStrut(10))
        
        top.add(JLabel("Method:"))
        self.editor_method = JComboBox(["tools/call", "tools/list", "resources/list", 
                                        "resources/read", "prompts/list", "prompts/get", "custom"])
        self.editor_method.addActionListener(lambda e: self._on_method_changed())
        top.add(self.editor_method)
        
        self.editor_send_btn = JButton("Send", actionPerformed=self._send_editor_request)
        self.editor_send_btn.setFont(Font("SansSerif", Font.BOLD, 12))
        self.editor_send_btn.setBackground(Color(255, 140, 0))
        self.editor_send_btn.setForeground(Color.WHITE)
        self.editor_send_btn.setOpaque(True)
        top.add(self.editor_send_btn)
        
        self.editor_clear_btn = JButton("Clear All", actionPerformed=self._clear_editor)
        top.add(self.editor_clear_btn)
        
        self.clear_history_btn = JButton("Clear History", actionPerformed=self._clear_history)
        top.add(self.clear_history_btn)
        
        self.prettify_btn = JButton("Unescape JSON", actionPerformed=self._prettify_response)
        self.prettify_btn.setToolTipText("Extract and format nested/escaped JSON from MCP responses")
        self.prettify_btn.setBackground(Color(70, 130, 180))
        self.prettify_btn.setForeground(Color.WHITE)
        self.prettify_btn.setOpaque(True)
        top.add(self.prettify_btn)
        
        panel.add(top, BorderLayout.NORTH)
        
        # Split pane
        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        split.setDividerLocation(500)
        split.setResizeWeight(0.5)
        
        # Request panel
        req_panel = JPanel(BorderLayout())
        req_panel.setBorder(BorderFactory.createTitledBorder("Request (JSON-RPC)"))
        self.request_editor = self._callbacks.createMessageEditor(self, True)
        req_panel.add(self.request_editor.getComponent(), BorderLayout.CENTER)
        
        initial_request = json.dumps({
            "jsonrpc": "2.0",
            "id": "req_1",
            "method": "tools/list",
            "params": {}
        }, indent=2)
        self.request_editor.setMessage(self._helpers.stringToBytes(initial_request), True)
        
        # Response panel
        resp_panel = JPanel(BorderLayout())
        resp_panel.setBorder(BorderFactory.createTitledBorder("Response"))
        self.response_editor = self._callbacks.createMessageEditor(self, False)
        resp_panel.add(self.response_editor.getComponent(), BorderLayout.CENTER)
        
        split.setLeftComponent(req_panel)
        split.setRightComponent(resp_panel)
        panel.add(split, BorderLayout.CENTER)
        
        return panel

    def _create_resources_tab(self):
        panel = JPanel(BorderLayout())
        
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.list_resources_btn = JButton("List Resources", actionPerformed=self._list_resources)
        btn_panel.add(self.list_resources_btn)
        btn_panel.add(JLabel("  Right-click a resource to send to Request Editor"))
        
        self.resources_model = DefaultTableModel(["URI", "Name", "Description", "MIME"], 0)
        self.resources_table = JTable(self.resources_model)
        
        class ResourceMouseHandler(MouseAdapter):
            def __init__(self, extender):
                self.extender = extender
            
            def mousePressed(self, event):
                if event.isPopupTrigger():
                    self.showMenu(event)
            
            def mouseReleased(self, event):
                if event.isPopupTrigger():
                    self.showMenu(event)
            
            def showMenu(self, event):
                row = self.extender.resources_table.rowAtPoint(event.getPoint())
                if row >= 0:
                    self.extender.resources_table.setRowSelectionInterval(row, row)
                    uri = self.extender.resources_model.getValueAt(row, 0)
                    
                    popup = JPopupMenu()
                    send_item = JMenuItem("Send to Request Editor")
                    send_item.addActionListener(lambda e: self.extender._send_resource_to_editor(uri))
                    popup.add(send_item)
                    
                    copy_item = JMenuItem("Copy URI")
                    copy_item.addActionListener(lambda e: self.extender._copy_to_clipboard(uri))
                    popup.add(copy_item)
                    
                    popup.show(event.getComponent(), event.getX(), event.getY())
        
        self.resources_table.addMouseListener(ResourceMouseHandler(self))
        resources_scroll = JScrollPane(self.resources_table)
        
        panel.add(btn_panel, BorderLayout.NORTH)
        panel.add(resources_scroll, BorderLayout.CENTER)
        
        return panel

    def _create_prompts_tab(self):
        panel = JPanel(BorderLayout())
        
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.list_prompts_btn = JButton("List Prompts", actionPerformed=self._list_prompts)
        btn_panel.add(self.list_prompts_btn)
        
        self.prompts_model = DefaultTableModel(["Name", "Description", "Arguments"], 0)
        self.prompts_table = JTable(self.prompts_model)
        prompts_scroll = JScrollPane(self.prompts_table)
        
        panel.add(btn_panel, BorderLayout.NORTH)
        panel.add(prompts_scroll, BorderLayout.CENTER)
        
        return panel

    def _create_info_tab(self):
        panel = JPanel(BorderLayout())
        self.info_area = JTextArea()
        self.info_area.setEditable(False)
        self.info_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        info_scroll = JScrollPane(self.info_area)
        panel.add(info_scroll, BorderLayout.CENTER)
        return panel

    def _create_logs_tab(self):
        panel = JPanel(BorderLayout())
        
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        clear_btn = JButton("Clear Logs", actionPerformed=self._clear_logs)
        btn_panel.add(clear_btn)
        
        self.logs_area = JTextArea()
        self.logs_area.setEditable(False)
        self.logs_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        logs_scroll = JScrollPane(self.logs_area)
        
        panel.add(btn_panel, BorderLayout.NORTH)
        panel.add(logs_scroll, BorderLayout.CENTER)
        
        return panel

    def getTabCaption(self):   
        return "MCP Inspector"
    
    def getUiComponent(self):  
        return self.panel

    # IMessageEditorController methods
    def getHttpService(self):
        return None
    
    def getRequest(self):
        return None
    
    def getResponse(self):
        return None

    def _copy_to_clipboard(self, text):
        from java.awt import Toolkit
        from java.awt.datatransfer import StringSelection
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)
        self._log("Copied: %s" % text[:50])

    def _prettify_response(self, event):
        """Extract and prettify nested/escaped JSON from MCP response"""
        try:
            response_bytes = self.response_editor.getMessage()
            if not response_bytes or len(response_bytes) == 0:
                self._log("No response to unescape")
                return
                
            response_text = self._helpers.bytesToString(response_bytes)
            original_length = len(response_text)
            
            # Parse outer JSON
            try:
                response_json = json.loads(response_text)
            except Exception as e:
                self._log("Response is not valid JSON: %s" % str(e))
                return
            
            self._log("Processing response for nested JSON...")
            
            # Process recursively to unescape nested JSON
            prettified = self._deep_unescape_json(response_json)
            
            # Format with indentation
            pretty_text = json.dumps(prettified, indent=2, ensure_ascii=False)
            new_length = len(pretty_text)
            
            # Check if anything actually changed
            if pretty_text == response_text:
                self._log("No escaped JSON found in response")
                return
            
            # Update response editor
            self.response_editor.setMessage(self._helpers.stringToBytes(pretty_text), False)
            self._log("Response unescaped successfully (was %d bytes, now %d bytes)" % (original_length, new_length))
            
        except Exception as e:
            self._log("Unescape failed: %s" % str(e))
            self._log(traceback.format_exc())

    def _deep_unescape_json(self, obj, depth=0):
        """Recursively find and parse escaped JSON strings"""
        # Prevent infinite recursion
        if depth > 10:
            return obj
            
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                result[key] = self._deep_unescape_json(value, depth + 1)
            return result
            
        elif isinstance(obj, list):
            return [self._deep_unescape_json(item, depth + 1) for item in obj]
            
        elif isinstance(obj, basestring):
            stripped = obj.strip()
            
            # Check for escape sequences that indicate JSON
            has_escapes = ('\\n' in stripped or '\\"' in stripped or '\\t' in stripped)
            looks_like_json = (
                (stripped.startswith('{') and stripped.endswith('}')) or
                (stripped.startswith('[') and stripped.endswith(']'))
            )
            
            if has_escapes or (looks_like_json and len(stripped) > 10):
                try:
                    # Try direct parse first (already unescaped)
                    try:
                        parsed = json.loads(stripped)
                        self._log("Found nested JSON (already unescaped) at depth %d" % depth)
                        return self._deep_unescape_json(parsed, depth + 1)
                    except:
                        pass
                    
                    # Unescape if needed
                    unescaped = stripped
                    if has_escapes:
                        # Replace common escape sequences
                        unescaped = unescaped.replace('\\n', '\n')
                        unescaped = unescaped.replace('\\"', '"')
                        unescaped = unescaped.replace('\\t', '\t')
                        unescaped = unescaped.replace('\\r', '\r')
                        unescaped = unescaped.replace('\\/', '/')
                        unescaped = unescaped.replace('\\b', '\b')
                        unescaped = unescaped.replace('\\f', '\f')
                        # Handle double-escaped backslashes last
                        unescaped = unescaped.replace('\\\\', '\\')
                    
                    # Try to parse the unescaped string
                    parsed = json.loads(unescaped)
                    self._log("Found and unescaped nested JSON at depth %d" % depth)
                    return self._deep_unescape_json(parsed, depth + 1)
                    
                except (ValueError, TypeError) as e:
                    # If it fails, return original
                    return obj
            
            return obj
        else:
            return obj

    def _log(self, msg):
        self._callbacks.printOutput("MCP: " + msg)
        try:
            def update():
                current = self.logs_area.getText()
                new_text = current + msg + "\n"
                lines = new_text.split('\n')
                if len(lines) > 5000:
                    lines = lines[-5000:]
                    new_text = '\n'.join(lines)
                self.logs_area.setText(new_text)
                self.logs_area.setCaretPosition(len(self.logs_area.getText()))
            SwingUtilities.invokeLater(update)
        except: 
            pass

    def _clear_logs(self, event):
        self.logs_area.setText("")

    def _update_status(self, msg, status_type="info"):
        """Update status with theme-aware colors"""
        def update():
            self.status_label.setText(msg)
            if status_type == "error":
                self.status_label.setForeground(self.theme_colors["text_error"])
                self.status_indicator.setText(" [X] ")
                self.status_indicator.setBackground(self.theme_colors["indicator_error"])
                self.status_indicator.setForeground(self.theme_colors["text_error"])
            elif status_type == "success":
                self.status_label.setForeground(self.theme_colors["text_success"])
                self.status_indicator.setText(" [+] ")
                self.status_indicator.setBackground(self.theme_colors["indicator_success"])
                self.status_indicator.setForeground(self.theme_colors["text_success"])
            elif status_type == "working":
                self.status_label.setForeground(self.theme_colors["text_working"])
                self.status_indicator.setText(" [~] ")
                self.status_indicator.setBackground(self.theme_colors["indicator_working"])
                self.status_indicator.setForeground(self.theme_colors["text_working"])
            else:
                self.status_label.setForeground(self.theme_colors["text_normal"])
                self.status_indicator.setText(" [*] ")
                self.status_indicator.setBackground(self.theme_colors["indicator_ready"])
                self.status_indicator.setForeground(Color.GRAY)
        
        SwingUtilities.invokeLater(update)
        self._log("STATUS: " + msg)

    def _update_server_info(self):
        info = []
        info.append("=== MCP Server Information ===\n")
        info.append("Endpoint: %s\n" % self.url_field.getText())
        info.append("Session ID: %s\n" % (self.session_id[:50] + "..." if self.session_id and len(self.session_id) > 50 else self.session_id or "None"))
        info.append("SSE Endpoint: %s\n" % (self.sse_endpoint or "Same as MCP endpoint"))
        info.append("Protocol Version: %s\n" % (self.protocol_version or "Unknown"))
        info.append("SSE Connection: %s\n" % ("Active" if self.sse_running else "Inactive"))
        info.append("\n=== Transport Settings ===\n")
        info.append("Request Timeout: %d seconds\n" % self.request_timeout)
        info.append("Reset on Progress: %s\n" % self.reset_on_progress)
        info.append("Max Total Timeout: %d seconds\n" % self.max_total_timeout)
        info.append("\n=== Custom Headers ===\n")
        if self.custom_headers:
            for k, v in self.custom_headers.items():
                display_val = v if len(v) < 50 else v[:47] + "..."
                info.append("%s: %s\n" % (k, display_val))
        else:
            info.append("None\n")
        info.append("\n=== Server Capabilities ===\n")
        info.append(json.dumps(self.server_capabilities, indent=2, ensure_ascii=False))
        
        def update():
            self.info_area.setText("".join(info))
        SwingUtilities.invokeLater(update)

    def _edit_headers(self, event):
        panel = JPanel(BorderLayout())
        
        headers_text = "\n".join(["%s: %s" % (k, v) for k, v in self.custom_headers.items()])
        if not headers_text:
            headers_text = "# Custom HTTP Headers (one per line)\n# Format: Header-Name: Value\n# Example:\n# Authorization: Bearer your-token-here\n# X-API-Key: your-key"
        
        text_area = JTextArea(headers_text, 15, 60)
        text_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        scroll = JScrollPane(text_area)
        
        panel.add(scroll, BorderLayout.CENTER)
        info = JLabel("Enter custom HTTP headers (one per line, format: Name: Value)")
        panel.add(info, BorderLayout.NORTH)
        
        result = JOptionPane.showConfirmDialog(
            self.panel, panel, "Custom HTTP Headers",
            JOptionPane.OK_CANCEL_OPTION
        )
        
        if result == JOptionPane.OK_OPTION:
            new_headers = {}
            for line in text_area.getText().split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        new_headers[parts[0].strip()] = parts[1].strip()
            
            self.custom_headers = new_headers
            self._log("Custom headers updated: %d headers" % len(new_headers))
            self._update_server_info()

    def _edit_settings(self, event):
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        
        gbc.gridx = 0
        gbc.gridy = 0
        panel.add(JLabel("Request Timeout (seconds):"), gbc)
        gbc.gridx = 1
        timeout_spinner = JSpinner(SpinnerNumberModel(self.request_timeout, 5, 300, 5))
        panel.add(timeout_spinner, gbc)
        
        gbc.gridx = 0
        gbc.gridy = 1
        panel.add(JLabel("Reset Timeout on Progress:"), gbc)
        gbc.gridx = 1
        reset_checkbox = JCheckBox("", self.reset_on_progress)
        panel.add(reset_checkbox, gbc)
        
        gbc.gridx = 0
        gbc.gridy = 2
        panel.add(JLabel("Maximum Total Timeout (seconds):"), gbc)
        gbc.gridx = 1
        max_spinner = JSpinner(SpinnerNumberModel(self.max_total_timeout, 30, 3600, 30))
        panel.add(max_spinner, gbc)
        
        result = JOptionPane.showConfirmDialog(
            self.panel, panel, "Timeout Settings",
            JOptionPane.OK_CANCEL_OPTION
        )
        
        if result == JOptionPane.OK_OPTION:
            self.request_timeout = timeout_spinner.getValue()
            self.reset_on_progress = reset_checkbox.isSelected()
            self.max_total_timeout = max_spinner.getValue()
            self._log("Timeout settings updated")
            self._update_server_info()

    def _get_param_summary(self, schema):
        props = schema.get("properties", {})
        required = schema.get("required", [])
        
        if not props:
            return "none"
        
        params = []
        for name in props.keys():
            if name in required:
                params.append(name + "*")
            else:
                params.append(name)
        
        return ", ".join(params[:5]) + ("..." if len(params) > 5 else "")

    def _generate_sample_args(self, schema):
        args = {}
        props = schema.get("properties", {})
        
        for prop, details in props.items():
            prop_type = details.get("type", "string")
            default = details.get("default")
            example = details.get("example")
            enum = details.get("enum")
            
            if default is not None:
                args[prop] = default
            elif example is not None:
                args[prop] = example
            elif enum:
                args[prop] = enum[0]
            elif prop_type == "number":
                args[prop] = 0
            elif prop_type == "boolean":
                args[prop] = False
            elif prop_type == "array":
                args[prop] = []
            elif prop_type == "object":
                args[prop] = {}
            else:
                args[prop] = ""
        
        return args

    def _send_tool_to_editor(self, tool_name):
        tool = next((t for t in self.tools if t["name"] == tool_name), None)
        if not tool:
            return
        
        schema = tool.get("inputSchema", {})
        args = self._generate_sample_args(schema)
        
        request = {
            "jsonrpc": "2.0",
            "id": "req_%d" % int(time.time() * 1000),
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args
            }
        }
        
        def update():
            self.editor_method.setSelectedItem("tools/call")
            request_text = json.dumps(request, indent=2, ensure_ascii=False)
            self.request_editor.setMessage(self._helpers.stringToBytes(request_text), True)
            
            parent = self.request_editor.getComponent().getParent()
            while parent and not isinstance(parent, JTabbedPane):
                parent = parent.getParent()
            if parent:
                parent.setSelectedIndex(1)
        
        SwingUtilities.invokeLater(update)
        self._log("Sent tool '%s' to Request Editor" % tool_name)

    def _send_resource_to_editor(self, uri):
        request = {
            "jsonrpc": "2.0",
            "id": "req_%d" % int(time.time() * 1000),
            "method": "resources/read",
            "params": {"uri": uri}
        }
        
        def update():
            self.editor_method.setSelectedItem("resources/read")
            request_text = json.dumps(request, indent=2, ensure_ascii=False)
            self.request_editor.setMessage(self._helpers.stringToBytes(request_text), True)
            parent = self.request_editor.getComponent().getParent()
            while parent and not isinstance(parent, JTabbedPane):
                parent = parent.getParent()
            if parent:
                parent.setSelectedIndex(1)
        
        SwingUtilities.invokeLater(update)
        self._log("Sent resource to Request Editor: %s" % uri)

    def _on_method_changed(self):
        method = self.editor_method.getSelectedItem()
        
        templates = {
            "tools/call": {"jsonrpc": "2.0", "id": "req_1", "method": "tools/call", "params": {"name": "tool_name", "arguments": {}}},
            "tools/list": {"jsonrpc": "2.0", "id": "req_1", "method": "tools/list", "params": {}},
            "resources/list": {"jsonrpc": "2.0", "id": "req_1", "method": "resources/list", "params": {}},
            "resources/read": {"jsonrpc": "2.0", "id": "req_1", "method": "resources/read", "params": {"uri": "resource://example"}},
            "prompts/list": {"jsonrpc": "2.0", "id": "req_1", "method": "prompts/list", "params": {}},
            "prompts/get": {"jsonrpc": "2.0", "id": "req_1", "method": "prompts/get", "params": {"name": "prompt_name", "arguments": {}}}
        }
        
        if method in templates and method != "custom":
            request_text = json.dumps(templates[method], indent=2)
            self.request_editor.setMessage(self._helpers.stringToBytes(request_text), True)

    def _add_to_history(self, request_text, response_text):
        self.request_history.append({"request": request_text, "response": response_text, "timestamp": time.strftime("%H:%M:%S")})
        if len(self.request_history) > 50:
            self.request_history = self.request_history[-50:]
        self.history_index = len(self.request_history) - 1
        self._update_history_buttons()

    def _history_back(self, event):
        if self.history_index > 0:
            self.history_index -= 1
            item = self.request_history[self.history_index]
            self.request_editor.setMessage(self._helpers.stringToBytes(item["request"]), True)
            self.response_editor.setMessage(self._helpers.stringToBytes(item["response"]), False)
            self._update_history_buttons()

    def _history_forward(self, event):
        if self.history_index < len(self.request_history) - 1:
            self.history_index += 1
            item = self.request_history[self.history_index]
            self.request_editor.setMessage(self._helpers.stringToBytes(item["request"]), True)
            self.response_editor.setMessage(self._helpers.stringToBytes(item["response"]), False)
            self._update_history_buttons()

    def _update_history_buttons(self):
        def update():
            self.history_back_btn.setEnabled(self.history_index > 0)
            self.history_forward_btn.setEnabled(self.history_index < len(self.request_history) - 1)
        SwingUtilities.invokeLater(update)

    def _send_editor_request(self, event):
        try:
            request_bytes = self.request_editor.getMessage()
            request_text = self._helpers.bytesToString(request_bytes)
            request_json = json.loads(request_text)
        except Exception as e:
            error_msg = "ERROR: Invalid JSON\n%s" % str(e)
            self.response_editor.setMessage(self._helpers.stringToBytes(error_msg), False)
            return
        
        self._update_status("Sending request...", "working")
        self.response_editor.setMessage(self._helpers.stringToBytes("Sending request..."), False)
        
        def handle_response(resp):
            response_text = json.dumps(resp, indent=2, ensure_ascii=False)
            
            def update():
                self.response_editor.setMessage(self._helpers.stringToBytes(response_text), False)
                self._add_to_history(request_text, response_text)
                
                if resp.get("error"):
                    self._update_status("Request failed", "error")
                else:
                    self._update_status("Request successful", "success")
            
            SwingUtilities.invokeLater(update)
        
        self._send_request_async(
            request_json.get("method"),
            request_json.get("params", {}),
            handle_response,
            req_id=request_json.get("id", "editor_req")
        )

    def _clear_editor(self, event):
        self.request_editor.setMessage(self._helpers.stringToBytes(""), True)
        self.response_editor.setMessage(self._helpers.stringToBytes(""), False)

    def _clear_history(self, event):
        self.request_history = []
        self.history_index = -1
        self._update_history_buttons()
        self._log("Request history cleared")

    def _parse_sse_body(self, body):
        if not body or not body.strip():
            return None
        try:
            return json.loads(body)
        except:
            pass
        events = re.split(r'\n\n+', body.strip())
        for ev in events:
            if not ev.strip():
                continue
            data_lines = []
            for line in ev.split('\n'):
                line = line.strip()
                if line.startswith('data:'):
                    data_content = line[5:].strip()
                    if data_content and data_content != "ping":
                        data_lines.append(data_content)
            if data_lines:
                try:
                    return json.loads('\n'.join(data_lines))
                except:
                    continue
        return None

    def _start_sse_listener(self):
        if self.sse_running:
            return
        self.sse_running = True
        
        def sse_listener():
            sse_url = self.sse_endpoint if self.sse_endpoint else self.url_field.getText().strip()
            self._log("Starting SSE: %s" % sse_url)
            retry_count = 0
            while self.sse_running and retry_count < 2:
                try:
                    conn = URL(sse_url).openConnection()
                    conn.setRequestMethod("GET")
                    conn.setRequestProperty("Accept", "text/event-stream")
                    if self.session_id:
                        conn.setRequestProperty("Mcp-Session-Id", self.session_id)
                    for k, v in self.custom_headers.items():
                        conn.setRequestProperty(k, v)
                    conn.setConnectTimeout(10000)
                    conn.setReadTimeout(0)
                    conn.connect()
                    
                    status = conn.getResponseCode()
                    if status == 200:
                        reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
                        retry_count = 0
                        event_type = None
                        event_data = []
                        while self.sse_running:
                            line = reader.readLine()
                            if line is None:
                                break
                            line = line.strip()
                            if not line:
                                if event_data:
                                    self._process_sse_event(event_type, event_data)
                                    event_type = None
                                    event_data = []
                                continue
                            if line.startswith("event:"):
                                event_type = line[6:].strip()
                            elif line.startswith("data:"):
                                data = line[5:].strip()
                                if data and data != "ping":
                                    event_data.append(data)
                        reader.close()
                    elif status == 405:
                        break
                    else:
                        retry_count += 1
                        time.sleep(2)
                except:
                    retry_count += 1
                    time.sleep(2)
            self.sse_running = False
        
        t = threading.Thread(target=sse_listener)
        t.daemon = True
        t.start()
        self.sse_thread = t

    def _process_sse_event(self, event_type, event_data):
        if not event_data:
            return
        try:
            data_str = '\n'.join(event_data)
            if event_type == "endpoint":
                self.sse_endpoint = data_str
                self._log("SSE Endpoint updated: %s" % self.sse_endpoint)
                self._update_server_info()
                return
            if event_type == "progress":
                parsed = json.loads(data_str)
                if "id" in parsed:
                    self.last_progress_time[parsed["id"]] = time.time()
                return
            parsed = json.loads(data_str)
            if "jsonrpc" in parsed and "id" in parsed:
                req_id = parsed["id"]
                if req_id in self.pending_requests:
                    callback = self.pending_requests[req_id]
                    del self.pending_requests[req_id]
                    callback(parsed)
        except:
            pass

    def _on_connect_click(self, event):
        if self.initializing:
            return
        url = self.url_field.getText().strip()
        if not url:
            self._update_status("Enter endpoint URL", "error")
            return
        
        # Auto-disconnect previous connection if endpoint changed
        if self.session_id:
            self._log("Disconnecting previous endpoint before connecting to new one...")
            self._disconnect_internal()
            time.sleep(0.5)  # Brief pause to ensure clean disconnect
        
        self.initializing = True
        self.connect_btn.setEnabled(False)
        self._update_status("Connecting...", "working")

        def init():
            try:
                resp = self._send_request_sync("initialize", {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
                    "clientInfo": {"name": "Burp MCP Inspector", "version": "2.0"}
                })
                if resp and "result" in resp:
                    result = resp["result"]
                    self.protocol_version = result.get("protocolVersion")
                    self.server_capabilities = result.get("capabilities", {})
                    server_info = result.get("serverInfo", {})
                    
                    if self.session_id:
                        self._start_sse_listener()
                        time.sleep(1)
                    
                    self._update_status("Connected: %s" % server_info.get("name", "MCP"), "success")
                    self._update_server_info()
                    
                    def enable():
                        self.disconnect_btn.setEnabled(True)
                    SwingUtilities.invokeLater(enable)
                    
                    # Auto-list tools after successful connection
                    time.sleep(0.5)
                    self._list_tools(None)
                    
                elif resp and "error" in resp:
                    self._update_status("Error: %s" % resp["error"].get("message"), "error")
                else:
                    self._update_status("Connection failed", "error")
            except Exception as e:
                self._update_status("Error: %s" % str(e), "error")
                self._log(traceback.format_exc())
            finally:
                self.connect_btn.setEnabled(True)
                self.initializing = False
                
        threading.Thread(target=init).start()

    def _disconnect_internal(self):
        """Internal disconnect logic - cleanly closes existing connection"""
        self._log("Closing SSE connection...")
        self.sse_running = False
        if self.sse_thread:
            self.sse_thread.join(timeout=2)
        
        self._log("Clearing session data...")
        self.session_id = None
        self.sse_endpoint = None
        self.protocol_version = None
        self.server_capabilities = {}
        self.tools = []
        self.resources = []
        self.prompts = []
        self.pending_requests = {}
        self.last_progress_time = {}

    def _on_disconnect_click(self, event):
        self._disconnect_internal()
        
        def update():
            self.tools_model.setRowCount(0)
            self.resources_model.setRowCount(0)
            self.prompts_model.setRowCount(0)
            self.disconnect_btn.setEnabled(False)
        SwingUtilities.invokeLater(update)
        
        self._update_status("Disconnected", "info")
        self._update_server_info()

    def _send_request_sync(self, method, params=None, req_id=None):
        if not req_id:
            req_id = "req_%s" % threading.currentThread().ident
        payload = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}})
        url = self.url_field.getText().strip()
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        headers.update(self.custom_headers)
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        try:
            builder = HttpRequest.newBuilder().uri(URI.create(url)).POST(
                HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8)
            ).timeout(Duration.ofSeconds(self.request_timeout))
            for k, v in headers.items():
                builder.header(k, v)
            resp = self.http_client.send(builder.build(),
                     HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
            sid_opt = resp.headers().firstValue("mcp-session-id")
            if sid_opt.isPresent() and not self.session_id:
                self.session_id = sid_opt.get()
                self._log("Session ID: %s..." % self.session_id[:30])
            return self._parse_sse_body(resp.body()) or {"error": {"code": -32700, "message": "Parse error"}}
        except Exception as e:
            return {"error": {"code": -1, "message": str(e)}}

    def _send_request_async(self, method, params, callback, timeout=None, req_id=None):
        if not timeout:
            timeout = self.request_timeout
        if not req_id:
            req_id = "req_%d" % int(time.time() * 1000)
        self.pending_requests[req_id] = callback
        self.last_progress_time[req_id] = time.time()
        payload = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}})
        url = self.url_field.getText().strip()
        
        def req_thread():
            try:
                builder = HttpRequest.newBuilder().uri(URI.create(url)).POST(
                    HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8)
                ).timeout(Duration.ofSeconds(timeout))
                builder.header("Content-Type", "application/json")
                builder.header("Accept", "application/json, text/event-stream")
                for k, v in self.custom_headers.items():
                    builder.header(k, v)
                if self.session_id:
                    builder.header("Mcp-Session-Id", self.session_id)
                resp = self.http_client.send(builder.build(),
                         HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                status = resp.statusCode()
                body = resp.body()
                if status == 202:
                    def monitor():
                        start = time.time()
                        while req_id in self.pending_requests:
                            if time.time() - start > self.max_total_timeout:
                                break
                            time.sleep(1)
                        if req_id in self.pending_requests:
                            del self.pending_requests[req_id]
                            callback({"error": {"code": -32000, "message": "Timeout"}})
                    t = threading.Thread(target=monitor)
                    t.daemon = True
                    t.start()
                elif status == 200:
                    if req_id in self.pending_requests:
                        del self.pending_requests[req_id]
                    parsed = self._parse_sse_body(body)
                    callback(parsed if parsed else {"error": {"code": -32700, "message": "Parse error"}})
                else:
                    if req_id in self.pending_requests:
                        del self.pending_requests[req_id]
                    callback({"error": {"code": status, "message": body[:200]}})
            except Exception as e:
                if req_id in self.pending_requests:
                    del self.pending_requests[req_id]
                callback({"error": {"code": -1, "message": str(e)}})
        t = threading.Thread(target=req_thread)
        t.daemon = True
        t.start()

    def _list_tools(self, event):
        self._update_status("Listing tools...", "working")
        def handle(resp):
            if resp and "result" in resp and "tools" in resp["result"]:
                self.tools = resp["result"]["tools"]
                def update():
                    self.tools_model.setRowCount(0)
                    for t in self.tools:
                        name = t.get("name", "")
                        params = self._get_param_summary(t.get("inputSchema", {}))
                        desc = t.get("description", "")
                        if len(desc) > 150:
                            desc = desc[:147] + "..."
                        self.tools_model.addRow([name, params, desc])
                SwingUtilities.invokeLater(update)
                self._update_status("Found %d tools" % len(self.tools), "success")
            else:
                self._update_status("Failed to list tools", "error")
        self._send_request_async("tools/list", {}, handle)

    def _list_resources(self, event):
        self._update_status("Listing resources...", "working")
        def handle(resp):
            if resp and "result" in resp:
                self.resources = resp["result"].get("resources", [])
                def update():
                    self.resources_model.setRowCount(0)
                    for r in self.resources:
                        self.resources_model.addRow([r.get("uri", ""), r.get("name", ""),
                            r.get("description", ""), r.get("mimeType", "")])
                SwingUtilities.invokeLater(update)
                self._update_status("Found %d resources" % len(self.resources), "success")
            else:
                self._update_status("No resources", "info")
        self._send_request_async("resources/list", {}, handle)

    def _list_prompts(self, event):
        self._update_status("Listing prompts...", "working")
        def handle(resp):
            if resp and "result" in resp:
                self.prompts = resp["result"].get("prompts", [])
                def update():
                    self.prompts_model.setRowCount(0)
                    for p in self.prompts:
                        args = json.dumps(p.get("arguments", [])) if p.get("arguments") else "None"
                        self.prompts_model.addRow([p.get("name", ""), p.get("description", ""), args])
                SwingUtilities.invokeLater(update)
                self._update_status("Found %d prompts" % len(self.prompts), "success")
            else:
                self._update_status("No prompts", "info")
        self._send_request_async("prompts/list", {}, handle)
