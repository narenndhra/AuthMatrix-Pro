# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController
from javax.swing import (JPanel, JButton, JLabel, JTextField, JTextArea, 
                         JScrollPane, JTabbedPane, BoxLayout, 
                         BorderFactory, JTable, SwingConstants,
                         JProgressBar, Box, JOptionPane, JComboBox, JSplitPane,
                         JCheckBox, ListSelectionModel)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing.RowFilter import regexFilter
from javax.swing.event import ListSelectionListener
from java.awt import (BorderLayout, GridLayout, Color, Dimension, FlowLayout, 
                      Font, GradientPaint, Cursor)
import json
import threading
import time
import re
import hashlib

class GradientPanel(JPanel):
    def __init__(self, color1, color2):
        JPanel.__init__(self)
        self.color1 = color1
        self.color2 = color2
    def paintComponent(self, g):
        g2d = g
        gradient = GradientPaint(0, 0, self.color1, 0, self.getHeight(), self.color2)
        g2d.setPaint(gradient)
        g2d.fillRect(0, 0, self.getWidth(), self.getHeight())

class ModernButton(JButton):
    def __init__(self, text, bg_color, fg_color=Color.WHITE):
        JButton.__init__(self, text)
        self.setBackground(bg_color)
        self.setForeground(fg_color)
        self.setFocusPainted(False)
        self.setBorderPainted(False)
        self.setOpaque(True)
        self.setFont(Font("Segoe UI", Font.BOLD, 12))
        self.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))

class VerdictCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        if value == "VULNERABLE":
            c.setBackground(Color(255, 235, 238))
            c.setForeground(Color(198, 40, 40))
            c.setFont(Font("Segoe UI", Font.BOLD, 11))
        elif value == "SAFE":
            c.setBackground(Color(232, 245, 233))
            c.setForeground(Color(46, 125, 50))
            c.setFont(Font("Segoe UI", Font.BOLD, 11))
        elif value == "SUSPICIOUS":
            c.setBackground(Color(255, 243, 224))
            c.setForeground(Color(230, 126, 34))
            c.setFont(Font("Segoe UI", Font.BOLD, 11))
        else:
            c.setBackground(Color.WHITE)
            c.setForeground(Color.BLACK)
        if isSelected:
            c.setBackground(Color(100, 181, 246))
        return c

class MessageEditorController(IMessageEditorController):
    def __init__(self, extender):
        self._extender = extender
        self._current_message = None
    def getHttpService(self):
        if self._current_message:
            return self._current_message.get('service')
        return None
    def getRequest(self):
        if self._current_message:
            return self._current_message.get('request')
        return None
    def getResponse(self):
        if self._current_message:
            return self._current_message.get('response')
        return None

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AuthMatrix Pro")
        
        # Core data structures
        self.roles = {}
        self.test_results = []
        self.request_hashes = set()
        
        # State management
        self.is_capturing = False
        self.baseline_role = None
        self.current_role = None
        self.testing_active = False
        
        # Thread safety
        self.roles_lock = threading.Lock()
        self.results_lock = threading.Lock()
        
        # Configuration
        self.url_exclusions = []
        self.exclude_static_files = True
        self.store_full_messages = True
        
        # Extended static file list
        self.static_extensions = [
            '.js', '.css', '.html', '.htm', '.gif', '.jpg', '.jpeg', 
            '.png', '.ico', '.woff', '.woff2', '.ttf', '.svg', '.webp',
            '.pdf', '.mp4', '.mp3', '.avi', '.mov', '.zip', '.rar', '.bmp',
            '.eot', '.otf', '.map', '.json', '.xml', '.txt', '.webmanifest',
            '.wasm', '.bin'
        ]
        
        self.colors = {
            'primary': Color(33, 150, 243),
            'success': Color(76, 175, 80),
            'danger': Color(244, 67, 54),
            'warning': Color(255, 152, 0),
            'dark': Color(38, 50, 56),
            'light': Color(245, 245, 245),
            'gradient_start': Color(67, 160, 231),
            'gradient_end': Color(30, 136, 229)
        }
        
        self._message_editor_controller = MessageEditorController(self)
        self.build_ui()
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        print("[*] AuthMatrix Pro v1.1 loaded! (Bug Fixes Applied)")
        print("[*] - Fixed: Cookie header consolidation")
        print("[*] - Fixed: Body encoding handling")
        print("[*] - Fixed: Thread safety with locks")
        print("[*] - Added: Request deduplication")
        print("[*] - Added: Memory management options")
        print("[*] - Extended: Static file detection")
    
    def getTabCaption(self):
        return "AuthMatrix Pro"
    
    def getUiComponent(self):
        return self.main_panel
    
    def should_ignore_url(self, url):
        if not self.exclude_static_files:
            return False
        url_without_query = url.split('?')[0].lower()
        for ext in self.static_extensions:
            if url_without_query.endswith(ext):
                return True
        for pattern in self.url_exclusions:
            try:
                if re.search(pattern, url, re.IGNORECASE):
                    return True
            except:
                pass
        return False
    
    def compute_request_hash(self, method, url, body):
        try:
            base_url = url.split('?')[0]
            hash_input = method + "|" + base_url + "|" + str(body)
            return hashlib.md5(hash_input.encode('utf-8')).hexdigest()
        except:
            return None
    
    def build_ui(self):
        self.main_panel = JPanel(BorderLayout())
        self.tabs = JTabbedPane()
        self.tabs.setFont(Font("Segoe UI", Font.BOLD, 13))
        self.tabs.addTab("  1. Capture Roles  ", self.create_capture_tab())
        self.tabs.addTab("  2. Configuration & Testing  ", self.create_mapping_tab())
        self.tabs.addTab("  3. Results Dashboard  ", self.create_dashboard_tab())
        self.main_panel.add(self.tabs)
    
    def create_capture_tab(self):
        panel = JPanel(BorderLayout())
        header = GradientPanel(self.colors['gradient_start'], self.colors['gradient_end'])
        header.setLayout(FlowLayout(FlowLayout.LEFT, 20, 15))
        header.setPreferredSize(Dimension(0, 60))
        title = JLabel("Capture Roles")
        title.setFont(Font("Segoe UI", Font.BOLD, 24))
        title.setForeground(Color.WHITE)
        header.add(title)
        subtitle = JLabel("Capture HTTP traffic for each role")
        subtitle.setFont(Font("Segoe UI", Font.PLAIN, 13))
        subtitle.setForeground(Color(255, 255, 255, 200))
        header.add(subtitle)
        panel.add(header, BorderLayout.NORTH)
        
        content = JPanel()
        content.setLayout(BoxLayout(content, BoxLayout.Y_AXIS))
        content.setBackground(Color.WHITE)
        content.setBorder(BorderFactory.createEmptyBorder(25, 35, 25, 35))
        
        info_panel = JPanel(BorderLayout())
        info_panel.setBackground(Color(227, 242, 253))
        info_panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(self.colors['primary'], 2),
            BorderFactory.createEmptyBorder(12, 15, 12, 15)
        ))
        info_panel.setMaximumSize(Dimension(32767, 80))
        info_text = JLabel("Quick Start: 1. Enter role -> 2. Start Capture -> 3. Browse app (use ALL features) -> 4. Stop")
        info_text.setFont(Font("Segoe UI", Font.PLAIN, 12))
        info_panel.add(info_text)
        content.add(info_panel)
        content.add(Box.createRigidArea(Dimension(0, 20)))
        
        capture_panel = JPanel()
        capture_panel.setLayout(BoxLayout(capture_panel, BoxLayout.Y_AXIS))
        capture_panel.setBackground(Color.WHITE)
        capture_panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(200, 200, 200), 1),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)
        ))
        capture_panel.setMaximumSize(Dimension(32767, 160))
        
        role_input = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))
        role_input.setBackground(Color.WHITE)
        role_label = JLabel("Role Name:")
        role_label.setFont(Font("Segoe UI", Font.BOLD, 13))
        role_input.add(role_label)
        self.role_name_field = JTextField(25)
        self.role_name_field.setText("Admin")
        self.role_name_field.setFont(Font("Segoe UI", Font.PLAIN, 13))
        self.role_name_field.setPreferredSize(Dimension(220, 28))
        role_input.add(self.role_name_field)
        capture_panel.add(role_input)
        capture_panel.add(Box.createRigidArea(Dimension(0, 12)))
        
        btn_panel = JPanel(FlowLayout(FlowLayout.CENTER, 15, 0))
        btn_panel.setBackground(Color.WHITE)
        self.capture_btn = ModernButton("Start Capture", self.colors['success'])
        self.capture_btn.addActionListener(lambda e: self.start_capture(e))
        self.capture_btn.setPreferredSize(Dimension(140, 36))
        self.stop_btn = ModernButton("Stop", self.colors['danger'])
        self.stop_btn.addActionListener(lambda e: self.stop_capture(e))
        self.stop_btn.setEnabled(False)
        self.stop_btn.setPreferredSize(Dimension(100, 36))
        btn_panel.add(self.capture_btn)
        btn_panel.add(self.stop_btn)
        capture_panel.add(btn_panel)
        capture_panel.add(Box.createRigidArea(Dimension(0, 12)))
        
        self.capture_status = JLabel("Ready", SwingConstants.CENTER)
        self.capture_status.setFont(Font("Segoe UI", Font.ITALIC, 12))
        self.capture_status.setForeground(Color.GRAY)
        self.capture_status.setAlignmentX(JLabel.CENTER_ALIGNMENT)
        capture_panel.add(self.capture_status)
        capture_panel.add(Box.createRigidArea(Dimension(0, 8)))
        
        self.progress_bar = JProgressBar(0, 100)
        self.progress_bar.setStringPainted(True)
        self.progress_bar.setForeground(self.colors['primary'])
        self.progress_bar.setPreferredSize(Dimension(0, 22))
        self.progress_bar.setMaximumSize(Dimension(32767, 22))
        capture_panel.add(self.progress_bar)
        
        content.add(capture_panel)
        content.add(Box.createRigidArea(Dimension(0, 20)))
        
        table_label = JLabel("Captured Roles:")
        table_label.setFont(Font("Segoe UI", Font.BOLD, 15))
        content.add(table_label)
        content.add(Box.createRigidArea(Dimension(0, 8)))
        
        self.capture_table_model = DefaultTableModel(["Role", "Requests", "Cookies", "Headers"], 0)
        self.capture_table = JTable(self.capture_table_model)
        self.capture_table.setFont(Font("Segoe UI", Font.PLAIN, 11))
        self.capture_table.setRowHeight(28)
        self.capture_table.setSelectionBackground(self.colors['primary'])
        self.capture_table.getTableHeader().setFont(Font("Segoe UI", Font.BOLD, 11))
        scroll = JScrollPane(self.capture_table)
        scroll.setPreferredSize(Dimension(0, 250))
        content.add(scroll)
        content.add(Box.createRigidArea(Dimension(0, 12)))
        
        delete_btn = ModernButton("Delete Selected", self.colors['danger'])
        delete_btn.addActionListener(lambda e: self.delete_role(e))
        delete_btn.setPreferredSize(Dimension(130, 28))
        delete_btn.setAlignmentX(JButton.LEFT_ALIGNMENT)
        content.add(delete_btn)
        
        panel.add(content, BorderLayout.CENTER)
        return panel
    
    def create_mapping_tab(self):
        panel = JPanel(BorderLayout())
        header = GradientPanel(self.colors['gradient_start'], self.colors['gradient_end'])
        header.setLayout(FlowLayout(FlowLayout.LEFT, 20, 15))
        header.setPreferredSize(Dimension(0, 60))
        title = JLabel("Configuration & Testing")
        title.setFont(Font("Segoe UI", Font.BOLD, 24))
        title.setForeground(Color.WHITE)
        header.add(title)
        panel.add(header, BorderLayout.NORTH)
        
        content = JPanel()
        content.setLayout(BoxLayout(content, BoxLayout.Y_AXIS))
        content.setBackground(Color.WHITE)
        content.setBorder(BorderFactory.createEmptyBorder(25, 35, 25, 35))
        
        url_section = JPanel()
        url_section.setLayout(BoxLayout(url_section, BoxLayout.Y_AXIS))
        url_section.setBackground(Color.WHITE)
        url_section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(self.colors['primary'], 2),
                "URL Filtering & Options",
                0, 0, Font("Segoe UI", Font.BOLD, 13), self.colors['primary']
            ),
            BorderFactory.createEmptyBorder(8, 12, 12, 12)
        ))
        url_section.setMaximumSize(Dimension(32767, 180))
        
        self.exclude_static_checkbox = JCheckBox("Auto-exclude static files (.js, .css, .woff, images, etc.)", True)
        self.exclude_static_checkbox.setBackground(Color.WHITE)
        self.exclude_static_checkbox.setFont(Font("Segoe UI", Font.PLAIN, 11))
        self.exclude_static_checkbox.addActionListener(lambda e: self.toggle_static_exclusion())
        url_section.add(self.exclude_static_checkbox)
        url_section.add(Box.createRigidArea(Dimension(0, 6)))
        
        self.store_messages_checkbox = JCheckBox("Store full request/response (disable for low memory)", True)
        self.store_messages_checkbox.setBackground(Color.WHITE)
        self.store_messages_checkbox.setFont(Font("Segoe UI", Font.PLAIN, 11))
        self.store_messages_checkbox.addActionListener(lambda e: self.toggle_message_storage())
        url_section.add(self.store_messages_checkbox)
        url_section.add(Box.createRigidArea(Dimension(0, 8)))
        
        url_input = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        url_input.setBackground(Color.WHITE)
        url_input.add(JLabel("Pattern:"))
        self.url_pattern_field = JTextField(30)
        self.url_pattern_field.setFont(Font("Segoe UI", Font.PLAIN, 11))
        url_input.add(self.url_pattern_field)
        add_btn = ModernButton("Add", self.colors['primary'])
        add_btn.addActionListener(lambda e: self.add_url_pattern())
        add_btn.setPreferredSize(Dimension(60, 24))
        url_input.add(add_btn)
        url_section.add(url_input)
        url_section.add(Box.createRigidArea(Dimension(0, 6)))
        
        self.patterns_display = JLabel("Active: None")
        self.patterns_display.setFont(Font("Segoe UI", Font.ITALIC, 10))
        self.patterns_display.setForeground(Color.GRAY)
        url_section.add(self.patterns_display)
        
        content.add(url_section)
        content.add(Box.createRigidArea(Dimension(0, 18)))
        
        baseline_section = JPanel()
        baseline_section.setLayout(BoxLayout(baseline_section, BoxLayout.Y_AXIS))
        baseline_section.setBackground(Color.WHITE)
        baseline_section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(self.colors['warning'], 2),
                "Step 1: Set Baseline Role",
                0, 0, Font("Segoe UI", Font.BOLD, 13), self.colors['warning']
            ),
            BorderFactory.createEmptyBorder(8, 12, 12, 12)
        ))
        baseline_section.setMaximumSize(Dimension(32767, 280))
        
        bl_info = JLabel("Select highest privilege role as baseline")
        bl_info.setFont(Font("Segoe UI", Font.PLAIN, 11))
        bl_info.setForeground(Color.GRAY)
        baseline_section.add(bl_info)
        baseline_section.add(Box.createRigidArea(Dimension(0, 8)))
        
        self.mapping_table_model = DefaultTableModel(["Role", "Requests", "Cookies", "Headers", "Status"], 0)
        self.mapping_table = JTable(self.mapping_table_model)
        self.mapping_table.setFont(Font("Segoe UI", Font.PLAIN, 11))
        self.mapping_table.setRowHeight(26)
        self.mapping_table.setSelectionBackground(self.colors['primary'])
        self.mapping_table.getTableHeader().setFont(Font("Segoe UI", Font.BOLD, 11))
        scroll = JScrollPane(self.mapping_table)
        scroll.setPreferredSize(Dimension(0, 140))
        baseline_section.add(scroll)
        baseline_section.add(Box.createRigidArea(Dimension(0, 10)))
        
        baseline_btn_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        baseline_btn_panel.setBackground(Color.WHITE)
        set_baseline_btn = ModernButton("Set Baseline", self.colors['warning'])
        set_baseline_btn.addActionListener(lambda e: self.set_baseline(e))
        set_baseline_btn.setPreferredSize(Dimension(120, 28))
        self.baseline_status = JLabel("None")
        self.baseline_status.setFont(Font("Segoe UI", Font.BOLD, 11))
        self.baseline_status.setForeground(self.colors['danger'])
        baseline_btn_panel.add(set_baseline_btn)
        baseline_btn_panel.add(Box.createHorizontalStrut(10))
        baseline_btn_panel.add(JLabel("Current:"))
        baseline_btn_panel.add(self.baseline_status)
        baseline_section.add(baseline_btn_panel)
        
        content.add(baseline_section)
        content.add(Box.createRigidArea(Dimension(0, 18)))
        
        test_section = JPanel()
        test_section.setLayout(BoxLayout(test_section, BoxLayout.Y_AXIS))
        test_section.setBackground(Color.WHITE)
        test_section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(self.colors['success'], 2),
                "Step 2: Run Tests",
                0, 0, Font("Segoe UI", Font.BOLD, 13), self.colors['success']
            ),
            BorderFactory.createEmptyBorder(8, 12, 12, 12)
        ))
        test_section.setMaximumSize(Dimension(32767, 170))
        
        self.test_config_label = JLabel("Configure baseline first")
        self.test_config_label.setFont(Font("Segoe UI", Font.PLAIN, 11))
        self.test_config_label.setForeground(Color.GRAY)
        test_section.add(self.test_config_label)
        test_section.add(Box.createRigidArea(Dimension(0, 12)))
        
        test_btn_panel = JPanel(FlowLayout(FlowLayout.CENTER, 12, 0))
        test_btn_panel.setBackground(Color.WHITE)
        self.start_test_btn = ModernButton("START TESTING", self.colors['success'])
        self.start_test_btn.addActionListener(lambda e: self.start_testing(e))
        self.start_test_btn.setPreferredSize(Dimension(150, 38))
        self.start_test_btn.setFont(Font("Segoe UI", Font.BOLD, 13))
        self.stop_test_btn = ModernButton("STOP", self.colors['danger'])
        self.stop_test_btn.addActionListener(lambda e: self.stop_testing(e))
        self.stop_test_btn.setEnabled(False)
        self.stop_test_btn.setPreferredSize(Dimension(80, 38))
        test_btn_panel.add(self.start_test_btn)
        test_btn_panel.add(self.stop_test_btn)
        test_section.add(test_btn_panel)
        test_section.add(Box.createRigidArea(Dimension(0, 12)))
        
        self.test_status = JLabel("Ready", SwingConstants.CENTER)
        self.test_status.setFont(Font("Segoe UI", Font.PLAIN, 11))
        self.test_status.setAlignmentX(JLabel.CENTER_ALIGNMENT)
        test_section.add(self.test_status)
        test_section.add(Box.createRigidArea(Dimension(0, 8)))
        
        self.test_progress = JProgressBar(0, 100)
        self.test_progress.setStringPainted(True)
        self.test_progress.setForeground(self.colors['success'])
        self.test_progress.setPreferredSize(Dimension(0, 20))
        self.test_progress.setMaximumSize(Dimension(32767, 20))
        test_section.add(self.test_progress)
        
        content.add(test_section)
        panel.add(content, BorderLayout.CENTER)
        return panel
    
    def create_dashboard_tab(self):
        panel = JPanel(BorderLayout())
        header = GradientPanel(self.colors['gradient_start'], self.colors['gradient_end'])
        header.setLayout(FlowLayout(FlowLayout.LEFT, 20, 15))
        header.setPreferredSize(Dimension(0, 60))
        title = JLabel("Results Dashboard")
        title.setFont(Font("Segoe UI", Font.BOLD, 24))
        title.setForeground(Color.WHITE)
        header.add(title)
        panel.add(header, BorderLayout.NORTH)
        
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_pane.setDividerLocation(450)
        split_pane.setResizeWeight(0.65)
        
        top_panel = JPanel(BorderLayout())
        
        stats_panel = JPanel(GridLayout(1, 4, 10, 10))
        stats_panel.setBackground(Color.WHITE)
        stats_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 8, 10))
        stats_panel.setPreferredSize(Dimension(0, 80))
        
        self.total_card = self.create_stat_card("Total", "0", self.colors['primary'])
        self.vuln_card = self.create_stat_card("Vulnerable", "0", self.colors['danger'])
        self.safe_card = self.create_stat_card("Safe", "0", self.colors['success'])
        self.susp_card = self.create_stat_card("Suspicious", "0", self.colors['warning'])
        
        stats_panel.add(self.total_card)
        stats_panel.add(self.vuln_card)
        stats_panel.add(self.safe_card)
        stats_panel.add(self.susp_card)
        
        top_panel.add(stats_panel, BorderLayout.NORTH)
        
        filter_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        filter_panel.setBackground(Color.WHITE)
        filter_panel.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color(220, 220, 220)))
        
        filter_label = JLabel("Filters:")
        filter_label.setFont(Font("Segoe UI", Font.BOLD, 10))
        filter_panel.add(filter_label)
        
        filter_panel.add(JLabel("Method:"))
        self.method_filter = JComboBox(["All", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        self.method_filter.addActionListener(lambda e: self.apply_filters())
        self.method_filter.setPreferredSize(Dimension(90, 24))
        filter_panel.add(self.method_filter)
        
        filter_panel.add(JLabel("Role:"))
        self.role_filter = JComboBox(["All"])
        self.role_filter.addActionListener(lambda e: self.apply_filters())
        self.role_filter.setPreferredSize(Dimension(110, 24))
        filter_panel.add(self.role_filter)
        
        filter_panel.add(JLabel("Status:"))
        self.status_filter = JComboBox(["All", "200", "201", "204", "301", "302", "400", "401", "403", "404", "500"])
        self.status_filter.addActionListener(lambda e: self.apply_filters())
        self.status_filter.setPreferredSize(Dimension(75, 24))
        filter_panel.add(self.status_filter)
        
        filter_panel.add(JLabel("Verdict:"))
        self.verdict_filter = JComboBox(["All", "VULNERABLE", "SAFE", "SUSPICIOUS"])
        self.verdict_filter.addActionListener(lambda e: self.apply_filters())
        self.verdict_filter.setPreferredSize(Dimension(120, 24))
        filter_panel.add(self.verdict_filter)
        
        reset_btn = ModernButton("Reset", self.colors['primary'])
        reset_btn.addActionListener(lambda e: self.reset_filters())
        reset_btn.setPreferredSize(Dimension(65, 24))
        filter_panel.add(reset_btn)
        
        table_panel = JPanel(BorderLayout())
        table_panel.add(filter_panel, BorderLayout.NORTH)
        
        self.results_table_model = DefaultTableModel(["Endpoint", "Method", "Role", "Status", "Verdict", "Details"], 0)
        self.results_table = JTable(self.results_table_model)
        self.results_table.setFont(Font("Segoe UI", Font.PLAIN, 10))
        self.results_table.setRowHeight(24)
        self.results_table.setSelectionBackground(self.colors['primary'])
        self.results_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.results_table.getTableHeader().setFont(Font("Segoe UI", Font.BOLD, 10))
        self.results_table.getColumnModel().getColumn(4).setCellRenderer(VerdictCellRenderer())
        self.results_table.getColumnModel().getColumn(0).setPreferredWidth(300)
        
        self.table_sorter = TableRowSorter(self.results_table_model)
        self.results_table.setRowSorter(self.table_sorter)
        self.results_table.getSelectionModel().addListSelectionListener(TableSelectionListener(self))
        
        scroll = JScrollPane(self.results_table)
        table_panel.add(scroll, BorderLayout.CENTER)
        
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 6))
        btn_panel.setBackground(Color.WHITE)
        btn_panel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color(220, 220, 220)))
        
        refresh_btn = ModernButton("Refresh", self.colors['primary'])
        refresh_btn.addActionListener(lambda e: self.refresh_dashboard())
        refresh_btn.setPreferredSize(Dimension(80, 26))
        
        export_all_btn = ModernButton("Export All", self.colors['success'])
        export_all_btn.addActionListener(lambda e: self.export_results(e, False))
        export_all_btn.setPreferredSize(Dimension(90, 26))
        
        export_filtered_btn = ModernButton("Export Filtered", self.colors['warning'])
        export_filtered_btn.addActionListener(lambda e: self.export_results(e, True))
        export_filtered_btn.setPreferredSize(Dimension(110, 26))
        
        clear_btn = ModernButton("Clear", self.colors['danger'])
        clear_btn.addActionListener(lambda e: self.clear_results(e))
        clear_btn.setPreferredSize(Dimension(70, 26))
        
        btn_panel.add(refresh_btn)
        btn_panel.add(export_all_btn)
        btn_panel.add(export_filtered_btn)
        btn_panel.add(clear_btn)
        
        table_panel.add(btn_panel, BorderLayout.SOUTH)
        top_panel.add(table_panel, BorderLayout.CENTER)
        
        bottom_panel = JPanel(BorderLayout())
        bottom_panel.setBackground(Color.WHITE)
        
        viewer_header = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        viewer_header.setBackground(Color(250, 250, 250))
        viewer_header.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 0, Color(220, 220, 220)))
        viewer_title = JLabel("Request & Response Viewer")
        viewer_title.setFont(Font("Segoe UI", Font.BOLD, 12))
        viewer_header.add(viewer_title)
        bottom_panel.add(viewer_header, BorderLayout.NORTH)
        
        viewer_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        viewer_split.setDividerLocation(0.5)
        viewer_split.setResizeWeight(0.5)
        
        self._request_viewer = self._callbacks.createMessageEditor(self._message_editor_controller, False)
        self._response_viewer = self._callbacks.createMessageEditor(self._message_editor_controller, False)
        
        req_panel = JPanel(BorderLayout())
        req_header = JLabel("  REQUEST", SwingConstants.LEFT)
        req_header.setFont(Font("Segoe UI", Font.BOLD, 10))
        req_header.setOpaque(True)
        req_header.setBackground(Color(240, 240, 240))
        req_header.setPreferredSize(Dimension(0, 22))
        req_panel.add(req_header, BorderLayout.NORTH)
        req_panel.add(self._request_viewer.getComponent(), BorderLayout.CENTER)
        
        resp_panel = JPanel(BorderLayout())
        resp_header = JLabel("  RESPONSE", SwingConstants.LEFT)
        resp_header.setFont(Font("Segoe UI", Font.BOLD, 10))
        resp_header.setOpaque(True)
        resp_header.setBackground(Color(240, 240, 240))
        resp_header.setPreferredSize(Dimension(0, 22))
        resp_panel.add(resp_header, BorderLayout.NORTH)
        resp_panel.add(self._response_viewer.getComponent(), BorderLayout.CENTER)
        
        viewer_split.setLeftComponent(req_panel)
        viewer_split.setRightComponent(resp_panel)
        bottom_panel.add(viewer_split, BorderLayout.CENTER)
        
        split_pane.setTopComponent(top_panel)
        split_pane.setBottomComponent(bottom_panel)
        panel.add(split_pane, BorderLayout.CENTER)
        return panel
    
    def create_stat_card(self, title, value, color):
        card = JPanel()
        card.setLayout(BoxLayout(card, BoxLayout.Y_AXIS))
        card.setBackground(Color.WHITE)
        card.setBorder(BorderFactory.createLineBorder(color, 2))
        
        value_label = JLabel(value, SwingConstants.CENTER)
        value_label.setFont(Font("Segoe UI", Font.BOLD, 24))
        value_label.setForeground(color)
        value_label.setAlignmentX(JLabel.CENTER_ALIGNMENT)
        
        title_label = JLabel(title, SwingConstants.CENTER)
        title_label.setFont(Font("Segoe UI", Font.PLAIN, 11))
        title_label.setForeground(Color.GRAY)
        title_label.setAlignmentX(JLabel.CENTER_ALIGNMENT)
        
        card.add(Box.createVerticalGlue())
        card.add(value_label)
        card.add(Box.createRigidArea(Dimension(0, 4)))
        card.add(title_label)
        card.add(Box.createVerticalGlue())
        
        card.putClientProperty("value_label", value_label)
        return card
    
    def toggle_static_exclusion(self):
        self.exclude_static_files = self.exclude_static_checkbox.isSelected()
        print("[*] Static file exclusion: " + str(self.exclude_static_files))
    
    def toggle_message_storage(self):
        self.store_full_messages = self.store_messages_checkbox.isSelected()
        print("[*] Full message storage: " + str(self.store_full_messages))
        if not self.store_full_messages:
            print("[*] WARNING: Request/Response viewer will be disabled for new results")
    
    def add_url_pattern(self):
        pattern = self.url_pattern_field.getText().strip()
        if pattern:
            try:
                re.compile(pattern)
                self.url_exclusions.append(pattern)
                self.url_pattern_field.setText("")
                self.update_patterns_display()
                print("[+] Added pattern: " + pattern)
            except:
                JOptionPane.showMessageDialog(self.main_panel, "Invalid regex!")
    
    def clear_patterns(self):
        self.url_exclusions = []
        self.update_patterns_display()
    
    def update_patterns_display(self):
        if self.url_exclusions:
            display = ", ".join(self.url_exclusions[:2])
            if len(self.url_exclusions) > 2:
                display += "... (+" + str(len(self.url_exclusions) - 2) + ")"
            self.patterns_display.setText("Active: " + display)
        else:
            self.patterns_display.setText("Active: None")
    
    def apply_filters(self):
        filters = []
        method = self.method_filter.getSelectedItem()
        if method != "All":
            filters.append(regexFilter(method, 1))
        role = self.role_filter.getSelectedItem()
        if role != "All":
            filters.append(regexFilter(role, 2))
        status = self.status_filter.getSelectedItem()
        if status != "All":
            filters.append(regexFilter(status, 3))
        verdict = self.verdict_filter.getSelectedItem()
        if verdict != "All":
            filters.append(regexFilter(verdict, 4))
        if filters:
            from javax.swing.RowFilter import andFilter
            self.table_sorter.setRowFilter(andFilter(filters))
        else:
            self.table_sorter.setRowFilter(None)
    
    def reset_filters(self):
        self.method_filter.setSelectedIndex(0)
        self.role_filter.setSelectedIndex(0)
        self.status_filter.setSelectedIndex(0)
        self.verdict_filter.setSelectedIndex(0)
        self.table_sorter.setRowFilter(None)
    
    def display_request_response(self, row):
        if row >= 0:
            model_row = self.results_table.convertRowIndexToModel(row)
            if model_row < len(self.test_results):
                result = self.test_results[model_row]
                if 'request_bytes' in result and result['request_bytes']:
                    self._request_viewer.setMessage(result['request_bytes'], True)
                else:
                    self._request_viewer.setMessage(None, True)
                if 'response_bytes' in result and result['response_bytes']:
                    self._response_viewer.setMessage(result['response_bytes'], False)
                else:
                    self._response_viewer.setMessage(None, False)
    
    def start_capture(self, event):
        role = self.role_name_field.getText().strip()
        if not role:
            JOptionPane.showMessageDialog(self.main_panel, "Enter role name!")
            return
        
        with self.roles_lock:
            if role in self.roles:
                JOptionPane.showMessageDialog(self.main_panel, "Role exists!")
                return
            self.roles[role] = {"cookies": [], "headers": [], "requests": []}
        
        self.is_capturing = True
        self.current_role = role
        self.request_hashes.clear()
        self.capture_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.capture_status.setText("Capturing: " + role + " - Use ALL app features!")
        self.capture_status.setForeground(self.colors['danger'])
        print("[+] Started capturing: " + role)
    
    def stop_capture(self, event):
        self.is_capturing = False
        self.capture_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        with self.roles_lock:
            count = len(self.roles[self.current_role]["requests"])
        
        self.capture_status.setText("Captured " + str(count) + " unique requests")
        self.capture_status.setForeground(self.colors['success'])
        self.refresh_capture_table()
        self.refresh_mapping_table()
        self.update_role_filter()
        JOptionPane.showMessageDialog(self.main_panel, "Captured " + str(count) + " unique requests for: " + self.current_role, "Success", JOptionPane.INFORMATION_MESSAGE)
        print("[+] Stopped: %d unique requests" % count)
    
    def set_baseline(self, event):
        row = self.mapping_table.getSelectedRow()
        if row >= 0:
            self.baseline_role = self.mapping_table_model.getValueAt(row, 0)
            self.baseline_status.setText(str(self.baseline_role))
            self.baseline_status.setForeground(self.colors['success'])
            self.refresh_mapping_table()
            
            with self.roles_lock:
                baseline = self.roles.get(self.baseline_role, {})
                num = len(baseline.get("requests", []))
                others = len(self.roles) - 1
            
            if others > 0:
                self.test_config_label.setText("Ready: " + str(num) + " requests x " + str(others) + " roles = " + str(num * others) + " tests")
            print("[+] Baseline: " + str(self.baseline_role))
        else:
            JOptionPane.showMessageDialog(self.main_panel, "Select a role!")
    
    def start_testing(self, event):
        if not self.baseline_role or len(self.roles) < 2:
            JOptionPane.showMessageDialog(self.main_panel, "Set baseline and capture 2+ roles!")
            return
        self.testing_active = True
        self.start_test_btn.setEnabled(False)
        self.stop_test_btn.setEnabled(True)
        
        with self.results_lock:
            self.test_results = []
        
        thread = threading.Thread(target=self.run_tests)
        thread.daemon = True
        thread.start()
    
    def run_tests(self):
        try:
            with self.roles_lock:
                baseline = dict(self.roles[self.baseline_role])
                other_roles = [r for r in self.roles.keys() if r != self.baseline_role]
                roles_copy = {name: dict(data) for name, data in self.roles.items()}
            
            requests = baseline.get("requests", [])
            total = len(requests) * len(other_roles)
            current = 0
            
            method_count = {}
            for req in requests:
                m = req['method']
                method_count[m] = method_count.get(m, 0) + 1
            
            print("[+] ========== TESTING STARTED ==========")
            print("[+] Baseline: " + str(self.baseline_role))
            print("[+] Total requests: " + str(len(requests)))
            print("[+] Methods:")
            for method, count in method_count.items():
                print("[+]   " + method + ": " + str(count))
            print("[+] Testing with: " + str(other_roles))
            print("[+] Total tests: " + str(total))
            print("[+] ========================================")
            
            for req in requests:
                if not self.testing_active:
                    break
                for role_name in other_roles:
                    if not self.testing_active:
                        break
                    current += 1
                    self.test_progress.setValue(int(current * 100.0 / total))
                    self.test_status.setText("Testing " + str(current) + "/" + str(total) + ": " + req['method'])
                    result = self.replay_request(req, role_name, roles_copy[role_name])
                    
                    with self.results_lock:
                        self.test_results.append(result)
                    
                    time.sleep(0.02)
            
            with self.results_lock:
                tested_methods = {}
                for r in self.test_results:
                    m = r['method']
                    tested_methods[m] = tested_methods.get(m, 0) + 1
                total_results = len(self.test_results)
                vuln_count = len([r for r in self.test_results if r['verdict'] == 'VULNERABLE'])
            
            print("[+] ========== COMPLETE ==========")
            print("[+] Total: " + str(total_results))
            print("[+] Methods tested:")
            for method, count in tested_methods.items():
                print("[+]   " + method + ": " + str(count))
            print("[+] =================================")
            
            self.test_status.setText("Complete!")
            self.start_test_btn.setEnabled(True)
            self.stop_test_btn.setEnabled(False)
            self.testing_active = False
            self.refresh_dashboard()
            self.tabs.setSelectedIndex(2)
            
            if vuln_count > 0:
                JOptionPane.showMessageDialog(self.main_panel, "Found " + str(vuln_count) + " VULNERABILITIES!", "Results", JOptionPane.WARNING_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self.main_panel, "No vulnerabilities found.", "Results", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            print("[-] Error: " + str(e))
            import traceback
            traceback.print_exc()
            self.start_test_btn.setEnabled(True)
            self.stop_test_btn.setEnabled(False)
    
    def replay_request(self, req, role_name, role_data):
        try:
            headers = list(req.get('headers', []))
            new_headers = []
            
            for h in headers:
                hl = h.lower()
                if not (hl.startswith("cookie:") or "authorization" in hl or 
                        "token" in hl or "x-auth" in hl or "bearer" in hl):
                    new_headers.append(h)
            
            role_cookies = role_data.get('cookies', [])
            if role_cookies:
                all_cookie_parts = []
                for cookie_header in role_cookies:
                    if ":" in cookie_header:
                        cookie_value = cookie_header.split(":", 1)[1].strip()
                        all_cookie_parts.append(cookie_value)
                
                if all_cookie_parts:
                    combined_cookies = "; ".join(all_cookie_parts)
                    new_headers.append("Cookie: " + combined_cookies)
            
            role_auth_headers = role_data.get('headers', [])
            for auth_header in role_auth_headers:
                new_headers.append(auth_header)
            
            body = req.get('body', '')
            if body:
                if hasattr(body, '__iter__') and not isinstance(body, str):
                    try:
                        body_bytes = bytearray(body)
                    except:
                        body_bytes = body
                else:
                    body_bytes = body
            else:
                body_bytes = ''
            
            service = self._helpers.buildHttpService(
                req.get('host', 'localhost'),
                req.get('port', 443),
                req.get('protocol', 'https') == 'https'
            )
            
            request_bytes = self._helpers.buildHttpMessage(new_headers, body_bytes)
            
            try:
                response = self._callbacks.makeHttpRequest(service, request_bytes)
                response_bytes = response.getResponse()
            except Exception as e:
                print("[-] Request timeout or error: " + str(e))
                return {
                    "endpoint": req.get('url', 'Unknown'),
                    "method": req.get('method', 'Unknown'),
                    "role": role_name,
                    "status": 0,
                    "verdict": "ERROR",
                    "details": "Request failed: " + str(e),
                    "request_bytes": request_bytes if self.store_full_messages else None,
                    "response_bytes": None
                }
            
            info = self._helpers.analyzeResponse(response_bytes)
            status = info.getStatusCode()
            
            verdict = "SAFE"
            details = "Access blocked"
            
            if status in [301, 302, 303, 307, 308]:
                redirect_location = ""
                for header in info.getHeaders():
                    if header.lower().startswith("location:"):
                        redirect_location = header.split(":", 1)[1].strip().lower()
                        break
                
                if any(keyword in redirect_location for keyword in ['/login', '/signin', '/auth', '/authenticate', 'login?', 'signin?']):
                    verdict = "SAFE"
                    details = "Redirect to login - access properly blocked"
                else:
                    verdict = "SUSPICIOUS"
                    details = "Redirect to: " + redirect_location[:100] + " - manual review recommended"
            
            elif status in [200, 201, 204]:
                verdict = "VULNERABLE"
                details = "Lower privilege role accessed restricted resource (Status: " + str(status) + ")"
            
            elif status in [401, 403, 405]:
                verdict = "SAFE"
                details = "Access properly blocked (Status: " + str(status) + ")"
            
            elif status >= 400:
                verdict = "SUSPICIOUS"
                details = "Unexpected status: " + str(status) + " - review manually"
            
            print("[%s] %s %s as %s -> %d" % (verdict, req['method'], req['url'][:50], role_name, status))
            
            return {
                "endpoint": req['url'],
                "method": req['method'],
                "role": role_name,
                "status": status,
                "verdict": verdict,
                "details": details,
                "request_bytes": request_bytes if self.store_full_messages else None,
                "response_bytes": response_bytes if self.store_full_messages else None,
                "service": service
            }
        except Exception as e:
            print("[-] Replay error: " + str(e))
            import traceback
            traceback.print_exc()
            return {
                "endpoint": req.get('url', 'Unknown'),
                "method": req.get('method', 'Unknown'),
                "role": role_name,
                "status": 0,
                "verdict": "ERROR",
                "details": str(e),
                "request_bytes": None,
                "response_bytes": None
            }
    
    def refresh_capture_table(self):
        self.capture_table_model.setRowCount(0)
        with self.roles_lock:
            for name, data in self.roles.items():
                self.capture_table_model.addRow([
                    name, 
                    len(data.get("requests", [])), 
                    len(data.get("cookies", [])), 
                    len(data.get("headers", []))
                ])
    
    def refresh_mapping_table(self):
        self.mapping_table_model.setRowCount(0)
        with self.roles_lock:
            for name, data in self.roles.items():
                status = "BASELINE" if name == self.baseline_role else ""
                self.mapping_table_model.addRow([
                    name, 
                    len(data.get("requests", [])), 
                    len(data.get("cookies", [])), 
                    len(data.get("headers", [])), 
                    status
                ])
    
    def update_role_filter(self):
        self.role_filter.removeAllItems()
        self.role_filter.addItem("All")
        with self.roles_lock:
            for name in self.roles.keys():
                self.role_filter.addItem(name)
    
    def refresh_dashboard(self):
        self.results_table_model.setRowCount(0)
        vuln = safe = susp = 0
        
        with self.results_lock:
            for r in self.test_results:
                self.results_table_model.addRow([
                    r['endpoint'], 
                    r['method'], 
                    r['role'], 
                    str(r['status']), 
                    r['verdict'], 
                    r.get('details', '')
                ])
                if r['verdict'] == 'VULNERABLE':
                    vuln += 1
                elif r['verdict'] == 'SAFE':
                    safe += 1
                elif r['verdict'] == 'SUSPICIOUS':
                    susp += 1
            total = len(self.test_results)
        
        self.update_stat(self.total_card, str(total))
        self.update_stat(self.vuln_card, str(vuln))
        self.update_stat(self.safe_card, str(safe))
        self.update_stat(self.susp_card, str(susp))
        self.update_role_filter()
    
    def update_stat(self, card, value):
        label = card.getClientProperty("value_label")
        if label:
            label.setText(value)
    
    def delete_role(self, event):
        row = self.capture_table.getSelectedRow()
        if row >= 0:
            name = self.capture_table_model.getValueAt(row, 0)
            if name == self.baseline_role:
                JOptionPane.showMessageDialog(self.main_panel, "Cannot delete baseline!")
                return
            confirm = JOptionPane.showConfirmDialog(
                self.main_panel, 
                "Delete '" + str(name) + "'?", 
                "Confirm", 
                JOptionPane.YES_NO_OPTION
            )
            if confirm == JOptionPane.YES_OPTION:
                with self.roles_lock:
                    del self.roles[name]
                self.refresh_capture_table()
                self.refresh_mapping_table()
                self.update_role_filter()
        else:
            JOptionPane.showMessageDialog(self.main_panel, "Select a role!")
    
    def stop_testing(self, event):
        self.testing_active = False
        self.start_test_btn.setEnabled(True)
        self.stop_test_btn.setEnabled(False)
    
    def get_filtered_results(self):
        filtered = []
        for i in range(self.results_table.getRowCount()):
            model_row = self.results_table.convertRowIndexToModel(i)
            with self.results_lock:
                if model_row < len(self.test_results):
                    filtered.append(self.test_results[model_row])
        return filtered
    
    def export_results(self, event, filtered_only):
        with self.results_lock:
            if not self.test_results:
                JOptionPane.showMessageDialog(self.main_panel, "No results!")
                return
        
        try:
            results_to_export = self.get_filtered_results() if filtered_only else self.test_results[:]
            export_list = []
            for r in results_to_export:
                export_list.append({
                    "endpoint": r['endpoint'],
                    "method": r['method'],
                    "role": r['role'],
                    "status": r['status'],
                    "verdict": r['verdict'],
                    "details": r['details']
                })
            export_data = {
                "extension": "AuthMatrix Pro v1.1",
                "baseline_role": self.baseline_role,
                "export_type": "filtered" if filtered_only else "all",
                "total": len(export_list),
                "vulnerabilities": len([r for r in export_list if r['verdict'] == 'VULNERABLE']),
                "results": export_list
            }
            json_str = json.dumps(export_data, indent=2)
            text_area = JTextArea(json_str)
            text_area.setEditable(False)
            text_area.setFont(Font("Consolas", Font.PLAIN, 10))
            scroll = JScrollPane(text_area)
            scroll.setPreferredSize(Dimension(700, 500))
            JOptionPane.showMessageDialog(
                self.main_panel, 
                scroll, 
                "Export", 
                JOptionPane.INFORMATION_MESSAGE
            )
            print("[+] Exported %d results" % len(export_list))
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, "Export failed: " + str(e))
            import traceback
            traceback.print_exc()
    
    def clear_results(self, event):
        with self.results_lock:
            if not self.test_results:
                return
            count = len(self.test_results)
        
        confirm = JOptionPane.showConfirmDialog(
            self.main_panel, 
            "Clear all " + str(count) + " results?", 
            "Confirm", 
            JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            with self.results_lock:
                self.test_results = []
            self.refresh_dashboard()
            self._request_viewer.setMessage(None, True)
            self._response_viewer.setMessage(None, False)
            print("[+] Cleared")
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self.is_capturing and messageIsRequest:
            try:
                request = messageInfo.getRequest()
                analyzed = self._helpers.analyzeRequest(messageInfo)
                headers = list(analyzed.getHeaders())
                url = str(analyzed.getUrl())
                method = analyzed.getMethod()
                
                print("[CAPTURE] " + method + " " + url[:80])
                
                if self.should_ignore_url(url):
                    print("[IGNORED] Static: " + url[:80])
                    return
                
                service = messageInfo.getHttpService()
                host = service.getHost()
                port = service.getPort()
                protocol = service.getProtocol()
                body_offset = analyzed.getBodyOffset()
                
                body = request[body_offset:]
                try:
                    body_str = body.tostring() if hasattr(body, 'tostring') else str(body)
                except:
                    body_str = ""
                
                req_hash = self.compute_request_hash(method, url, body_str)
                if req_hash and req_hash in self.request_hashes:
                    print("[DUPLICATE] Skipping: " + method + " " + url[:80])
                    return
                
                if req_hash:
                    self.request_hashes.add(req_hash)
                
                cookies = []
                auth_headers = []
                for h in headers:
                    hl = h.lower()
                    if hl.startswith("cookie:"):
                        cookies.append(h)
                    elif "authorization" in hl or "token" in hl or "x-auth" in hl or "bearer" in hl:
                        auth_headers.append(h)
                
                with self.roles_lock:
                    if self.current_role in self.roles:
                        self.roles[self.current_role]["requests"].append({
                            "url": url,
                            "method": method,
                            "headers": headers,
                            "cookies": cookies,
                            "body": body_str,
                            "host": host,
                            "port": port,
                            "protocol": protocol
                        })
                        
                        for c in cookies:
                            if c not in self.roles[self.current_role]["cookies"]:
                                self.roles[self.current_role]["cookies"].append(c)
                        
                        for h in auth_headers:
                            if h not in self.roles[self.current_role]["headers"]:
                                self.roles[self.current_role]["headers"].append(h)
                        
                        num = len(self.roles[self.current_role]["requests"])
                
                self.progress_bar.setValue(min(num, 100))
                self.progress_bar.setString(str(num) + " requests")
                print("[STORED] " + method + " for " + self.current_role + " (Total: " + str(num) + ")")
            except Exception as e:
                print("[-] Capture error: " + str(e))
                import traceback
                traceback.print_exc()

class TableSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self._extender = extender
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            row = self._extender.results_table.getSelectedRow()
            self._extender.display_request_response(row)