#!/usr/bin/env python3
"""
Real-Time Network Packet Analyzer
Main entry point for the GUI application.
"""

import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QIcon
from ui.main_window import MainWindow

def main():
    """Main function to start the application."""
    app = QApplication(sys.argv)
    app.setApplicationName("Real-Time Network Packet Analyzer")
    app.setApplicationVersion("1.0")

    # Set application icon if available
    icon_path = os.path.join(os.path.dirname(__file__), 'assets', 'icon.png')
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    # Load dark theme stylesheet
    style_path = os.path.join(os.path.dirname(__file__), 'ui', 'styles.qss')
    if os.path.exists(style_path):
        with open(style_path, 'r') as f:
            app.setStyleSheet(f.read())

    # Create and show main window
    window = MainWindow()
    window.show()

    # Start event loop
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
