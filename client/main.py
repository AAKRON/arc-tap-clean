#!/usr/bin/env python3
"""
Arc-TAP NFC Utility - Main Application Entry Point (Client)

This module serves as the main entry point for the Arc-TAP NFC Utility
desktop application. It initializes configuration, sets up logging,
creates controllers, and starts the user interface.
"""

import os
import sys
import logging
import traceback
from pathlib import Path
from typing import Optional, Any

# This file (main.py) is in the 'client' directory.
# Modules like 'config', 'services', etc., are in 'client/src/'.
# To import 'from src.utils.config import config', the 'client' directory
# (which is the parent of 'src') needs to be in sys.path.
# The current CLIENT_DIR setup correctly points to 'client/'.
CLIENT_DIR = Path(__file__).resolve().parent
if str(CLIENT_DIR) not in sys.path:
    sys.path.insert(0, str(CLIENT_DIR)) # Add 'client' to sys.path

# PyQt5 imports
try:
    from PyQt5.QtWidgets import QApplication, QMessageBox, QSplashScreen, QStyleFactory, QWidget, QLabel, QVBoxLayout
    from PyQt5.QtGui import QPixmap, QIcon
    from PyQt5.QtCore import Qt, QTimer
except ImportError:
    # This is a critical error for a GUI application.
    print("CRITICAL ERROR: PyQt5 library not found. "
          "Please install it using 'pip install PyQt5'.", file=sys.stderr)
    sys.exit(1)

# Attempt to import actual application modules
# These will be fully implemented in their respective files.
try:
    from src.utils.config import config # Uses the global instance from config.py
    # Assuming a function in logging_config.py that uses the config object
    # from src.utils.logging_config import setup_logging_from_config
    from src.services.database_service import DatabaseService
    from src.services.tag_operations import TagOperationsService
    # from src.controllers.nfc_controller import NFCController # Actual import later
    from src.controllers.batch_controller import BatchController # Actual import
    # from src.ui.main_window import MainWindow # Actual import later
except ImportError as e:
    print(f"CRITICAL ERROR: Failed to import core application modules: {e}. "
          "Ensure all modules are correctly placed in the 'src' directory and dependencies are installed.",
          file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)


# --- Placeholder for logging_config.py content (until it's created) ---
def setup_logging_from_config(app_config: Any) -> logging.Logger: # app_config is 'config' instance
    """Sets up logging based on the provided configuration object."""
    log_level_val = getattr(logging, app_config.LOG_LEVEL.upper(), logging.INFO)
    
    # Ensure log directory exists
    app_config.LOG_DIR.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=log_level_val,
        format='%(asctime)s [%(levelname)s] %(name)s (%(module)s.%(funcName)s:%(lineno)d): %(message)s',
        handlers=[
            logging.FileHandler(app_config.LOG_FILE_PATH, mode='a'),
            logging.StreamHandler(sys.stdout) # Also log to console
        ]
    )
    logger = logging.getLogger(app_config.APP_NAME) # Use app name for the main logger
    logger.info(f"Logging initialized at level {app_config.LOG_LEVEL} to {app_config.LOG_FILE_PATH}")
    return logger

# --- Placeholder UI and Controller components (to be replaced by actual imports) ---
# These are simplified versions to make main.py runnable before full UI/Controller implementation.

class PlaceholderNFCController:
    """Minimal placeholder for NFCController if actual is not ready."""
    def __init__(self, tag_ops_service: TagOperationsService):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.tag_ops = tag_ops_service
        self.logger.info("PlaceholderNFCController initialized.")

    def start_polling(self):
        self.logger.info("PlaceholderNFCController: Polling would start here.")
        if self.tag_ops:
            self.tag_ops.start_polling()

    def disconnect(self):
        self.logger.info("PlaceholderNFCController: Disconnecting.")
        if self.tag_ops:
            self.tag_ops.disconnect_reader()
            self.tag_ops.cleanup()
    
    # Add other methods that MainWindow might call (even if they do nothing yet)
    def connect_to_reader(self) -> bool:
        self.logger.info("PlaceholderNFCController: connect_to_reader called.")
        return self.tag_ops.connect_reader() if self.tag_ops else False


class PlaceholderMainWindow(QWidget): # Use QWidget for simplicity
    """Minimal placeholder for the main UI window."""
    def __init__(self, nfc_controller: Any, batch_controller: Any, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.nfc_ctrl = nfc_controller
        self.batch_ctrl = batch_controller
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self.setWindowTitle(f"{config.APP_NAME} v{config.CLIENT_VERSION} (Placeholder UI)")
        self.setMinimumSize(800, 600)
        
        # Basic UI
        layout = QVBoxLayout(self)
        self.info_label = QLabel("Arc-TAP NFC Utility - Main Window (Placeholder)\n"
                                 "Full UI to be implemented in src/ui/main_window.py", self)
        self.info_label.setAlignment(Qt.AlignCenter)
        font = self.info_label.font()
        font.setPointSize(14)
        self.info_label.setFont(font)
        layout.addWidget(self.info_label)
        
        self.logger.info("PlaceholderMainWindow UI initialized.")

    def show(self):
        super().show()
        self.logger.info("PlaceholderMainWindow shown.")

# Use actual controllers if available, otherwise placeholders
try:
    from src.controllers.nfc_controller import NFCController
except ImportError:
    NFCController = PlaceholderNFCController # type: ignore
    logging.warning("Using PlaceholderNFCController as actual src.controllers.nfc_controller not found.")

try:
    from src.ui.main_window import MainWindow
except ImportError:
    MainWindow = PlaceholderMainWindow # type: ignore
    logging.warning("Using PlaceholderMainWindow as actual src.ui.main_window not found.")


# --- Global Exception Handler ---
def setup_global_exception_handler(app_logger: logging.Logger) -> None:
    """Sets up a global exception handler to log unhandled exceptions."""
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback) # Default hook for Ctrl+C
            return

        app_logger.critical("Unhandled exception caught by global handler:",
                            exc_info=(exc_type, exc_value, exc_traceback))

        if QApplication.instance(): # Show GUI message box if app is running
            error_message = (f"An unexpected critical error occurred: {exc_value}\n\n"
                             f"Details have been logged to:\n{config.LOG_FILE_PATH}\n\n"
                             "The application may need to close.")
            QMessageBox.critical(None, "Critical Application Error", error_message)
        else: # Fallback to console if GUI not up
            print(f"CRITICAL UNHANDLED ERROR: {exc_value}", file=sys.stderr)
            traceback.print_exception(exc_type, exc_value, exc_traceback, file=sys.stderr)
        
        # Optionally, decide if the app should exit here.
        # For critical errors, exiting might be safer.
        # sys.exit(1)

    sys.excepthook = handle_exception
    app_logger.info("Global exception handler set up.")


# --- Splash Screen ---
def create_splash_screen() -> Optional[QSplashScreen]:
    """Creates and shows a splash screen."""
    if not QApplication.instance(): return None

    icon_full_path = config.APP_ICON_PATH
    splash_pixmap = QPixmap(str(icon_full_path))

    if splash_pixmap.isNull():
        logging.warning(f"Splash screen icon not found at '{icon_full_path}'. Using default.")
        splash_pixmap = QPixmap(400, 200)
        splash_pixmap.fill(Qt.lightGray)
        # Could draw app name on pixmap here if desired
    
    splash = QSplashScreen(splash_pixmap)
    splash.showMessage(f"Loading {config.APP_NAME} v{config.CLIENT_VERSION}...",
                       Qt.AlignBottom | Qt.AlignCenter, Qt.black)
    splash.show()
    QApplication.processEvents() # Ensure splash is displayed
    return splash


# --- Main Application Logic ---
def main_client() -> int:
    """Main entry point for the Arc-TAP NFC Utility client application."""
    
    # 1. Initialize Configuration (global 'config' instance from src.utils.config)
    # The 'config' object is already instantiated when src.utils.config is imported.
    # Its __init__ method handles loading .env, creating dirs, and validation.
    # If config instantiation failed, the program would have exited due to ConfigError.
    app_logger = setup_logging_from_config(config) # Use actual logging setup

    # 2. Set up Global Exception Handler
    setup_global_exception_handler(app_logger)

    app_logger.info(f"--- Starting {config.APP_NAME} v{config.CLIENT_VERSION} (Env: {config.APP_ENV}) ---")

    exit_code = 0
    db_service_instance = None # For finally block
    tag_ops_service_instance = None # For finally block
    nfc_controller_instance = None # For finally block

    try:
        # 3. Create Qt Application instance
        app = QApplication(sys.argv)
        try:
            app.setStyle(QStyleFactory.create('Fusion'))
        except Exception as e_style:
            app_logger.warning(f"Could not set Fusion style (using default system style): {e_style}")
        
        app.setApplicationName(config.APP_NAME)
        app.setApplicationVersion(config.CLIENT_VERSION)
        
        if config.APP_ICON_PATH.exists():
            app.setWindowIcon(QIcon(str(config.APP_ICON_PATH)))
        else:
            app_logger.warning(f"Application icon not found at: {config.APP_ICON_PATH}")

        # 4. Show Splash Screen
        splash = create_splash_screen()
        # Simulate some loading time / actual init
        # time.sleep(1) # Example delay

        # 5. Initialize Services
        app_logger.info("Initializing core services...")
        db_service_instance = DatabaseService() # Uses global 'config'
        tag_ops_service_instance = TagOperationsService() # Uses global 'config'

        # 6. Initialize Controllers
        app_logger.info("Initializing application controllers...")
        # Pass instantiated services to controllers
        nfc_controller_instance = NFCController(tag_ops_service_instance)
        batch_controller_instance = BatchController(db_service_instance, tag_ops_service_instance)
        
        # 7. Create and Show Main Window
        app_logger.info("Creating main user interface...")
        main_window = MainWindow(nfc_controller_instance, batch_controller_instance)
        
        if splash:
            splash.finish(main_window) # Close splash when main window is ready
        main_window.show()

        # 8. Start background tasks (e.g., NFC polling)
        # Use QTimer to ensure it starts after Qt event loop is running.
        if hasattr(nfc_controller_instance, 'start_polling') and callable(nfc_controller_instance.start_polling):
            QTimer.singleShot(250, nfc_controller_instance.start_polling)
        else:
            app_logger.warning("NFCController does not have a 'start_polling' method.")


        # 9. Start the Qt event loop
        app_logger.info("Application event loop starting.")
        exit_code = app.exec_()
        app_logger.info(f"Application event loop finished. Exit code: {exit_code}")

    except SystemExit: # Allow sys.exit() to propagate for clean exits
        app_logger.info("Application exited via SystemExit.")
        # exit_code is already set by sys.exit()
        raise # Re-raise to ensure proper exit
    except Exception as e_startup:
        app_logger.critical(f"Fatal error during application startup or execution: {e_startup}", exc_info=True)
        if QApplication.instance(): # If GUI is up, global handler should have shown a message
            pass
        else: # Fallback if GUI didn't even start
             print(f"CRITICAL STARTUP ERROR: {e_startup}", file=sys.stderr)
             traceback.print_exception(type(e_startup), e_startup, e_startup.__traceback__, file=sys.stderr)
        exit_code = 1 # Indicate error
    finally:
        # Cleanup tasks
        app_logger.info("Performing application cleanup...")
        if nfc_controller_instance and hasattr(nfc_controller_instance, 'disconnect') and callable(nfc_controller_instance.disconnect):
            app_logger.info("Disconnecting NFC controller/reader...")
            nfc_controller_instance.disconnect()
        
        if db_service_instance and hasattr(db_service_instance, 'close_connections') and callable(db_service_instance.close_connections):
            app_logger.info("Closing database connections...")
            db_service_instance.close_connections()
            
        app_logger.info(f"--- {config.APP_NAME} Shutdown Complete (Exit Code: {exit_code}) ---")
    
    return exit_code


if __name__ == "__main__":
    # This ensures that main_client() is called only when this script is executed directly.
    # The exit code from main_client() will be used by sys.exit().
    sys.exit(main_client())
