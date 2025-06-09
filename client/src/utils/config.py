"""
Configuration Management for Arc-TAP NFC Utility Client.

This module handles loading application settings from environment variables
and .env files, provides sensible defaults, supports different environments,
and includes configuration validation.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Any, Optional, Literal, Union

from dotenv import load_dotenv

# --- Environment Setup ---
# Determine the application environment (development, testing, production)
# Default to 'development' if APP_ENV is not set.
APP_ENV_TYPE = Literal["development", "testing", "production"]
APP_ENV: APP_ENV_TYPE = os.getenv("APP_ENV", "development").lower() # type: ignore

# --- Path Configuration ---
# Define the base directory of the client application (client/)
# Assumes this config.py is in client/src/utils/
CLIENT_DIR = Path(__file__).resolve().parent.parent.parent # client/
ENV_FILE_NAME = f".env.{APP_ENV}" if APP_ENV != "production" else ".env"
ENV_PATH = CLIENT_DIR / ENV_FILE_NAME

# Load environment variables from the .env file specific to the environment,
# or from a generic .env file.
if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)
    # print(f"INFO: Loaded configuration from: {ENV_PATH}") # Use logger after it's set up
else:
    # Fallback to .env if specific environment file doesn't exist
    fallback_env_path = CLIENT_DIR / ".env"
    if fallback_env_path.exists():
        load_dotenv(dotenv_path=fallback_env_path)
        # print(f"INFO: Loaded configuration from fallback: {fallback_env_path}")
    else:
        # print(f"WARNING: No .env file found at {ENV_PATH} or {fallback_env_path}. Using environment variables and defaults.")
        pass # Will be logged once logger is configured

# Logger setup will happen after Config class is defined,
# so initial messages about .env loading might go to stdout/stderr if logger not yet configured.
# We'll get a logger instance within the Config class or after it's instantiated.

class ConfigError(Exception):
    """Custom exception for configuration errors."""
    pass

class Config:
    """
    Application configuration class.

    Loads settings from environment variables and .env files.
    Provides methods for accessing and validating configuration.
    """

    # --- Application Information ---
    APP_NAME: str = "Arc-TAP NFC Utility Client"
    CLIENT_VERSION: str = os.getenv("CLIENT_VERSION", "1.0.0") # Default version
    APP_ENV: APP_ENV_TYPE = APP_ENV

    # --- Debugging and Logging ---
    DEBUG: bool = APP_ENV == "development" or os.getenv("DEBUG", "False").lower() == "true"
    LOG_LEVEL_TYPE = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    LOG_LEVEL: LOG_LEVEL_TYPE = os.getenv("LOG_LEVEL", "INFO" if APP_ENV == "production" else "DEBUG").upper() # type: ignore
    LOG_DIR_NAME: str = os.getenv("LOG_DIR_NAME", "logs")
    LOG_FILE_NAME: str = os.getenv("LOG_FILE_NAME", "arc_tap_client.log")
    LOG_DIR: Path = CLIENT_DIR / LOG_DIR_NAME
    LOG_FILE_PATH: Path = LOG_DIR / LOG_FILE_NAME

    # --- Database Settings ---
    # Local SQLite Database
    DATA_DIR_NAME: str = os.getenv("DATA_DIR_NAME", "data")
    LOCAL_DB_FILE_NAME: str = os.getenv("LOCAL_DB_FILE_NAME", "arc_tap_local.db")
    LOCAL_DB_DIR: Path = CLIENT_DIR / DATA_DIR_NAME
    LOCAL_DB_PATH: Path = LOCAL_DB_DIR / LOCAL_DB_FILE_NAME

    # Remote Neon PostgreSQL Database (Optional)
    # Example: postgresql://user:password@host:port/dbname
    NEON_DATABASE_URL: Optional[str] = os.getenv("NEON_DATABASE_URL")

    # --- Security ---
    # Fernet encryption key (32 url-safe base64-encoded bytes string from environment)
    ENCRYPTION_KEY_STR: Optional[str] = os.getenv("ENCRYPTION_KEY")
    ENCRYPTION_KEY_BYTES: Optional[bytes] = None # Derived to bytes for Fernet

    # --- NFC Specific Settings ---
    DEFAULT_NFC_URL_SCHEME: str = os.getenv("DEFAULT_NFC_URL_SCHEME", "https://")
    DEFAULT_NFC_WRITE_URL: str = os.getenv("DEFAULT_NFC_WRITE_URL", "aakronline.com/tap") # Example
    NFC_POLLING_INTERVAL_S: float = float(os.getenv("NFC_POLLING_INTERVAL_S", "0.75"))


    # --- UI and Resources ---
    RESOURCES_DIR_NAME: str = os.getenv("RESOURCES_DIR_NAME", "resources")
    RESOURCES_DIR: Path = CLIENT_DIR / RESOURCES_DIR_NAME
    APP_ICON_NAME: str = os.getenv("APP_ICON_NAME", "app_icon.png") # Example icon name
    APP_ICON_PATH: Path = RESOURCES_DIR / APP_ICON_NAME

    _logger: Optional[logging.Logger] = None


    def __init__(self):
        """
        Initializes the configuration object, creates directories, derives keys, and validates.
        """
        # Initialize logger for Config class itself first
        # This allows Config methods to log warnings/errors during setup
        # Basic setup until full logging_config module is imported and used by main.py
        if not Config._logger: # Setup logger only once
            Config._logger = logging.getLogger(self.__class__.__name__)
            # Basic config for early messages if main logger not set up yet
            if not logging.getLogger().hasHandlers(): # Check if root logger is configured
                logging.basicConfig(level=self.LOG_LEVEL, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
            Config._logger.setLevel(self.LOG_LEVEL) # Ensure Config's logger uses its own level

        self._log_env_loading_status() # Log .env loading status now that logger is available
        self._create_directories()
        self._derive_encryption_key_bytes()
        self.validate() # Perform validation upon instantiation

    def _log_env_loading_status(self):
        if ENV_PATH.exists():
            self._logger.info(f"Configuration successfully loaded from: {ENV_PATH}")
        else:
            fallback_env_path = CLIENT_DIR / ".env"
            if fallback_env_path.exists():
                self._logger.info(f"Configuration successfully loaded from fallback: {fallback_env_path}")
            else:
                self._logger.warning(f"No .env file found at {ENV_PATH} or {fallback_env_path}. "
                                    "Using environment variables and default settings.")


    def _create_directories(self) -> None:
        """Creates necessary directories if they don't exist."""
        try:
            self.LOG_DIR.mkdir(parents=True, exist_ok=True)
            self.LOCAL_DB_DIR.mkdir(parents=True, exist_ok=True)
            self.RESOURCES_DIR.mkdir(parents=True, exist_ok=True)
            self._logger.debug(f"Ensured directories exist: Logs at '{self.LOG_DIR}', Data at '{self.LOCAL_DB_DIR}'")
        except OSError as e:
            self._logger.error(f"Error creating application directories: {e}")
            # Depending on severity, could raise ConfigError

    def _derive_encryption_key_bytes(self) -> None:
        """
        Derives the Fernet encryption key (bytes) from the string environment variable.
        Warns if the key is missing or invalid.
        """
        if self.ENCRYPTION_KEY_STR:
            try:
                key_as_bytes = self.ENCRYPTION_KEY_STR.encode('utf-8')
                # Validate by attempting to instantiate Fernet (requires cryptography lib)
                from cryptography.fernet import Fernet
                Fernet(key_as_bytes) # This will raise ValueError if key is invalid
                self.ENCRYPTION_KEY_BYTES = key_as_bytes
                self._logger.info("Encryption key loaded and validated successfully from environment.")
            except ImportError:
                self._logger.error("cryptography library not found. ENCRYPTION_KEY cannot be validated or used.")
                self.ENCRYPTION_KEY_BYTES = None
            except ValueError as e: # Catch Fernet's error for invalid key
                self._logger.error(f"ENCRYPTION_KEY is invalid: {e}. Encryption features will be disabled.")
                self.ENCRYPTION_KEY_BYTES = None
            except Exception as e: # Catch other unexpected errors
                self._logger.error(f"Unexpected error processing ENCRYPTION_KEY: {e}. Encryption disabled.")
                self.ENCRYPTION_KEY_BYTES = None
        else:
            if self.is_production():
                self._logger.critical("CRITICAL: ENCRYPTION_KEY is NOT SET in a production environment! "
                                "Sensitive data cannot be securely encrypted. Application may be insecure.")
                # Consider raising ConfigError for production if key is mandatory
                # raise ConfigError("ENCRYPTION_KEY must be set and valid in production.")
            else: # Development or Testing
                self._logger.warning("ENCRYPTION_KEY is not set. Generating a temporary development key (INSECURE and CHANGES ON EACH RUN). "
                               "For consistent encryption in development, set a valid ENCRYPTION_KEY in your .env file.")
                try:
                    from cryptography.fernet import Fernet
                    self.ENCRYPTION_KEY_BYTES = Fernet.generate_key()
                    self._logger.debug(f"Generated temporary development ENCRYPTION_KEY: {self.ENCRYPTION_KEY_BYTES.decode()}.")
                except ImportError:
                    self._logger.error("cryptography library not found. Cannot generate development encryption key.")
                    self.ENCRYPTION_KEY_BYTES = None

    def validate(self) -> None:
        """
        Validates critical configuration settings.
        Logs warnings or raises ConfigError if validation fails.
        """
        # Validate Log Level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.LOG_LEVEL not in valid_log_levels:
            self._logger.error(f"Invalid LOG_LEVEL: '{self.LOG_LEVEL}'. Defaulting to INFO. Must be one of {valid_log_levels}.")
            self.LOG_LEVEL = "INFO" # Fallback to a safe default

        # Validate Encryption Key (already handled by _derive_encryption_key_bytes for validity)
        if self.is_production() and not self.ENCRYPTION_KEY_BYTES:
            # This is a critical failure for production.
            # _derive_encryption_key_bytes logs this, but we might want to raise here too.
            # For now, rely on the critical log from derivation.
            pass

        # Validate Neon DB URL if provided (basic check)
        if self.NEON_DATABASE_URL and not self.NEON_DATABASE_URL.startswith("postgresql://"):
            self._logger.error(
                f"Invalid NEON_DATABASE_URL format: '{self.NEON_DATABASE_URL}'. "
                "It should start with 'postgresql://'. Remote DB functionality may fail."
            )
            # Optionally raise ConfigError or nullify NEON_DATABASE_URL
            # self.NEON_DATABASE_URL = None 
        
        # Validate default NFC URL scheme
        if self.DEFAULT_NFC_URL_SCHEME not in ["http://", "https://"]:
             self._logger.warning(
                f"Invalid DEFAULT_NFC_URL_SCHEME: '{self.DEFAULT_NFC_URL_SCHEME}'. Defaulting to 'https://'."
            )
             self.DEFAULT_NFC_URL_SCHEME = "https://"
        
        try:
            interval = float(self.NFC_POLLING_INTERVAL_S)
            if not (0.1 <= interval <= 5.0):
                self._logger.warning(f"NFC_POLLING_INTERVAL_S ({interval}s) is outside recommended range (0.1s-5s). Defaulting to 0.75s.")
                self.NFC_POLLING_INTERVAL_S = 0.75
        except ValueError:
            self._logger.warning(f"Invalid NFC_POLLING_INTERVAL_S ('{self.NFC_POLLING_INTERVAL_S}'). Must be a float. Defaulting to 0.75s.")
            self.NFC_POLLING_INTERVAL_S = 0.75


        self._logger.info(f"Configuration validated successfully for APP_ENV='{self.APP_ENV}'.")

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieves a configuration value by its attribute name."""
        return getattr(self, key, default)

    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    def is_development(self) -> bool:
        return self.APP_ENV == "development"

    def is_testing(self) -> bool:
        return self.APP_ENV == "testing"

    def __str__(self) -> str:
        """String representation of the config for debugging, masking sensitive values."""
        masked_neon_url = f"{self.NEON_DATABASE_URL[:20]}..." if self.NEON_DATABASE_URL and len(self.NEON_DATABASE_URL) > 20 else self.NEON_DATABASE_URL
        masked_enc_key_status = "Set (masked)" if self.ENCRYPTION_KEY_BYTES else "Not Set or Invalid"
        return (
            f"Config(APP_NAME='{self.APP_NAME}', VERSION='{self.CLIENT_VERSION}', APP_ENV='{self.APP_ENV}', DEBUG={self.DEBUG}, "
            f"LOG_LEVEL='{self.LOG_LEVEL}', LOG_FILE_PATH='{self.LOG_FILE_PATH}', "
            f"LOCAL_DB_PATH='{self.LOCAL_DB_PATH}', "
            f"NEON_DATABASE_URL='{masked_neon_url if masked_neon_url else 'Not Set'}', "
            f"ENCRYPTION_KEY_STATUS='{masked_enc_key_status}')"
        )

# --- Global Configuration Instance ---
# This instance is created when the module is imported.
# Application components can import this instance directly: from src.utils.config import config
try:
    config = Config()
except ConfigError as e:
    # Use a basic logger if config._logger failed to initialize
    emergency_logger = logging.getLogger("ConfigEmergency")
    if not emergency_logger.hasHandlers():
        logging.basicConfig(level="ERROR") # Ensure messages are visible
    emergency_logger.critical(f"CRITICAL FAILURE during Config instantiation: {e}. Application cannot start.")
    print(f"CRITICAL CONFIGURATION ERROR: {e}", file=sys.stderr)
    sys.exit(1) # Exit if config validation fails critically during instantiation

# Example of how to use the config instance in other modules:
# from .config import config
# db_url = config.NEON_DATABASE_URL
# if config.is_development():
#     print("Running in development mode")

if __name__ == "__main__":
    # This block is for testing the configuration module directly.
    # It will run when you execute `python -m src.utils.config` from the `client` directory.
    
    # Ensure a basic logger is available for the test output
    test_logger_name = "ConfigModuleTest"
    test_logger = logging.getLogger(test_logger_name)
    if not test_logger.hasHandlers(): # Configure if not already configured by Config()
        logging.basicConfig(level=config.LOG_LEVEL if 'config' in locals() and hasattr(config, 'LOG_LEVEL') else "DEBUG",
                            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        test_logger.setLevel(config.LOG_LEVEL if 'config' in locals() and hasattr(config, 'LOG_LEVEL') else "DEBUG")


    test_logger.info("--- Configuration Module Self-Test ---")
    test_logger.info(f"Current Environment (APP_ENV from os.getenv): {os.getenv('APP_ENV', 'Not Set -> defaults to development')}")
    test_logger.info(f"Attempted to load .env path: {ENV_PATH}")
    test_logger.info(f".env file exists: {ENV_PATH.exists()}")
    
    if 'config' in locals() and isinstance(config, Config):
        test_logger.info(f"Successfully instantiated Config object.")
        test_logger.info(f"Config Details: {config}") # Uses the __str__ method
        
        test_logger.info(f"Log file path from config: {config.LOG_FILE_PATH}")
        test_logger.info(f"Local DB path from config: {config.LOCAL_DB_PATH}")
        
        if config.NEON_DATABASE_URL:
            test_logger.info(f"Neon DB URL is SET (value masked in general log).")
        else:
            test_logger.info("Neon DB URL is NOT SET.")

        if config.ENCRYPTION_KEY_BYTES:
            test_logger.info(f"Encryption key (bytes) is SET (value masked). Length: {len(config.ENCRYPTION_KEY_BYTES)} bytes.")
            try:
                from cryptography.fernet import Fernet
                Fernet(config.ENCRYPTION_KEY_BYTES)
                test_logger.info("Encryption key is VALID for Fernet.")
            except Exception as e_fernet:
                test_logger.error(f"Loaded Encryption key test FAILED with Fernet: {e_fernet}")
        else:
            test_logger.warning("Encryption key (bytes) is NOT SET or was invalid.")
        
        test_logger.info(f"Log directory exists: {config.LOG_DIR.exists()}")
        test_logger.info(f"Local DB directory exists: {config.LOCAL_DB_DIR.exists()}")
        test_logger.info(f"Resources directory exists: {config.RESOURCES_DIR.exists()}")
        test_logger.info(f"App Icon Path: {config.APP_ICON_PATH} (Exists: {config.APP_ICON_PATH.exists()})")

    else:
        test_logger.error("Global 'config' object was not created or is not a Config instance. Check for critical errors during Config instantiation.")

    test_logger.info("--- End Configuration Module Self-Test ---")
