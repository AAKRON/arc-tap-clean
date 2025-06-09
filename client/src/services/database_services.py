"""
Database Service for the Arc-TAP NFC Utility client application.

This module provides a service layer for database operations, supporting
both a local SQLite database and a remote PostgreSQL (Neon) database.
It uses an adapter pattern to interact with different database systems.
"""

import os
import sqlite3
import psycopg2 # type: ignore
import psycopg2.pool # type: ignore
import psycopg2.extras # type: ignore
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Tuple, Union
from datetime import datetime
import json
from pathlib import Path
from dataclasses import dataclass, field, fields # Import fields for dynamic BatchRecord creation
import uuid # For generating batch_id

# --- Configuration Placeholder ---
# In a real application, this would be imported from src.utils.config
class ConfigPlaceholder:
    """Placeholder for application configuration."""
    APP_ENV: str = os.getenv("APP_ENV", "development").lower()
    CLIENT_DIR = Path(__file__).resolve().parent.parent.parent # Assumes this file is in client/src/services/

    LOCAL_DB_FILE_NAME: str = os.getenv("LOCAL_DB_FILE_NAME", "arc_tap_local.db")
    LOCAL_DB_DIR: Path = CLIENT_DIR / "data"
    LOCAL_DB_PATH: Path = LOCAL_DB_DIR / LOCAL_DB_FILE_NAME

    NEON_DATABASE_URL: Optional[str] = os.getenv("NEON_DATABASE_URL")
    ENCRYPTION_KEY: Optional[str] = os.getenv("ENCRYPTION_KEY") # URL-safe base64-encoded 32-byte key string

    def __init__(self):
        self.LOCAL_DB_DIR.mkdir(parents=True, exist_ok=True)
        if self.APP_ENV == "production":
            if not self.NEON_DATABASE_URL:
                logger.critical("CRITICAL: NEON_DATABASE_URL is NOT SET in production environment!")
            if not self.ENCRYPTION_KEY:
                logger.critical("CRITICAL: ENCRYPTION_KEY is NOT SET in production environment!")

config = ConfigPlaceholder()

# --- Logging Setup ---
logger = logging.getLogger(__name__)
# Basic logging config if not already set up by main application
if not logger.hasHandlers():
    logging.basicConfig(level=logging.INFO if config.APP_ENV == "production" else logging.DEBUG,
                        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')

# --- Encryption Utilities Placeholder ---
_cipher = None
if config.ENCRYPTION_KEY:
    try:
        from cryptography.fernet import Fernet
        _cipher = Fernet(config.ENCRYPTION_KEY.encode('utf-8')) # Fernet key must be bytes
        logger.info("Fernet cipher initialized for password encryption.")
    except ImportError:
        logger.error("cryptography library not found. Password encryption will NOT work.")
    except ValueError as e:
        logger.error(f"Invalid ENCRYPTION_KEY: {e}. Password encryption will NOT work.")
else:
    logger.warning("ENCRYPTION_KEY not set. Passwords will NOT be encrypted.")

def encrypt_data(clear_text_password: str) -> Optional[bytes]:
    if _cipher and clear_text_password:
        try:
            return _cipher.encrypt(clear_text_password.encode('utf-8'))
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return None
    return None

def decrypt_data(encrypted_password_bytes: bytes) -> Optional[str]:
    if _cipher and encrypted_password_bytes:
        try:
            return _cipher.decrypt(encrypted_password_bytes).decode('utf-8')
        except Exception as e: # Includes InvalidToken
            logger.error(f"Decryption failed (key mismatch or corrupted data?): {e}")
            return None # Or raise an error
    return None

# --- BatchRecord Model Placeholder ---
@dataclass
class BatchRecord:
    """Data class for representing a batch operation."""
    destination_url: str
    quantity: int
    batch_id: str = field(default_factory=lambda: f"batch_{uuid.uuid4().hex[:8]}")
    static_url: Optional[str] = None
    customer_name: Optional[str] = None
    customer_id: Optional[str] = None
    order_number: Optional[str] = None
    password: Optional[str] = None  # Cleartext password (used for input/output, not stored directly)
    encrypted_password: Optional[bytes] = None # Encrypted password for DB storage
    payment_status: str = "Pending"
    start_uid: Optional[str] = None
    finish_uid: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    completed: bool = False
    tags_written: int = 0
    errors: int = 0

    def to_db_dict(self) -> Dict[str, Any]:
        """Prepares a dictionary suitable for database insertion/update."""
        return {
            "batch_id": self.batch_id,
            "destination_url": self.destination_url,
            "static_url": self.static_url,
            "customer_name": self.customer_name,
            "customer_id": self.customer_id,
            "order_number": self.order_number,
            "payment_status": self.payment_status,
            "encrypted_password": self.encrypted_password, # This should be bytes
            "quantity": self.quantity,
            "start_uid": self.start_uid,
            "finish_uid": self.finish_uid,
            "created_at": self.created_at.isoformat(), # Store as ISO string
            "updated_at": self.updated_at.isoformat(), # Store as ISO string
            "completed": 1 if self.completed else 0, # SQLite uses 0/1 for BOOLEAN
            "tags_written": self.tags_written,
            "errors": self.errors
        }

    @classmethod
    def from_db_row(cls, row: Union[sqlite3.Row, psycopg2.extras.DictRow]) -> 'BatchRecord':
        """Creates a BatchRecord instance from a database row (sqlite3.Row or DictRow)."""
        row_dict = dict(row)
        
        # Handle cleartext password by decrypting
        cleartext_password = None
        if row_dict.get('encrypted_password'):
            cleartext_password = decrypt_data(row_dict['encrypted_password'])
            if cleartext_password is None:
                 logger.warning(f"Failed to decrypt password for batch {row_dict.get('batch_id')}. Password will be None.")
        
        # Ensure all fields expected by __init__ are present or have defaults
        batch_fields = {f.name for f in fields(cls)}
        init_data = {k: row_dict.get(k) for k in batch_fields if k in row_dict}

        # Specific type conversions
        init_data['password'] = cleartext_password # Set the decrypted password
        if 'encrypted_password' in init_data: # Don't pass encrypted_password to constructor if password is set
            del init_data['encrypted_password']

        if 'created_at' in row_dict and isinstance(row_dict['created_at'], str):
            init_data['created_at'] = datetime.fromisoformat(row_dict['created_at'])
        elif 'created_at' not in init_data: # Should be set by DB default or Python default
            init_data['created_at'] = datetime.now()

        if 'updated_at' in row_dict and isinstance(row_dict['updated_at'], str):
            init_data['updated_at'] = datetime.fromisoformat(row_dict['updated_at'])
        elif 'updated_at' not in init_data:
            init_data['updated_at'] = datetime.now()
            
        # SQLite stores booleans as 0/1
        if 'completed' in row_dict and isinstance(row_dict['completed'], int):
            init_data['completed'] = bool(row_dict['completed'])
        
        # Ensure all required fields for BatchRecord constructor are present
        # destination_url and quantity are mandatory
        if 'destination_url' not in init_data: init_data['destination_url'] = "N/A" # Should not happen
        if 'quantity' not in init_data: init_data['quantity'] = 0 # Should not happen

        return cls(**init_data)


# --- Database Adapter Interface ---
class DatabaseAdapter(ABC):
    """Abstract Base Class for database adapters."""
    @abstractmethod
    def connect(self) -> Any: pass
    @abstractmethod
    def disconnect(self, conn: Optional[Any] = None) -> None: pass
    @abstractmethod
    def init_schema(self) -> None: pass
    @abstractmethod
    def register_batch_record(self, batch: BatchRecord) -> bool: pass
    @abstractmethod
    def get_batch_record(self, batch_id: str) -> Optional[BatchRecord]: pass
    @abstractmethod
    def update_batch_record(self, batch: BatchRecord) -> bool: pass
    @abstractmethod
    def delete_batch_record(self, batch_id: str) -> bool: pass
    @abstractmethod
    def list_batch_records(self, limit: int = 100, offset: int = 0) -> List[BatchRecord]: pass
    @abstractmethod
    def get_redirect_destination(self, batch_id_or_uid: str) -> Optional[str]: pass
    @abstractmethod
    def add_tag_event(self, batch_id: str, uid: str, success: bool, timestamp: datetime, error_message: Optional[str]) -> bool: pass
    @abstractmethod
    def get_tags_for_batch(self, batch_id: str) -> List[Dict[str, Any]]: pass
    @abstractmethod
    def get_statistics(self) -> Dict[str, Any]: pass

# --- SQLite Adapter ---
class SQLiteAdapter(DatabaseAdapter):
    DB_SCHEMA_VERSION = 1
    TABLES_SQL = {
        'redirects': """
            CREATE TABLE IF NOT EXISTS redirects (
                batch_id TEXT PRIMARY KEY,
                destination_url TEXT NOT NULL,
                static_url TEXT,
                customer_name TEXT,
                customer_id TEXT,
                order_number TEXT,
                payment_status TEXT,
                encrypted_password BLOB,
                quantity INTEGER NOT NULL,
                start_uid TEXT,
                finish_uid TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                completed INTEGER DEFAULT 0,
                tags_written INTEGER DEFAULT 0,
                errors INTEGER DEFAULT 0
            )
        """,
        'tags': """
            CREATE TABLE IF NOT EXISTS tags (
                uid TEXT NOT NULL,
                batch_id TEXT NOT NULL,
                written_at TEXT DEFAULT CURRENT_TIMESTAMP,
                success INTEGER DEFAULT 1,
                error_message TEXT,
                PRIMARY KEY (uid, batch_id),
                FOREIGN KEY (batch_id) REFERENCES redirects(batch_id) ON DELETE CASCADE
            )
        """,
        'schema_version': """
            CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT)
        """
    }
    INDEXES_SQL = {
        'idx_tags_batch_id_sqlite': "CREATE INDEX IF NOT EXISTS idx_tags_batch_id_sqlite ON tags(batch_id)"
    }

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = str(db_path)
        self.conn: Optional[sqlite3.Connection] = None

    def connect(self) -> sqlite3.Connection:
        if self.conn is None or self.conn.total_changes == -1: # Check if connection is closed
            try:
                self.conn = sqlite3.connect(self.db_path)
                self.conn.row_factory = sqlite3.Row
                self.conn.execute("PRAGMA foreign_keys = ON;") # Enable foreign key constraints
                logger.info(f"Connected to SQLite: {self.db_path}")
            except sqlite3.Error as e:
                logger.error(f"SQLite connection error to {self.db_path}: {e}")
                raise ConnectionError(f"SQLite connection error: {e}") from e
        return self.conn

    def disconnect(self, conn: Optional[sqlite3.Connection] = None) -> None: # conn arg for API consistency
        if self.conn:
            self.conn.close()
            self.conn = None
            logger.info("Disconnected from SQLite.")

    def _execute(self, query: str, params: Union[tuple, Dict[str, Any]] = (), commit: bool = False, fetch_one: bool = False, fetch_all: bool = False) -> Any:
        loc_conn = self.connect()
        try:
            with loc_conn: # Context manager handles commits for DML, or rollbacks on error
                cursor = loc_conn.cursor()
                cursor.execute(query, params)
                if fetch_one: return cursor.fetchone()
                if fetch_all: return cursor.fetchall()
                # For DDL (like CREATE TABLE), commit might be needed if not auto-committed by `with`
                if commit and not loc_conn.in_transaction: 
                    loc_conn.commit()
                return cursor.lastrowid if query.strip().upper().startswith("INSERT") else cursor.rowcount
        except sqlite3.Error as e:
            logger.error(f"SQLite error: {e} for query: {query[:100]}... with params: {str(params)[:100]}...")
            raise

    def init_schema(self) -> None:
        logger.info("Initializing SQLite schema...")
        for table_sql in self.TABLES_SQL.values(): self._execute(table_sql, commit=True)
        for index_sql in self.INDEXES_SQL.values(): self._execute(index_sql, commit=True)
        
        version_row = self._execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1", fetch_one=True)
        current_version = version_row['version'] if version_row else 0
        if current_version < self.DB_SCHEMA_VERSION:
            logger.info(f"SQLite schema version {current_version}, migrating to {self.DB_SCHEMA_VERSION}...")
            # Add migration logic here if needed for future versions
            self._execute("INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (?, ?)",
                          (self.DB_SCHEMA_VERSION, datetime.now().isoformat()), commit=True)
        logger.info("SQLite schema initialized/verified.")

    def register_batch_record(self, batch: BatchRecord) -> bool:
        db_data = batch.to_db_dict()
        query = """
            INSERT OR REPLACE INTO redirects 
            (batch_id, destination_url, static_url, customer_name, customer_id, order_number, 
            payment_status, encrypted_password, quantity, start_uid, finish_uid, 
            created_at, updated_at, completed, tags_written, errors)
            VALUES (:batch_id, :destination_url, :static_url, :customer_name, :customer_id, :order_number, 
            :payment_status, :encrypted_password, :quantity, :start_uid, :finish_uid, 
            :created_at, :updated_at, :completed, :tags_written, :errors)
        """
        return bool(self._execute(query, db_data))

    def get_batch_record(self, batch_id: str) -> Optional[BatchRecord]:
        row = self._execute("SELECT * FROM redirects WHERE batch_id = ?", (batch_id,), fetch_one=True)
        return BatchRecord.from_db_row(row) if row else None

    def update_batch_record(self, batch: BatchRecord) -> bool:
        # INSERT OR REPLACE handles updates too
        return self.register_batch_record(batch)

    def delete_batch_record(self, batch_id: str) -> bool:
        return bool(self._execute("DELETE FROM redirects WHERE batch_id = ?", (batch_id,)))

    def list_batch_records(self, limit: int = 100, offset: int = 0) -> List[BatchRecord]:
        rows = self._execute("SELECT * FROM redirects ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset), fetch_all=True)
        return [BatchRecord.from_db_row(row) for row in rows if row]

    def get_redirect_destination(self, batch_id_or_uid: str) -> Optional[str]:
        # Assuming redirect lookup is by batch_id for simplicity here.
        # If UID lookup is needed, would query 'tags' then 'redirects'.
        query = "SELECT static_url, destination_url FROM redirects WHERE batch_id = ?"
        row = self._execute(query, (batch_id_or_uid,), fetch_one=True)
        return row['static_url'] if row and row['static_url'] else (row['destination_url'] if row else None)

    def add_tag_event(self, batch_id: str, uid: str, success: bool, timestamp: datetime, error_message: Optional[str]) -> bool:
        query = """
            INSERT OR REPLACE INTO tags (batch_id, uid, success, written_at, error_message)
            VALUES (?, ?, ?, ?, ?)
        """
        return bool(self._execute(query, (batch_id, uid, 1 if success else 0, timestamp.isoformat(), error_message)))

    def get_tags_for_batch(self, batch_id: str) -> List[Dict[str, Any]]:
        rows = self._execute("SELECT uid, success, written_at, error_message FROM tags WHERE batch_id = ?", (batch_id,), fetch_all=True)
        return [dict(row) for row in rows]

    def get_statistics(self) -> Dict[str, Any]:
        total_batches = self._execute("SELECT COUNT(*) as count FROM redirects", fetch_one=True)['count']
        total_tags_events = self._execute("SELECT COUNT(*) as count FROM tags", fetch_one=True)['count']
        return {"total_batches": total_batches, "total_tags_events": total_tags_events}

# --- PostgreSQL Adapter ---
class PostgreSQLAdapter(DatabaseAdapter):
    DB_SCHEMA_VERSION = 1
    TABLES_SQL = { # Note: boolean and timestamptz types are different from SQLite
        'redirects': """
            CREATE TABLE IF NOT EXISTS redirects (
                batch_id TEXT PRIMARY KEY,
                destination_url TEXT NOT NULL,
                static_url TEXT,
                customer_name TEXT,
                customer_id TEXT,
                order_number TEXT,
                payment_status TEXT,
                encrypted_password BYTEA,
                quantity INTEGER NOT NULL,
                start_uid TEXT,
                finish_uid TEXT,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                completed BOOLEAN DEFAULT FALSE,
                tags_written INTEGER DEFAULT 0,
                errors INTEGER DEFAULT 0
            )
        """,
        'tags': """
            CREATE TABLE IF NOT EXISTS tags (
                uid TEXT NOT NULL,
                batch_id TEXT NOT NULL REFERENCES redirects(batch_id) ON DELETE CASCADE,
                written_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT TRUE,
                error_message TEXT,
                PRIMARY KEY (uid, batch_id)
            )
        """,
        'schema_version': """
            CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ)
        """
    }
    INDEXES_SQL = {
        'idx_tags_batch_id_pg': "CREATE INDEX IF NOT EXISTS idx_tags_batch_id_pg ON tags(batch_id)"
    }

    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool: Optional[psycopg2.pool.SimpleConnectionPool] = None
        self._init_pool()

    def _init_pool(self):
        try:
            # minconn=1, maxconn=5. Adjust as needed.
            self.pool = psycopg2.pool.SimpleConnectionPool(1, 5, dsn=self.dsn)
            logger.info("PostgreSQL connection pool initialized.")
        except psycopg2.Error as e:
            logger.error(f"Failed to initialize PostgreSQL pool: {e}")
            self.pool = None # Critical failure

    def connect(self) -> Any: # Returns a psycopg2 connection object
        if not self.pool:
            logger.warning("PostgreSQL pool not available. Attempting to re-initialize.")
            self._init_pool()
            if not self.pool:
                raise ConnectionError("PostgreSQL connection pool failed to initialize.")
        try:
            return self.pool.getconn()
        except Exception as e: # Catch pool errors like PoolError
            logger.error(f"Failed to get connection from PostgreSQL pool: {e}")
            raise ConnectionError(f"PostgreSQL pool error: {e}") from e


    def disconnect(self, conn: Optional[Any] = None) -> None:
        if conn and self.pool:
            self.pool.putconn(conn)
            # logger.debug("PostgreSQL connection returned to pool.")

    def _execute(self, query: str, params: Union[tuple, Dict[str, Any]] = (), commit: bool = False, fetch_one: bool = False, fetch_all: bool = False) -> Any:
        pg_conn = None
        try:
            pg_conn = self.connect()
            # Use DictCursor for easier row mapping
            with pg_conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(query, params)
                if commit: pg_conn.commit()
                if fetch_one: return cursor.fetchone()
                if fetch_all: return cursor.fetchall()
                return cursor.rowcount if query.strip().upper().startswith(("INSERT", "UPDATE", "DELETE")) else True
        except psycopg2.Error as e:
            if pg_conn: pg_conn.rollback() # Rollback on error
            logger.error(f"PostgreSQL error: {e} for query: {query[:100]}... with params: {str(params)[:100]}...")
            raise
        finally:
            if pg_conn: self.disconnect(pg_conn)

    def init_schema(self) -> None:
        logger.info("Initializing PostgreSQL schema...")
        for table_sql in self.TABLES_SQL.values(): self._execute(table_sql, commit=True)
        for index_sql in self.INDEXES_SQL.values(): self._execute(index_sql, commit=True)

        version_row = self._execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1", fetch_one=True)
        current_version = version_row['version'] if version_row else 0
        if current_version < self.DB_SCHEMA_VERSION:
            logger.info(f"PostgreSQL schema version {current_version}, migrating to {self.DB_SCHEMA_VERSION}...")
            # Add migration logic here for future versions
            self._execute("INSERT INTO schema_version (version, applied_at) VALUES (%s, %s) ON CONFLICT (version) DO NOTHING",
                          (self.DB_SCHEMA_VERSION, datetime.now()), commit=True)
        logger.info("PostgreSQL schema initialized/verified.")

    def register_batch_record(self, batch: BatchRecord) -> bool:
        db_data = batch.to_db_dict()
        # PostgreSQL uses BOOLEAN directly for 'completed'
        db_data['completed'] = batch.completed 
        # Timestamps are handled as ISO strings by psycopg2 for TIMESTAMPTZ
        
        query = """
            INSERT INTO redirects 
            (batch_id, destination_url, static_url, customer_name, customer_id, order_number, 
            payment_status, encrypted_password, quantity, start_uid, finish_uid, 
            created_at, updated_at, completed, tags_written, errors)
            VALUES (%(batch_id)s, %(destination_url)s, %(static_url)s, %(customer_name)s, %(customer_id)s, 
            %(order_number)s, %(payment_status)s, %(encrypted_password)s, %(quantity)s, 
            %(start_uid)s, %(finish_uid)s, %(created_at)s, %(updated_at)s, %(completed)s, 
            %(tags_written)s, %(errors)s)
            ON CONFLICT (batch_id) DO UPDATE SET
                destination_url = EXCLUDED.destination_url,
                static_url = EXCLUDED.static_url,
                customer_name = EXCLUDED.customer_name,
                customer_id = EXCLUDED.customer_id,
                order_number = EXCLUDED.order_number,
                payment_status = EXCLUDED.payment_status,
                encrypted_password = EXCLUDED.encrypted_password,
                quantity = EXCLUDED.quantity,
                start_uid = EXCLUDED.start_uid,
                finish_uid = EXCLUDED.finish_uid,
                updated_at = EXCLUDED.updated_at,
                completed = EXCLUDED.completed,
                tags_written = EXCLUDED.tags_written,
                errors = EXCLUDED.errors;
        """
        return bool(self._execute(query, db_data, commit=True))

    def get_batch_record(self, batch_id: str) -> Optional[BatchRecord]:
        row = self._execute("SELECT * FROM redirects WHERE batch_id = %s", (batch_id,), fetch_one=True)
        return BatchRecord.from_db_row(row) if row else None

    def update_batch_record(self, batch: BatchRecord) -> bool:
        # ON CONFLICT DO UPDATE handles this in register_batch_record
        return self.register_batch_record(batch)

    def delete_batch_record(self, batch_id: str) -> bool:
        return bool(self._execute("DELETE FROM redirects WHERE batch_id = %s", (batch_id,), commit=True))

    def list_batch_records(self, limit: int = 100, offset: int = 0) -> List[BatchRecord]:
        rows = self._execute("SELECT * FROM redirects ORDER BY created_at DESC LIMIT %s OFFSET %s", (limit, offset), fetch_all=True)
        return [BatchRecord.from_db_row(row) for row in rows if row]

    def get_redirect_destination(self, batch_id_or_uid: str) -> Optional[str]:
        query = "SELECT static_url, destination_url FROM redirects WHERE batch_id ILIKE %s" # Case-insensitive for PG
        row = self._execute(query, (batch_id_or_uid,), fetch_one=True)
        return row['static_url'] if row and row['static_url'] else (row['destination_url'] if row else None)

    def add_tag_event(self, batch_id: str, uid: str, success: bool, timestamp: datetime, error_message: Optional[str]) -> bool:
        query = """
            INSERT INTO tags (batch_id, uid, success, written_at, error_message)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (uid, batch_id) DO UPDATE SET 
                success = EXCLUDED.success, 
                written_at = EXCLUDED.written_at, 
                error_message = EXCLUDED.error_message;
        """
        return bool(self._execute(query, (batch_id, uid, success, timestamp, error_message), commit=True))

    def get_tags_for_batch(self, batch_id: str) -> List[Dict[str, Any]]:
        rows = self._execute("SELECT uid, success, written_at, error_message FROM tags WHERE batch_id = %s", (batch_id,), fetch_all=True)
        return [dict(row) for row in rows]
    
    def get_statistics(self) -> Dict[str, Any]:
        total_batches_row = self._execute("SELECT COUNT(*) as count FROM redirects", fetch_one=True)
        total_tags_events_row = self._execute("SELECT COUNT(*) as count FROM tags", fetch_one=True)
        return {
            "total_batches": total_batches_row['count'] if total_batches_row else 0,
            "total_tags_events": total_tags_events_row['count'] if total_tags_events_row else 0
        }

# --- Main Database Service ---
class DatabaseService:
    """
    Main database service for the application.
    Manages local (SQLite) and optional remote (PostgreSQL) database interactions.
    """
    def __init__(self):
        self.local_db = SQLiteAdapter(config.LOCAL_DB_PATH)
        self.remote_db: Optional[PostgreSQLAdapter] = None

        if config.NEON_DATABASE_URL:
            try:
                self.remote_db = PostgreSQLAdapter(config.NEON_DATABASE_URL)
                logger.info("Remote PostgreSQL database adapter configured.")
            except Exception as e: # Catch specific errors if psycopg2 or pool init fails
                logger.error(f"Failed to initialize remote PostgreSQL adapter: {e}")
                self.remote_db = None # Ensure it's None if init fails
        else:
            logger.info("Remote PostgreSQL database NOT configured (NEON_DATABASE_URL not set).")

        # Initialize schemas after adapters are created
        try:
            self.local_db.init_schema()
        except Exception as e: # Catch specific errors like ConnectionError or sqlite3.Error
            logger.error(f"Failed to initialize local SQLite schema: {e}")
            # Decide if this is a fatal error for the application
        
        if self.remote_db:
            try:
                self.remote_db.init_schema()
            except Exception as e: # Catch specific errors
                logger.error(f"Failed to initialize remote PostgreSQL schema: {e}. Remote operations may fail.")
                # Application might continue with local DB only if remote init fails

    def _prepare_batch_for_storage(self, batch: BatchRecord):
        """Encrypts password if present and cipher is available."""
        if batch.password: # If a new cleartext password is provided
            if _cipher:
                encrypted = encrypt_data(batch.password)
                if encrypted:
                    batch.encrypted_password = encrypted
                    # Optionally clear batch.password after encryption for security
                    # batch.password = None 
                else:
                    logger.error(f"Failed to encrypt password for batch {batch.batch_id}. Storing without encryption (if schema allows) or failing.")
                    # Depending on policy, might raise error or proceed with unencrypted if allowed
            else:
                logger.warning(f"Cipher not available. Password for batch {batch.batch_id} will not be encrypted.")
                # If storing cleartext is an option, ensure DB schema for encrypted_password can handle it or use a different field.
                # For now, encrypted_password will remain None or its previous value.

    def register_batch(self, batch: BatchRecord) -> Tuple[bool, Optional[bool]]:
        self._prepare_batch_for_storage(batch)
        local_success = self.local_db.register_batch_record(batch)
        remote_success: Optional[bool] = None
        if self.remote_db:
            remote_success = self.remote_db.register_batch_record(batch)
        return local_success, remote_success

    def get_batch(self, batch_id: str, source: str = 'local') -> Optional[BatchRecord]:
        if source == 'remote' and self.remote_db:
            return self.remote_db.get_batch_record(batch_id)
        return self.local_db.get_batch_record(batch_id)

    def update_batch(self, batch: BatchRecord) -> Tuple[bool, Optional[bool]]:
        self._prepare_batch_for_storage(batch) # Re-encrypt if password changed
        local_success = self.local_db.update_batch_record(batch)
        remote_success: Optional[bool] = None
        if self.remote_db:
            remote_success = self.remote_db.update_batch_record(batch)
        return local_success, remote_success

    def delete_batch(self, batch_id: str) -> Tuple[bool, Optional[bool]]:
        local_success = self.local_db.delete_batch_record(batch_id)
        remote_success: Optional[bool] = None
        if self.remote_db:
            remote_success = self.remote_db.delete_batch_record(batch_id)
        return local_success, remote_success

    def list_batches(self, limit: int = 100, offset: int = 0, source: str = 'local') -> List[BatchRecord]:
        if source == 'remote' and self.remote_db:
            return self.remote_db.list_batch_records(limit, offset)
        return self.local_db.list_batch_records(limit, offset)

    def get_redirect_destination(self, batch_id_or_uid: str, preference: str = 'remote_first') -> Optional[str]:
        if preference == 'remote_first':
            if self.remote_db:
                dest = self.remote_db.get_redirect_destination(batch_id_or_uid)
                if dest: return dest
            return self.local_db.get_redirect_destination(batch_id_or_uid)
        elif preference == 'local_first':
            dest = self.local_db.get_redirect_destination(batch_id_or_uid)
            if dest: return dest
            if self.remote_db:
                return self.remote_db.get_redirect_destination(batch_id_or_uid)
        elif preference == 'remote' and self.remote_db:
            return self.remote_db.get_redirect_destination(batch_id_or_uid)
        # Default to local or if preference is 'local'
        return self.local_db.get_redirect_destination(batch_id_or_uid)

    def add_tag_event(self, batch_id: str, uid: str, success: bool, 
                      timestamp: Optional[datetime] = None, 
                      error_message: Optional[str] = None) -> Tuple[bool, Optional[bool]]:
        ts = timestamp or datetime.now()
        local_success = self.local_db.add_tag_event(batch_id, uid, success, ts, error_message)
        remote_success: Optional[bool] = None
        if self.remote_db:
            remote_success = self.remote_db.add_tag_event(batch_id, uid, success, ts, error_message)
        return local_success, remote_success

    def get_tags_for_batch(self, batch_id: str, source: str = 'local') -> List[Dict[str, Any]]:
        if source == 'remote' and self.remote_db:
            return self.remote_db.get_tags_for_batch(batch_id)
        return self.local_db.get_tags_for_batch(batch_id)

    def get_statistics(self, source: str = 'local') -> Dict[str, Any]:
        if source == 'remote' and self.remote_db:
            return self.remote_db.get_statistics()
        return self.local_db.get_statistics()

    def close_connections(self) -> None:
        """Closes all managed database connections."""
        self.local_db.disconnect()
        if self.remote_db and self.remote_db.pool:
            try:
                self.remote_db.pool.closeall() # Close all connections in the pool
                logger.info("PostgreSQL connection pool closed.")
            except Exception as e:
                logger.error(f"Error closing PostgreSQL connection pool: {e}")

# --- Example Usage (for testing this module directly) ---
if __name__ == '__main__':
    # Ensure environment variables like NEON_DATABASE_URL and ENCRYPTION_KEY are set for full testing.
    # Example:
    # export ENCRYPTION_KEY="your_fernet_key_base64_string" (must be 32 url-safe base64-encoded bytes)
    # export NEON_DATABASE_URL="postgres://user:pass@host:port/db?sslmode=require"
    
    logger.info("--- DatabaseService Test ---")
    
    # Create a dummy .env file for testing if it doesn't exist
    env_file = Path(config.CLIENT_DIR) / ".env.development"
    if not env_file.exists():
        with open(env_file, "w") as f:
            f.write("# Dummy .env.development for testing database_service.py\n")
            f.write("APP_ENV=development\n")
            f.write("LOG_LEVEL=DEBUG\n")
            # f.write("NEON_DATABASE_URL=your_test_neon_url_here_if_testing_remote\n")
            f.write("ENCRYPTION_KEY=Y0tTIk9zR1J5Z0NwcVdDZUFjX1JmNnN0S1NMelNqWlUzZzF0V2wzX0VIQT0=\n") # Example key
    
    # Re-initialize config to load .env if it was just created
    config = ConfigPlaceholder() 
    
    # Re-init cipher if key was just loaded
    if config.ENCRYPTION_KEY and not _cipher:
        try:
            from cryptography.fernet import Fernet
            _cipher = Fernet(config.ENCRYPTION_KEY.encode('utf-8'))
            logger.info("Test: Fernet cipher re-initialized.")
        except Exception as e:
             logger.error(f"Test: Failed to re-init cipher: {e}")


    db_service = DatabaseService()

    # Test BatchRecord creation and encryption
    test_pwd = "mysecretbatchpassword"
    batch1 = BatchRecord(destination_url="https://test.com/batch1", quantity=100, password=test_pwd)
    logger.info(f"Batch 1 (clear pwd): {batch1.password}, (encrypted): {batch1.encrypted_password}")
    
    db_service._prepare_batch_for_storage(batch1) # Manually call for this test
    logger.info(f"Batch 1 after prepare (clear pwd): {batch1.password}, (encrypted): {batch1.encrypted_password}")
    
    if batch1.encrypted_password:
        decrypted_pwd = decrypt_data(batch1.encrypted_password)
        logger.info(f"Decrypted password for batch1: {decrypted_pwd} (Original: {test_pwd})")
        assert decrypted_pwd == test_pwd, "Password encryption/decryption mismatch!"

    # Test registration
    l_success, r_success_opt = db_service.register_batch(batch1)
    r_success = r_success_opt if r_success_opt is not None else "N/A"
    logger.info(f"Register Batch 1 ({batch1.batch_id}): Local={l_success}, Remote={r_success}")

    # Test retrieval
    retrieved_b1_local = db_service.get_batch(batch1.batch_id, source='local')
    if retrieved_b1_local:
        logger.info(f"Retrieved B1 Local: ID={retrieved_b1_local.batch_id}, URL={retrieved_b1_local.destination_url}, Pwd={retrieved_b1_local.password}")
        assert retrieved_b1_local.password == test_pwd
    else:
        logger.error(f"Failed to retrieve B1 from local DB.")

    if db_service.remote_db:
        retrieved_b1_remote = db_service.get_batch(batch1.batch_id, source='remote')
        if retrieved_b1_remote:
            logger.info(f"Retrieved B1 Remote: ID={retrieved_b1_remote.batch_id}, URL={retrieved_b1_remote.destination_url}, Pwd={retrieved_b1_remote.password}")
            assert retrieved_b1_remote.password == test_pwd
        else:
            logger.error(f"Failed to retrieve B1 from remote DB.")

    # Test tag event
    db_service.add_tag_event(batch1.batch_id, "UID001", True, datetime.now())
    db_service.add_tag_event(batch1.batch_id, "UID002", False, datetime.now(), "Failed to write NDEF")
    
    tags_b1_local = db_service.get_tags_for_batch(batch1.batch_id, source='local')
    logger.info(f"Tags for B1 Local: {tags_b1_local}")

    # Test listing
    all_local_batches = db_service.list_batches(source='local')
    logger.info(f"All Local Batches ({len(all_local_batches)}): {[b.batch_id for b in all_local_batches]}")

    # Test stats
    local_stats = db_service.get_statistics(source='local')
    logger.info(f"Local Stats: {local_stats}")
    if db_service.remote_db:
        remote_stats = db_service.get_statistics(source='remote')
        logger.info(f"Remote Stats: {remote_stats}")

    # Test redirect lookup
    redirect_url = db_service.get_redirect_destination(batch1.batch_id, preference='local_first')
    logger.info(f"Redirect URL for {batch1.batch_id}: {redirect_url}")
    assert redirect_url == batch1.destination_url

    db_service.close_connections()
    logger.info("--- DatabaseService Test Finished ---")
