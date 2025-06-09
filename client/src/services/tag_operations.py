"""
NFC Tag Operations Service for Arc-TAP NFC Utility Client.

This service provides a high-level API for interacting with NFC tags,
managing reader connections, and performing various tag operations.
It abstracts the complexities of direct smartcard communication.
"""

import logging
import time
import threading
from enum import Enum, auto
from typing import List, Dict, Optional, Tuple, Union, Any, Callable
from abc import ABC, abstractmethod

# Assuming NFCTag model and Config are available
from ..models.nfc_tag import NFCTag, TagType # Actual import from models
from ..utils.config import config # Use the global config instance from utils

# --- Reader Handler Components ---
# These components handle direct communication with NFC readers.

class ReaderType(Enum):
    """Enumeration of supported NFC reader types."""
    UNKNOWN = auto()
    PCSC_GENERIC = auto() # For any PCSC compliant reader
    # Specific models can be added if they require special handling beyond standard PCSC
    # e.g., ACS_ACR122U, ACS_ACR1252U

class ReaderHandlerError(Exception):
    """Base exception for reader handler errors."""
    pass

class ReaderConnectionError(ReaderHandlerError):
    """Error during reader connection."""
    pass

class ReaderCommandError(ReaderHandlerError):
    """Error executing a command on the reader."""
    pass

class ReaderAuthenticationError(ReaderHandlerError):
    """Error during tag authentication with the reader."""
    pass


class ReaderHandler(ABC): # Abstract Base Class
    """
    Abstract base class for NFC Reader Handlers.
    Defines the interface for interacting with different NFC readers.
    """
    def __init__(self, reader_name: str):
        self.reader_name = reader_name
        self.logger = logging.getLogger(f"{self.__class__.__name__}[{reader_name}]")
        self._is_connected = False

    @abstractmethod
    def connect(self) -> bool:
        """Connects to the physical reader. Returns True on success."""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Disconnects from the physical reader."""
        pass

    @property
    def is_connected(self) -> bool:
        """Returns True if the reader is connected."""
        return self._is_connected

    @abstractmethod
    def get_atr(self) -> Optional[List[int]]:
        """Gets the ATR (Answer To Reset) of the current card. Returns None if no card or error."""
        pass
    
    @abstractmethod
    def get_uid(self) -> Optional[List[int]]:
        """Gets the UID of the current card. Returns None if no card or error."""
        pass

    @abstractmethod
    def transmit(self, command: List[int], timeout_ms: Optional[int] = None) -> Tuple[Optional[List[int]], Optional[List[int]]]:
        """
        Transmits an APDU command to the card.
        Returns (response_data, status_word_sw1_sw2) or (None, None) on error.
        timeout_ms is an optional timeout for the transmit operation.
        """
        pass

    # --- Tag Type Specific Operations (NTAG/Type 2 focus) ---
    def ntag_read_page(self, page_number: int) -> Optional[List[int]]:
        """Reads a 4-byte page from an NTAG or compatible Type 2 tag."""
        # APDU for NTAG Read: FF B0 00 <Page Number (1 byte)> <Length (1 byte, usually 04 for one page)>
        command = [0xFF, 0xB0, 0x00, page_number & 0xFF, 0x04]
        data, sw = self.transmit(command)
        if data and sw == [0x90, 0x00]:
            return data
        elif sw == [0x6A, 0x82]: # Page not found / Address out of range
            self.logger.warning(f"NTAG Read page {page_number}: Address out of range (6A 82).")
        elif sw == [0x69, 0x82]: # Security status not satisfied
            self.logger.warning(f"NTAG Read page {page_number}: Security status not satisfied (69 82).")
            raise ReaderAuthenticationError(f"Authentication required to read page {page_number}.")
        else:
            self.logger.warning(f"NTAG Read page {page_number} failed. SW: {sw[0]:02X}{sw[1]:02X if sw and len(sw)>1 else ''}")
        return None

    def ntag_write_page(self, page_number: int, data_to_write: List[int]) -> bool:
        """Writes 4 bytes of data to a page on an NTAG or compatible Type 2 tag."""
        if len(data_to_write) != 4:
            self.logger.error("NTAG write_page data must be exactly 4 bytes.")
            return False
        # APDU for NTAG Write: FF D6 00 <Page Number (1 byte)> <Length (1 byte, 04)> <Data (4 bytes)>
        command = [0xFF, 0xD6, 0x00, page_number & 0xFF, 0x04] + data_to_write
        _, sw = self.transmit(command)
        if sw == [0x90, 0x00]:
            return True
        elif sw == [0x69, 0x82]: # Security status not satisfied
            self.logger.warning(f"NTAG Write page {page_number}: Security status not satisfied (69 82).")
            raise ReaderAuthenticationError(f"Authentication required to write page {page_number}.")
        else:
            self.logger.warning(f"NTAG Write page {page_number} failed. SW: {sw[0]:02X}{sw[1]:02X if sw and len(sw)>1 else ''}")
        return False

    def ntag_pwd_auth(self, password_bytes: List[int]) -> bool:
        """Authenticates an NTAG with a 4-byte password."""
        if len(password_bytes) != 4:
            self.logger.error("NTAG password must be 4 bytes for PWD_AUTH.")
            return False
        
        # NTAG PWD_AUTH command is 0x1B followed by 4 password bytes.
        # This needs to be wrapped in a reader-specific APDU if the reader doesn't handle it directly.
        # A common pseudo-APDU for some readers (like ACR122U for direct NTAG commands):
        # FF 00 00 00 Lc <NTAG_Command_Byte> <NTAG_Params...>
        # So, for PWD_AUTH: FF 00 00 00 05 1B PWD0 PWD1 PWD2 PWD3
        # This is an example; actual APDU might vary based on reader firmware.
        # For a generic PCSC handler, we assume the reader transparently passes NTAG commands
        # or has a specific APDU for this.
        # Let's use a common direct APDU for PWD_AUTH (0x1B) for NTAG.
        command = [0x1B] + password_bytes # This is the NTAG command itself
        # How to send this? It depends on the reader.
        # For now, this method is more of an interface declaration.
        # A PCSC handler might try to wrap this, e.g., using a "Direct Transmit" APDU if supported by the reader.
        # Or, if the reader exposes NTAG commands directly via specific APDUs:
        # Example: apdu_for_ntag_auth = [0xFF, 0xD4, 0x40, 0x01, 0x05, 0x1B] + password_bytes # For some ACS readers
        # For now, let's assume a simple transmit of the PWD_AUTH command.
        # This part is highly reader-dependent if not using a high-level SDK for the reader.
        
        # Placeholder for a common PCSC direct transmit attempt for PWD_AUTH
        # This APDU structure is just an example and might not work with all readers.
        # It assumes the reader is in a mode to accept raw tag commands.
        # Data field = [NTAG_CMD_BYTE, PWD0, PWD1, PWD2, PWD3]
        ntag_command_payload = [0x1B] + password_bytes 
        apdu = [0xFF, 0x00, 0x00, 0x00, len(ntag_command_payload)] + ntag_command_payload
        
        data, sw = self.transmit(apdu)
        if sw == [0x90, 0x00]:
            # NTAG PWD_AUTH returns PACK (Password Acknowledge, 2 bytes) on success.
            if data and len(data) >= 2: # Check if PACK is returned
                self.logger.info(f"NTAG PWD_AUTH successful. PACK: {''.join(f'{b:02X}' for b in data[:2])}")
                return True
            else: # Success SW but no/invalid PACK
                self.logger.warning("NTAG PWD_AUTH successful (SW 9000) but PACK not as expected.")
                return True # Still consider auth success based on SW
        else:
            self.logger.warning(f"NTAG PWD_AUTH failed. SW: {sw[0]:02X}{sw[1]:02X if sw and len(sw)>1 else ''}")
            return False

class PCSCReaderHandler(ReaderHandler):
    """PCSC-based Reader Handler using the `pyscard` library."""
    def __init__(self, reader_name: str):
        super().__init__(reader_name)
        self.connection = None
        self.pcsc_reader_obj = None
        try:
            from smartcard.System import readers as pcsc_readers
            from smartcard.CardConnection import CardConnection as PCSCConnection
            from smartcard.Exceptions import CardConnectionException, NoCardException
            self.PCSCConnection = PCSCConnection
            self.CardConnectionException = CardConnectionException
            self.NoCardException = NoCardException
            
            available_pcsc_readers = pcsc_readers()
            for r in available_pcsc_readers:
                if str(r) == reader_name:
                    self.pcsc_reader_obj = r
                    break
            if not self.pcsc_reader_obj:
                raise ReaderHandlerError(f"PCSC Reader '{reader_name}' not found in system list: {available_pcsc_readers}")
        except ImportError:
            self.logger.critical("pyscard library not found. PCSCReaderHandler cannot function.")
            raise ReaderHandlerError("pyscard library not installed. Please run: pip install pyscard")
        except Exception as e:
            self.logger.critical(f"Error initializing PCSC system or finding reader '{reader_name}': {e}")
            raise ReaderHandlerError(f"PCSC system error: {e}")

    def connect(self) -> bool:
        if not self.pcsc_reader_obj:
            self.logger.error("No PCSC reader object available to connect.")
            return False
        try:
            self.connection = self.pcsc_reader_obj.createConnection()
            # Connect using shared mode and try both T=0 and T=1 protocols
            self.connection.connect(self.PCSCConnection.SHARE_SHARED, 
                                    self.PCSCConnection.PROTOCOL_T0 | self.PCSCConnection.PROTOCOL_T1)
            self._is_connected = True
            self.logger.info(f"Connected to PCSC reader: {self.reader_name} using protocol {self.connection.getProtocol()}")
            return True
        except self.NoCardException:
            self.logger.warning(f"Cannot connect to PCSC reader '{self.reader_name}': No card present.")
            # For some operations, connecting without a card is fine.
            # However, for tag operations, a card is needed.
            # Let's consider connection successful but note no card.
            # self._is_connected = True # Reader itself is connected
            # return True 
            # Or, treat "no card" as a connection failure for tag operations context:
            self.connection = None
            self._is_connected = False
            return False # No card, so can't really operate on a tag
        except Exception as e:
            self.logger.error(f"Failed to connect to PCSC reader '{self.reader_name}': {e}")
            self.connection = None
            self._is_connected = False
            return False

    def disconnect(self) -> None:
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception as e:
                self.logger.error(f"Error disconnecting from PCSC reader '{self.reader_name}': {e}")
            finally:
                self.connection = None
                self._is_connected = False
                self.logger.info(f"Disconnected from PCSC reader: {self.reader_name}")
    
    def get_atr(self) -> Optional[List[int]]:
        if not self.is_connected or not self.connection: return None
        try:
            return self.connection.getATR()
        except self.NoCardException:
            self.logger.debug("get_atr: No card present.")
            return None
        except self.CardConnectionException as e: # Catch card removal during operation
            self.logger.warning(f"get_atr: Card connection error (likely removed): {e}")
            self._is_connected = False # Assume connection is lost or card is gone
            return None
        except Exception as e:
            self.logger.error(f"Error getting ATR: {e}")
            return None

    def get_uid(self) -> Optional[List[int]]:
        GET_UID_APDU = [0xFF, 0xCA, 0x00, 0x00, 0x00] 
        data, sw = self.transmit(GET_UID_APDU)
        if data and sw == [0x90, 0x00]:
            return data
        self.logger.warning(f"Failed to get UID. SW: {sw[0]:02X}{sw[1]:02X if sw and len(sw)>1 else '' if sw else 'N/A'}")
        return None
        
    def transmit(self, command: List[int], timeout_ms: Optional[int] = None) -> Tuple[Optional[List[int]], Optional[List[int]]]:
        if not self.is_connected or not self.connection:
            self.logger.error("Cannot transmit, PCSC reader not connected.")
            return None, None
        try:
            hex_command = ' '.join(f'{b:02X}' for b in command)
            self.logger.debug(f"PCSC Tx: {hex_command}")
            
            # pyscard's transmit timeout is not straightforward.
            # It's often handled at the PCSC service level or driver level.
            # For now, we don't explicitly use timeout_ms with pyscard's transmit.
            data, sw1, sw2 = self.connection.transmit(command)
            status_word = [sw1, sw2]
            
            hex_data = ' '.join(f'{b:02X}' for b in data) if data else ""
            self.logger.debug(f"PCSC Rx: {hex_data} SW: {sw1:02X}{sw2:02X}")
            return data, status_word
        except self.NoCardException:
            self.logger.warning("PCSC transmit error: No card present.")
            self._is_connected = False # Or just current card gone
            return None, [0x6A, 0x82] # Simulate "File not found" or similar for no card
        except self.CardConnectionException as e:
            self.logger.error(f"PCSC card connection exception during transmit: {e}")
            self._is_connected = False # Connection is likely broken
            return None, None # Indicate total failure
        except Exception as e:
            self.logger.error(f"PCSC transmit error: {e}")
            return None, None


class ReaderFactory:
    """Factory for creating ReaderHandler instances."""
    @staticmethod
    def get_available_reader_names() -> List[str]:
        """Returns a list of names of all available PCSC readers."""
        try:
            from smartcard.System import readers as pcsc_readers
            return [str(r) for r in pcsc_readers()]
        except ImportError:
            logger.error("pyscard library not found. Cannot list PCSC readers.")
            return []
        except Exception as e:
            logger.error(f"Error listing PCSC readers (PC/SC service running?): {e}")
            return []

    @staticmethod
    def create_handler(reader_name: Optional[str] = None) -> Optional[ReaderHandler]:
        available_readers = ReaderFactory.get_available_reader_names()
        if not available_readers:
            logger.error("No PCSC readers found to create a handler.")
            return None

        selected_reader_name = reader_name
        if not selected_reader_name:
            selected_reader_name = available_readers[0]
            logger.info(f"No reader name specified, using first available: {selected_reader_name}")
        elif selected_reader_name not in available_readers:
            logger.error(f"Specified reader '{selected_reader_name}' not found. Available: {available_readers}")
            return None
        
        try:
            # Currently, only PCSCReaderHandler is implemented.
            # Can add logic here to choose different handlers based on reader_name if needed.
            return PCSCReaderHandler(selected_reader_name)
        except ReaderHandlerError as e: # Catch errors from PCSCReaderHandler constructor
            logger.error(f"Failed to create PCSC handler for '{selected_reader_name}': {e}")
            return None

# --- Tag Operation Service Exceptions ---
class TagOperationError(Exception): pass
class TagNotPresentError(TagOperationError): pass
class TagWriteError(TagOperationError): pass
class TagReadError(TagOperationError): pass
class TagAuthenticationError(TagOperationError): pass # Re-defined here for service level
class TagFormatError(TagOperationError): pass
class TagLockError(TagOperationError): pass

# --- Callback Types ---
TagCallback = Callable[[Optional[NFCTag]], None]
ErrorCallback = Callable[[str], None]

class TagOperationsService:
    """Service for high-level NFC tag operations."""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.reader_handler: Optional[ReaderHandler] = None
        self.current_tag: Optional[NFCTag] = None
        self._polling_active: bool = False
        self._polling_thread: Optional[threading.Thread] = None
        self._polling_interval_sec: float = config.get("NFC_POLLING_INTERVAL_S", 0.75)
        self.on_tag_detected: Optional[TagCallback] = None
        self.on_tag_removed: Optional[TagCallback] = None
        self.on_operation_error: Optional[ErrorCallback] = None
        self._last_detected_uid_hex: Optional[str] = None

    def _handle_error(self, error_message: str, error_exception: Optional[Exception] = None):
        full_message = error_message
        if error_exception:
            full_message += f" (Details: {error_exception})"
        self.logger.error(full_message)
        if self.on_operation_error:
            try:
                self.on_operation_error(error_message) # Pass simpler message to UI
            except Exception as cb_err:
                self.logger.error(f"Error in on_operation_error callback: {cb_err}")
    
    def _ensure_reader_and_tag(self, operation_name: str, require_tag: bool = True) -> Optional[NFCTag]:
        """Checks reader connection and optionally current tag presence."""
        if not self.reader_handler or not self.reader_handler.is_connected:
            msg = f"{operation_name} failed: Reader not connected."
            raise TagOperationError(msg) # Raise, don't just log/callback
        if require_tag:
            if not self.current_tag or not self._last_detected_uid_hex:
                msg = f"{operation_name} failed: No tag present or tag lost."
                raise TagNotPresentError(msg)
            return self.current_tag
        return None # If require_tag is False

    def get_available_readers(self) -> List[str]:
        return ReaderFactory.get_available_reader_names()

    def select_reader(self, reader_name: Optional[str] = None) -> bool:
        if self.reader_handler and self.reader_handler.is_connected:
            self.disconnect_reader() # Disconnect previous before selecting new
        
        new_handler = ReaderFactory.create_handler(reader_name)
        if new_handler:
            self.reader_handler = new_handler
            self.logger.info(f"Reader selected: {self.reader_handler.reader_name}")
            return True
        else:
            self.reader_handler = None
            self._handle_error(f"Failed to select reader: {reader_name or 'default'}")
            return False

    def connect_reader(self) -> bool:
        if not self.reader_handler:
            self._handle_error("Cannot connect: No reader selected.")
            return False
        if self.reader_handler.is_connected: return True
        
        try:
            if self.reader_handler.connect():
                return True
            else: # connect() returned False, specific error should have been logged by handler
                self._handle_error(f"Failed to connect to reader: {self.reader_handler.reader_name}")
                return False
        except ReaderConnectionError as e: # Catch specific connection errors
            self._handle_error(str(e), e)
            return False

    def disconnect_reader(self) -> None:
        if self.reader_handler: self.reader_handler.disconnect()
        self.current_tag = None
        self._last_detected_uid_hex = None

    def start_polling(self, interval_sec: Optional[float] = None):
        if interval_sec is not None: self._polling_interval_sec = interval_sec
        
        if not self.reader_handler or not self.reader_handler.is_connected:
            self.logger.warning("Attempting to connect reader before starting polling...")
            if not self.connect_reader():
                 self._handle_error("Polling not started: Reader connection failed.")
                 return

        if self._polling_active: return
        self._polling_active = True
        self._polling_thread = threading.Thread(target=self._polling_loop, daemon=True)
        self._polling_thread.start()
        self.logger.info(f"Tag polling started (interval: {self._polling_interval_sec}s).")

    def stop_polling(self):
        if not self._polling_active: return
        self._polling_active = False
        if self._polling_thread and self._polling_thread.is_alive():
            self._polling_thread.join(timeout=self._polling_interval_sec * 2.5) # Increased timeout
            if self._polling_thread.is_alive():
                 self.logger.warning("Polling thread did not terminate in time.")
        self._polling_thread = None
        self.logger.info("Tag polling stopped.")

    def _polling_loop(self):
        while self._polling_active:
            if not self.reader_handler or not self.reader_handler.is_connected:
                self.logger.warning("Polling: Reader not connected. Attempting reconnect...")
                if not self.connect_reader():
                    self.logger.error("Polling: Reconnect failed. Stopping polling.")
                    self._polling_active = False
                    self._handle_error("Reader connection lost during polling.")
                    break 
                else: self.logger.info("Polling: Reconnected.")

            current_uid_bytes, current_atr_bytes = None, None
            try:
                # Prioritize ATR, then UID. Some readers/cards might give ATR even if UID fails initially.
                current_atr_bytes = self.reader_handler.get_atr()
                if current_atr_bytes:
                    current_uid_bytes = self.reader_handler.get_uid() 
                    if not current_uid_bytes: # If UID fails after ATR, still treat as card presence
                        self.logger.warning("Polling: Got ATR but failed to get UID. Assuming card present.")
                # If no ATR, UID is unlikely, but try anyway for robustness
                elif not current_atr_bytes and self.reader_handler: # Added check for self.reader_handler
                     current_uid_bytes = self.reader_handler.get_uid()

            except Exception as e:
                self.logger.error(f"Polling: Error during ATR/UID check: {e}")
                if self._last_detected_uid_hex: # If a tag was previously detected
                    self.logger.info(f"Polling: Assuming tag {self._last_detected_uid_hex} removed due to error.")
                    removed_tag_obj = self.current_tag
                    self.current_tag = None
                    self._last_detected_uid_hex = None
                    if self.on_tag_removed: self.on_tag_removed(removed_tag_obj)
                time.sleep(self._polling_interval_sec)
                continue

            current_uid_hex = ''.join(f'{b:02X}' for b in current_uid_bytes) if current_uid_bytes else None

            if current_uid_hex and current_uid_hex != self._last_detected_uid_hex:
                self.logger.info(f"Polling: New tag detected or re-detected: UID {current_uid_hex}")
                try:
                    # Create NFCTag. Read full memory if needed by application logic upon detection.
                    # For now, create with basic info. UI can trigger full read.
                    tag_obj = NFCTag(uid=current_uid_bytes, atr=current_atr_bytes)
                    self.current_tag = tag_obj # Update service's current tag
                    self._last_detected_uid_hex = current_uid_hex
                    if self.on_tag_detected: self.on_tag_detected(tag_obj)
                except Exception as e:
                    self._handle_error(f"Error processing new tag {current_uid_hex}", e)
            
            elif not current_uid_hex and self._last_detected_uid_hex:
                self.logger.info(f"Polling: Tag removed: UID {self._last_detected_uid_hex}")
                removed_tag_obj = self.current_tag
                self.current_tag = None
                self._last_detected_uid_hex = None
                if self.on_tag_removed: self.on_tag_removed(removed_tag_obj)
            
            time.sleep(self._polling_interval_sec)
        self.logger.debug("Polling loop ended.")

    def read_tag_info(self, read_full_memory: bool = False) -> Optional[NFCTag]:
        """Reads current tag's basic info. If read_full_memory, gets memory dump."""
        self._ensure_reader_and_tag("Read Tag Info", require_tag=False) # Reader must be connected, tag not strictly required yet

        if not self.reader_handler: return None # Should be caught by ensure_reader

        uid_bytes = self.reader_handler.get_uid()
        atr_bytes = self.reader_handler.get_atr()

        if not uid_bytes or not atr_bytes:
            if self._last_detected_uid_hex: # Tag was there, now gone
                self.logger.info(f"Read Tag Info: Tag {self._last_detected_uid_hex} removed.")
                removed_tag_obj = self.current_tag
                self.current_tag = None; self._last_detected_uid_hex = None
                if self.on_tag_removed: self.on_tag_removed(removed_tag_obj)
            return None

        try:
            tag = NFCTag(uid=uid_bytes, atr=atr_bytes) # Basic object
            
            if read_full_memory:
                memory_dump = self._read_full_tag_memory_internal(tag)
                if memory_dump: tag.set_memory_dump(memory_dump)
                else: self.logger.warning(f"Could not read full memory for {tag.uid_hex}")

            self.current_tag = tag # Update service's current tag
            self._last_detected_uid_hex = tag.uid_hex
            self.logger.info(f"Tag info read: {tag}")
            return tag
        except Exception as e:
            self._handle_error(f"Error processing tag data for UID {uid_bytes.hex() if uid_bytes else 'N/A'}", e)
            self.current_tag = None
            return None

    def _read_full_tag_memory_internal(self, tag_model: NFCTag) -> Optional[Dict[int, List[int]]]:
        """Internal: Reads all relevant pages of a tag based on its type config."""
        if not self.reader_handler: return None # Should be caught by _ensure_reader_and_tag

        dump: Dict[int, List[int]] = {}
        cfg = tag_model.config
        # Determine pages to read: from page 0 up to end of user memory or config area.
        # Max pages to attempt reading could be cfg.get('total_pages').
        # Be cautious with reading beyond user memory unless specific config pages are needed.
        # For NDEF and basic info, reading up to user_memory_end_page + few config pages is usually enough.
        
        # Let's try reading all pages defined in its config (if total_pages is reasonable)
        # or a fixed number for unknown types.
        max_page_to_read = cfg.get('total_pages', 16) if tag_model.tag_type != TagType.UNKNOWN else 16
        if max_page_to_read == 0 and tag_model.tag_type != TagType.UNKNOWN: max_page_to_read = 16 # Fallback
        
        self.logger.debug(f"Reading memory for {tag_model.type_name} (UID: {tag_model.uid_hex}), up to {max_page_to_read} pages.")

        for page_num in range(max_page_to_read):
            try:
                page_data = self.reader_handler.ntag_read_page(page_num) # Assumes NTAG-like read
                if page_data:
                    dump[page_num] = page_data
                else: # Read failed for this page
                    self.logger.warning(f"Failed to read page {page_num} for tag {tag_model.uid_hex}. Memory dump may be incomplete.")
                    # Depending on tag type, might be normal (e.g. past end of memory, or protected page)
                    # For now, if a page read fails, we stop reading further pages for this dump.
                    break 
            except ReaderAuthenticationError:
                self.logger.warning(f"Page {page_num} requires authentication. Stopping memory read for {tag_model.uid_hex}.")
                break 
            except ReaderCommandError as rce:
                self.logger.warning(f"Command error reading page {page_num} for {tag_model.uid_hex}: {rce}. Stopping.")
                break
            except Exception as e: # Catch any other unexpected error from reader_handler
                self.logger.error(f"Unexpected error reading page {page_num} for {tag_model.uid_hex}: {e}", exc_info=True)
                break 
        return dump if dump else None

    def write_url_to_tag(self, url: str, 
                         new_password: Optional[str] = None, 
                         existing_password_for_auth: Optional[str] = None) -> bool:
        tag = self._ensure_reader_and_tag("Write URL")
        if not tag or not self.reader_handler : return False # Should be caught by ensure_reader_and_tag

        try:
            if existing_password_for_auth:
                if not self.authenticate_tag(existing_password_for_auth, tag_to_auth=tag):
                    raise TagAuthenticationError(f"Initial authentication failed for {tag.uid_hex}.")
            elif tag.is_password_protected: # From previous read
                raise TagAuthenticationError(f"Tag {tag.uid_hex} is password protected. Existing password required.")

            ndef_msg_bytes = tag.create_ndef_message_with_url(url)
            tlv_data = tag.get_ndef_tlv_bytes(ndef_msg_bytes)

            if len(tlv_data) > tag.max_ndef_bytes:
                 raise TagWriteError(f"NDEF data ({len(tlv_data)} bytes) exceeds tag capacity ({tag.max_ndef_bytes} bytes).")

            user_start, _ = tag.user_memory_pages_range
            num_pages = (len(tlv_data) + NFCTag.PAGE_SIZE_BYTES - 1) // NFCTag.PAGE_SIZE_BYTES

            for i in range(num_pages):
                page_num = user_start + i
                page_chunk = list(tlv_data[i*NFCTag.PAGE_SIZE_BYTES : (i+1)*NFCTag.PAGE_SIZE_BYTES])
                # Ensure chunk is exactly PAGE_SIZE_BYTES, pad with 0x00 if needed (should be handled by get_ndef_tlv_bytes)
                while len(page_chunk) < NFCTag.PAGE_SIZE_BYTES: page_chunk.append(0x00)
                
                if not self.reader_handler.ntag_write_page(page_num, page_chunk):
                    raise TagWriteError(f"Failed to write page {page_num} for tag {tag.uid_hex}.")
                self.logger.debug(f"Wrote page {page_num} for tag {tag.uid_hex}.")
                time.sleep(0.02) # Small delay often helps with tag writes

            self.logger.info(f"URL '{url}' written to tag {tag.uid_hex}.")

            if new_password:
                if not self.set_password(new_password, tag_to_protect=tag, 
                                         # If we authed with existing_password, we are still in "authed state" for some tags
                                         # But NTAG password set might not need prior auth if pages are open.
                                         # Let's assume set_password handles its own auth needs if existing_password_for_auth is not for *this* operation.
                                         already_authed_for_config_write=bool(existing_password_for_auth)):
                    self.logger.error(f"URL written, but failed to set new password on {tag.uid_hex}.")
                    # Decide if this constitutes overall failure. For now, URL write is main goal.
                else: self.logger.info(f"New password set on {tag.uid_hex} after URL write.")
            
            self.read_tag_info(read_full_memory=True) # Refresh current_tag state
            return True
        except (TagOperationError, ValueError, ndef.EncodeError, ReaderHandlerError) as e:
            self._handle_error(f"Error writing URL to tag {tag.uid_hex if tag else 'N/A'}: {str(e)}", e)
            return False
        except Exception as e:
            self._handle_error(f"Unexpected error writing URL to {tag.uid_hex if tag else 'N/A'}", e)
            return False

    def format_tag(self, existing_password_for_auth: Optional[str] = None) -> bool:
        tag = self._ensure_reader_and_tag("Format Tag")
        if not tag or not self.reader_handler: return False

        if tag.is_locked: # From previous read
            self._handle_error(f"Tag {tag.uid_hex} is locked. Cannot format.")
            return False
        try:
            if existing_password_for_auth:
                if not self.authenticate_tag(existing_password_for_auth, tag_to_auth=tag):
                    raise TagAuthenticationError(f"Authentication failed for {tag.uid_hex}. Cannot format.")
            elif tag.is_password_protected: # From previous read
                 raise TagAuthenticationError(f"Tag {tag.uid_hex} is password protected. Provide password to format.")

            empty_ndef_tlv = tag.get_ndef_tlv_bytes(b'') # TLV for empty NDEF message
            user_start, user_end = tag.user_memory_pages_range
            
            if len(empty_ndef_tlv) > (user_end - user_start + 1) * NFCTag.PAGE_SIZE_BYTES:
                raise TagFormatError("Tag user memory too small for even an empty NDEF TLV.")

            num_pages = (len(empty_ndef_tlv) + NFCTag.PAGE_SIZE_BYTES - 1) // NFCTag.PAGE_SIZE_BYTES
            for i in range(num_pages):
                page_num = user_start + i
                page_chunk = list(empty_ndef_tlv[i*NFCTag.PAGE_SIZE_BYTES : (i+1)*NFCTag.PAGE_SIZE_BYTES])
                while len(page_chunk) < NFCTag.PAGE_SIZE_BYTES: page_chunk.append(0x00)
                if not self.reader_handler.ntag_write_page(page_num, page_chunk):
                    raise TagFormatError(f"Failed to write page {page_num} during format for {tag.uid_hex}.")
                time.sleep(0.02)
            
            # Optionally, clear more pages if needed, but writing empty NDEF is usually enough.
            self.logger.info(f"Tag {tag.uid_hex} formatted (NDEF area cleared).")
            self.read_tag_info(read_full_memory=True)
            return True
        except (TagOperationError, ReaderHandlerError) as e:
            self._handle_error(f"Error formatting tag {tag.uid_hex}: {str(e)}", e)
            return False
        except Exception as e:
            self._handle_error(f"Unexpected error formatting {tag.uid_hex}", e)
            return False

    def authenticate_tag(self, password_hex: str, tag_to_auth: Optional[NFCTag] = None) -> bool:
        """Authenticates tag with a 4-byte password provided as an 8-char hex string."""
        tag = tag_to_auth or self._ensure_reader_and_tag("Authenticate Tag")
        if not tag or not self.reader_handler: return False

        if not tag.supports_password:
            self._handle_error(f"Tag type {tag.type_name} does not support password auth.")
            return False
        if not (len(password_hex) == 8 and all(c in "0123456789abcdefABCDEF" for c in password_hex)):
            self._handle_error("Invalid password format. Expected 8 hex characters (4 bytes).")
            return False
        
        password_bytes = list(bytes.fromhex(password_hex))
        try:
            if self.reader_handler.ntag_pwd_auth(password_bytes): # Assumes NTAG-like auth
                self.logger.info(f"Tag {tag.uid_hex} authenticated successfully.")
                return True
            else: # Auth failed (e.g. wrong password)
                self._handle_error(f"Authentication failed for tag {tag.uid_hex} (incorrect password or tag error).")
                return False
        except ReaderAuthenticationError as e: # Catch specific auth errors from handler
            self._handle_error(f"Authentication error for tag {tag.uid_hex}: {str(e)}", e)
            return False
        except Exception as e: # Catch other handler errors
            self._handle_error(f"Unexpected error during auth for {tag.uid_hex}", e)
            return False

    def set_password(self, new_password_hex: str, 
                     existing_password_for_auth: Optional[str] = None, 
                     tag_to_protect: Optional[NFCTag] = None,
                     already_authed_for_config_write: bool = False) -> bool:
        tag = tag_to_protect or self._ensure_reader_and_tag("Set Password")
        if not tag or not self.reader_handler: return False

        if not tag.supports_password:
            self._handle_error(f"Tag type {tag.type_name} does not support password setting.")
            return False
        if not (len(new_password_hex) == 8 and all(c in "0123456789abcdefABCDEF" for c in new_password_hex)):
            self._handle_error("Invalid new password format. Expected 8 hex characters (4 bytes).")
            return False
        
        new_pwd_bytes = list(bytes.fromhex(new_password_hex))
        
        try:
            if not already_authed_for_config_write:
                if existing_password_for_auth: # If old password is known
                    if not self.authenticate_tag(existing_password_for_auth, tag_to_auth=tag):
                        raise TagAuthenticationError(f"Authentication with existing password failed for {tag.uid_hex}.")
                elif tag.is_password_protected: # If protected but no old password given
                    raise TagAuthenticationError(f"Tag {tag.uid_hex} is password protected. Existing password required to change it.")

            # Actual password setting logic (highly NTAG specific for this example)
            cfg = tag.config
            pwd_page = cfg.get('pwd_page')
            pack_page = cfg.get('pack_page')
            auth0_page = cfg.get('auth0_page')
            access_page = cfg.get('access_page')

            if not all([pwd_page, pack_page, auth0_page, access_page]):
                raise TagOperationError(f"Tag type {tag.type_name} password config pages not defined.")

            # 1. Write new PWD (4 bytes)
            if not self.reader_handler.ntag_write_page(pwd_page, new_pwd_bytes):
                raise TagWriteError(f"Failed to write PWD to page {pwd_page}.")
            
            # 2. Write PACK (2 bytes, usually first 2 of PWD)
            pack_bytes = new_pwd_bytes[:2] + [0x00, 0x00] # Pad to 4 bytes for page write
            if not self.reader_handler.ntag_write_page(pack_page, pack_bytes):
                raise TagWriteError(f"Failed to write PACK to page {pack_page}.")

            # 3. Configure AUTH0 (first page to be protected by this password)
            #    Typically user memory start page (e.g., 0x04 for NTAGs)
            auth0_value = cfg.get('user_start', 4) 
            auth0_data = [auth0_value, 0x00, 0x00, 0x00] # Other bytes in AUTH0 page are often RFUI
            if not self.reader_handler.ntag_write_page(auth0_page, auth0_data):
                raise TagWriteError(f"Failed to write AUTH0 to page {auth0_page}.")

            # 4. Configure ACCESS page (enable password protection, define R/W access)
            #    Example for NTAG: ACCESS byte 0, bit 7 (PROT) = 1 (enable PWD protection for writes)
            #    Bit 6 (CFGLCK) = 0 (config pages not locked by PWD)
            #    Bit 5 (AUTHLIM0-2) = 000 (no auth attempt limit)
            #    This is simplified. Real ACCESS byte config is complex.
            access_data = self.reader_handler.ntag_read_page(access_page) or [0x00, 0x00, 0x00, 0x00]
            access_data[0] = (access_data[0] & 0x7F) | 0x80 # Set PROT=1, keep other bits
            # access_data[0] &= ~0b01110000 # Clear AUTHLIM (bits 4-6) for no limit (optional)
            if not self.reader_handler.ntag_write_page(access_page, access_data):
                raise TagWriteError(f"Failed to write ACCESS to page {access_page}.")

            self.logger.info(f"Password set successfully on tag {tag.uid_hex}.")
            self.read_tag_info(read_full_memory=True)
            return True
        except (TagOperationError, ReaderHandlerError) as e:
            self._handle_error(f"Error setting password on {tag.uid_hex}: {str(e)}", e)
            return False
        except Exception as e:
            self._handle_error(f"Unexpected error setting password on {tag.uid_hex}", e)
            return False

    def remove_password(self, current_password_hex: str, tag_to_unprotect: Optional[NFCTag] = None) -> bool:
        tag = tag_to_unprotect or self._ensure_reader_and_tag("Remove Password")
        if not tag or not self.reader_handler: return False

        if not tag.is_password_protected: # From previous read
             self.logger.info(f"Tag {tag.uid_hex} is not password protected. No action needed.")
             return True
        if not tag.supports_password:
            self._handle_error(f"Tag type {tag.type_name} does not support password removal.")
            return False
        
        try:
            if not self.authenticate_tag(current_password_hex, tag_to_auth=tag):
                # Auth error already handled by authenticate_tag
                return False

            # Logic to disable password (highly NTAG specific for this example)
            cfg = tag.config
            auth0_page = cfg.get('auth0_page')
            access_page = cfg.get('access_page')
            if not auth0_page or not access_page:
                 raise TagOperationError(f"Tag type {tag.type_name} password config pages not defined for removal.")

            # 1. Set AUTH0 to a value >= total_pages (e.g., 0xFF for NTAG) to disable protection
            auth0_data_disable = [0xFF, 0x00, 0x00, 0x00] 
            if not self.reader_handler.ntag_write_page(auth0_page, auth0_data_disable):
                raise TagWriteError(f"Failed to write AUTH0 (disable) to page {auth0_page}.")

            # 2. Optionally, clear PROT bit in ACCESS page (set bit 7 to 0)
            access_data = self.reader_handler.ntag_read_page(access_page) or [0x00, 0x00, 0x00, 0x00]
            access_data[0] &= 0x7F # Clear PROT bit (bit 7)
            if not self.reader_handler.ntag_write_page(access_page, access_data):
                # This might not be critical if AUTH0 is already 0xFF, but good practice.
                self.logger.warning(f"Failed to update ACCESS page during password removal for {tag.uid_hex}.")
            
            # 3. Optionally, overwrite PWD and PACK pages with 0x00 for security (if desired)
            # pwd_page = cfg.get('pwd_page')
            # pack_page = cfg.get('pack_page')
            # if pwd_page: self.reader_handler.ntag_write_page(pwd_page, [0x00]*4)
            # if pack_page: self.reader_handler.ntag_write_page(pack_page, [0x00]*4)

            self.logger.info(f"Password removed from tag {tag.uid_hex}.")
            self.read_tag_info(read_full_memory=True)
            return True
        except (TagOperationError, ReaderHandlerError) as e:
            self._handle_error(f"Error removing password from {tag.uid_hex}: {str(e)}", e)
            return False
        except Exception as e:
            self._handle_error(f"Unexpected error removing password from {tag.uid_hex}", e)
            return False

    def lock_tag(self) -> bool:
        """Permanently locks parts of the tag (makes it read-only). IRREVERSIBLE."""
        tag = self._ensure_reader_and_tag("Lock Tag")
        if not tag or not self.reader_handler: return False

        if not tag.supports_locking:
            self._handle_error(f"Tag type {tag.type_name} does not support locking.")
            return False
        if tag.is_locked: # From previous read
            self.logger.info(f"Tag {tag.uid_hex} is already reported as locked.")
            return True 

        # UI should get EXTREME confirmation before calling this.
        # Logic to set lock bits (highly tag-specific and DANGEROUS).
        # For NTAG: Static lock bits in CC page 3 (byte 2), Dynamic lock bits (pages E2 for NTAG213).
        # Example: Setting all user memory lock bits for NTAG213 (simplified)
        # This is a placeholder and needs careful, verified implementation for each tag type.
        self.logger.warning("lock_tag is a placeholder. Actual locking is IRREVERSIBLE and DANGEROUS.")
        # Example: For NTAG213, to lock all user pages (4-39) and CC page.
        # This usually involves writing to byte 2 of page 3 (CC) and potentially other lock pages.
        # cc_data = self.reader_handler.ntag_read_page(3) or [0xE1, 0x10, 0x12, 0x00]
        # cc_data[2] |= 0xF0 # Lock pages 4-15 (bits 4-7)
        # cc_data[3] |= 0x0F # Lock pages 16-.. (bits 0-3 of byte 3 for NTAG213 for more pages)
        # if not self.reader_handler.ntag_write_page(3, cc_data):
        #     raise TagLockError("Failed to write CC lock bits.")
        # self.logger.info(f"Tag {tag.uid_hex} PERMANENTLY LOCKED (simulated).")
        # self.read_tag_info(read_full_memory=True)
        # return True
        self._handle_error("Lock tag feature not fully implemented due to its irreversible nature.")
        return False # Placeholder: return False until safe implementation

    def get_current_tag_details(self) -> Optional[Dict[str, Any]]:
        if not self.current_tag: return None
        return {
            "uid": self.current_tag.uid_hex, "type": self.current_tag.type_name,
            "atr": ''.join(f'{b:02X}' for b in self.current_tag.atr) if self.current_tag.atr else "N/A",
            "url": self.current_tag.get_url_from_ndef(),
            "is_locked": self.current_tag.is_locked,
            "is_password_protected": self.current_tag.is_password_protected,
            "max_ndef_bytes": self.current_tag.max_ndef_bytes,
            "ndef_records_count": len(self.current_tag.ndef_records)
        }

    def cleanup(self):
        self.stop_polling()
        self.disconnect_reader()
        self.logger.info("TagOperationsService cleaned up.")

# Example Usage (for testing this module directly if run standalone)
if __name__ == '__main__':
    # This basicConfig is for when running this file directly.
    # The main application (main.py) should set up logging.
    logging.basicConfig(level=logging.DEBUG, 
                        format='%(asctime)s [%(levelname)s] %(name)s (%(module)s.%(funcName)s:%(lineno)d): %(message)s')
    logger_main = logging.getLogger("__main__TagOpsTest")

    service = TagOperationsService()

    def my_tag_detected_callback(tag: Optional[NFCTag]):
        if tag: logger_main.info(f"CALLBACK: Tag Detected! {tag}")
        else: logger_main.info("CALLBACK: Tag Detected event, but tag object is None.")

    def my_tag_removed_callback(tag: Optional[NFCTag]):
        if tag: logger_main.info(f"CALLBACK: Tag Removed! UID: {tag.uid_hex}")
        else: logger_main.info("CALLBACK: Tag Removed (no specific tag info).")

    def my_error_callback(error_msg: str):
        logger_main.error(f"CALLBACK: Operation Error! Message: {error_msg}")

    service.on_tag_detected = my_tag_detected_callback
    service.on_tag_removed = my_tag_removed_callback
    service.on_operation_error = my_error_callback

    available_readers = service.get_available_readers()
    if not available_readers:
        logger_main.warning("No PCSC readers found. Some tests will be skipped or may fail.")
    else:
        logger_main.info(f"Available PCSC readers: {available_readers}")
        if service.select_reader(available_readers[0]): # Try to use the first one
            if service.connect_reader():
                logger_main.info(f"Successfully connected to reader: {service.reader_handler.reader_name if service.reader_handler else 'N/A'}")
                
                logger_main.info("Starting polling for 10 seconds to detect tags...")
                service.start_polling(interval_sec=1.0)
                
                # Simulate some time for polling
                for i in range(10):
                    if service.current_tag:
                        logger_main.info(f"Polling... Current tag: {service.current_tag.uid_hex}")
                        # Test read_tag_info if a tag is present
                        full_info_tag = service.read_tag_info(read_full_memory=True)
                        if full_info_tag:
                            logger_main.info(f"  Full info: URL='{full_info_tag.get_url_from_ndef()}', Locked={full_info_tag.is_locked}, PwdProt={full_info_tag.is_password_protected}")
                        
                        # Example write (CAUTION: This would write to a real tag if present!)
                        # try:
                        #    test_url = f"{config.DEFAULT_NFC_WRITE_URL}/test_{time.time()}"
                        #    logger_main.info(f"Attempting to write URL: {test_url}")
                        #    if service.write_url_to_tag(test_url):
                        #        logger_main.info("Test URL written successfully.")
                        #    else:
                        #        logger_main.error("Failed to write test URL.")
                        # except Exception as e:
                        #    logger_main.error(f"Error during test write: {e}")
                        break # Stop polling after first tag interaction for test
                    time.sleep(1)
                
                service.stop_polling()
                service.disconnect_reader()
            else:
                logger_main.error("Failed to connect to the selected reader.")
        else:
            logger_main.error("Failed to select a reader handler.")
    
    service.cleanup()
    logger_main.info("TagOperationsService test finished.")

