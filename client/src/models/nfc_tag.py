"""
NFC Tag Model for the Arc-TAP NFC Utility client application.

This module provides a class representation of NFC tags with properties
for UID, type, NDEF message, and other attributes, as well as methods
for checking tag capabilities and status.
"""

from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Union, Any
import logging
import ndef # type: ignore - ndeflib might not have stubs

logger = logging.getLogger(__name__)

class TagType(Enum):
    """Enumeration of supported NFC tag types."""
    UNKNOWN = auto()
    NTAG213 = auto()
    NTAG215 = auto()
    NTAG216 = auto() # NTAG216 is larger than NTAG215
    FUDAN_FM11NT021TT = auto() # Common Fudan tag
    MIFARE_CLASSIC_1K = auto()
    MIFARE_ULTRALIGHT = auto()
    # Add other types as needed

    @classmethod
    def from_atr(cls, atr: Optional[List[int]]) -> 'TagType':
        """
        Determine tag type from ATR (Answer To Reset).
        This is a simplified detection, real-world scenarios might need more checks
        and often involve reading the Capability Container (CC) or specific memory pages.

        Args:
            atr: ATR bytes as a list of integers

        Returns:
            TagType enum value
        """
        if not atr:
            return cls.UNKNOWN

        atr_hex = "".join(f"{b:02X}" for b in atr)
        logger.debug(f"Attempting to determine tag type from ATR: {atr_hex}")

        # NTAG213/215/216 often share similar ATR starts
        # Example: 3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 XX XX 00 00 00 00 6X
        # The crucial part is often the first few bytes and historical bytes.
        if atr_hex.startswith("3B8F8001804F0C"): # Common for NXP NTAG series based on ISO/IEC 14443-3 Type A
            # Further differentiation requires reading CC (page 3) or memory size.
            # For now, this indicates it's likely an NTAG. Defaulting to NTAG213,
            # actual type should be refined by reading CC page 3, byte 2 (memory size).
            logger.debug("ATR matches NXP NTAG series prefix.")
            return cls.NTAG213 # Default, should be refined by CC read

        # Fudan FM11NT021TT (and similar Fudan Type A tags)
        # ATR can vary, e.g., 3B 81 80 01... or 3B 8F 80 01...
        # A common pattern for some Fudan tags might be specific T0 or historical bytes.
        # This is a very generic prefix, specific Fudan models might vary.
        # Often, Fudan tags are NTAG compatible but might have different CC or memory map.
        if atr_hex.startswith("3B8F8001") and "FUDAN" in atr_hex: # Highly speculative, real Fudan ATRs vary
             logger.debug("ATR suggests Fudan (speculative).")
             return cls.FUDAN_FM11NT021TT
        if atr_hex.startswith("3B818001"): # Another possible generic Type A start
             logger.debug("ATR suggests generic Type A, possibly Fudan.")
             return cls.FUDAN_FM11NT021TT # Speculative

        # MIFARE Classic 1K
        # Example ATR: 3B 8F 80 01 80 4F 0C A0 00 00 03 06 08 00 08 00 00 00 00 7A
        # SAK value (from SELECT response, not ATR) is key for MIFARE. SAK=08 for 1K.
        # This ATR alone is not definitive for MIFARE Classic.
        if atr_hex.startswith("3B8F8001804F0C") and len(atr) > 13 and atr[13] == 0x08: # Check TCK byte if it indicates SAK
            logger.debug("ATR suggests MIFARE Classic 1K based on TCK byte (speculative).")
            return cls.MIFARE_CLASSIC_1K

        # MIFARE Ultralight
        # Example ATR: 3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 00 00 00 00 00 68
        # SAK=00 for Ultralight.
        if atr_hex.startswith("3B8F8001804F0C") and len(atr) > 13 and atr[13] == 0x00: # Check TCK byte
            logger.debug("ATR suggests MIFARE Ultralight based on TCK byte (speculative).")
            return cls.MIFARE_ULTRALIGHT
            
        logger.debug(f"ATR {atr_hex} did not match known prefixes. Type Unknown.")
        return cls.UNKNOWN


class NFCTag:
    """
    Model representation of an NFC tag.
    Encapsulates properties and behaviors of an NFC tag.
    """

    PAGE_SIZE_BYTES = 4 # Common page size for NTAG/Fudan Type 2 tags

    # (total_writable_pages, user_memory_start_page, user_memory_end_page,
    #  config_start_page, pwd_page, pack_page, auth0_page, access_page, max_ndef_bytes)
    # Note: Page numbers are 0-indexed.
    TAG_CONFIG = {
        TagType.NTAG213: {
            'total_pages': 45, 'user_start': 4, 'user_end': 39, # User area: 36 pages * 4 = 144 bytes
            'config_start': 40, 'pwd_page': 43, 'pack_page': 44, 'auth0_page': 41, 'access_page': 42,
            'max_ndef_bytes': 144 - 6 # Approx. 137-138 usable after NDEF TLVs (03, len, FE, padding)
        },
        TagType.NTAG215: {
            'total_pages': 135, 'user_start': 4, 'user_end': 129, # User area: 126 pages * 4 = 504 bytes
            'config_start': 130, 'pwd_page': 133, 'pack_page': 134, 'auth0_page': 131, 'access_page': 132,
            'max_ndef_bytes': 504 - 6 # Approx. 498 usable
        },
        TagType.NTAG216: {
            'total_pages': 231, 'user_start': 4, 'user_end': 225, # User area: 222 pages * 4 = 888 bytes
            'config_start': 226, 'pwd_page': 229, 'pack_page': 230, 'auth0_page': 227, 'access_page': 228,
            'max_ndef_bytes': 888 - 6 # Approx. 882 usable
        },
        TagType.FUDAN_FM11NT021TT: { # Fudan NTAG compatibles can vary, this is an example
            'total_pages': 64, 'user_start': 4, 'user_end': 59, # User area: 56 pages * 4 = 224 bytes
            'config_start': 60, 'pwd_page': 60, 'pack_page': None, 'auth0_page': 61, 'access_page': 61, # Simplified
            'max_ndef_bytes': 224 - 6 # Approx. 218 usable
        },
        TagType.MIFARE_ULTRALIGHT: { # Basic MIFARE Ultralight (not EV1, etc.)
            'total_pages': 16, 'user_start': 4, 'user_end': 15, # User area: 12 pages * 4 = 48 bytes
            'config_start': 2, 'pwd_page': None, 'pack_page': None, 'auth0_page': None, 'access_page': None, # No password on basic Ultralight
            'max_ndef_bytes': 48 - 6 # Approx. 42 usable
        },
        TagType.MIFARE_CLASSIC_1K: { # NDEF on MIFARE Classic is complex (MAD)
             'total_pages': 64 * 4, # 64 sectors * 4 blocks (but blocks are 16 bytes)
             'user_start': -1, 'user_end': -1, # NDEF not stored in simple page sequence
             'config_start': -1, 'pwd_page': -1, 'pack_page': -1, 'auth0_page': -1, 'access_page': -1,
             'max_ndef_bytes': 716 # Approx, depends on MAD version and sectors used
        },
        TagType.UNKNOWN: {
            'total_pages': 0, 'user_start': 0, 'user_end': 0,
            'config_start': 0, 'pwd_page': 0, 'pack_page': 0, 'auth0_page': 0, 'access_page': 0,
            'max_ndef_bytes': 0
        }
    }

    def __init__(
        self,
        uid: Optional[List[int]] = None,
        atr: Optional[List[int]] = None,
        tag_type_from_cc: Optional[TagType] = None, # Type determined by reading CC
        memory_dump: Optional[Dict[int, List[int]]] = None
    ):
        self.uid: List[int] = uid or []
        self.atr: List[int] = atr or []
        self.memory_dump: Dict[int, List[int]] = memory_dump or {}
        
        if tag_type_from_cc: # Type from CC is more reliable
            self.tag_type: TagType = tag_type_from_cc
        elif atr:
            self.tag_type = TagType.from_atr(atr)
        else:
            self.tag_type = TagType.UNKNOWN
            
        self.ndef_records: List[ndef.record.Record] = []
        self._is_locked: Optional[bool] = None
        self._is_password_protected: Optional[bool] = None
        
        if self.memory_dump:
            # If tag_type is still generic (e.g. NTAG213 from ATR), try to refine it from CC in memory_dump
            if self.tag_type == TagType.NTAG213 and 3 in self.memory_dump: # Page 3 is CC for NTAG
                self._refine_ntag_type_from_cc(self.memory_dump[3])

            self._parse_ndef_from_memory()
            self._analyze_protection_status()

    def _refine_ntag_type_from_cc(self, cc_page_data: List[int]):
        """Refines NTAG type (213/215/216) based on Capability Container (page 3)."""
        if len(cc_page_data) == 4:
            size_byte = cc_page_data[2] # CC byte 2 indicates memory size
            if size_byte == 0x12: self.tag_type = TagType.NTAG213
            elif size_byte == 0x3E: self.tag_type = TagType.NTAG215 # NXP datasheet says 0x3E for NTAG215
            elif size_byte == 0x6D: self.tag_type = TagType.NTAG216 # NXP datasheet says 0x6D for NTAG216
            else: logger.warning(f"Unknown NTAG size byte in CC: {size_byte:#02x}. Keeping type {self.tag_type}.")
            logger.debug(f"Refined tag type from CC to: {self.tag_type.name}")


    @property
    def uid_hex(self) -> str:
        return ''.join(f'{byte:02X}' for byte in self.uid)

    @property
    def type_name(self) -> str:
        return self.tag_type.name

    @property
    def config(self) -> Dict[str, Any]:
        return self.TAG_CONFIG.get(self.tag_type, self.TAG_CONFIG[TagType.UNKNOWN])

    @property
    def max_ndef_bytes(self) -> int:
        return self.config.get('max_ndef_bytes', 0)

    @property
    def user_memory_pages_range(self) -> Tuple[int, int]:
        return self.config.get('user_start', 0), self.config.get('user_end', 0)

    @property
    def supports_password(self) -> bool:
        return self.config.get('pwd_page') is not None

    @property
    def supports_locking(self) -> bool:
        # Most Type 2 tags support some form of locking.
        # MIFARE Classic has sector-based locking.
        return self.tag_type not in [TagType.UNKNOWN] # Too generic, refine later

    @property
    def is_locked(self) -> Optional[bool]:
        return self._is_locked

    @property
    def is_password_protected(self) -> Optional[bool]:
        return self._is_password_protected

    def set_memory_dump(self, memory_dump: Dict[int, List[int]]) -> None:
        self.memory_dump = memory_dump
        if self.tag_type == TagType.NTAG213 and 3 in self.memory_dump: # Re-check CC if NTAG
            self._refine_ntag_type_from_cc(self.memory_dump[3])
        self._parse_ndef_from_memory()
        self._analyze_protection_status()

    def _extract_user_memory_bytes(self) -> bytes:
        user_start, user_end = self.user_memory_pages_range
        if user_start == 0 and user_end == 0 and self.tag_type != TagType.MIFARE_ULTRALIGHT: # Ultralight starts user at 4
             if not (user_start == 0 and self.tag_type == TagType.UNKNOWN): # Allow unknown if user_start is 0
                logger.debug(f"No user memory range defined for tag type {self.type_name}.")
                return b''
            
        data_bytes = bytearray()
        for page_num in range(user_start, user_end + 1):
            page_data = self.memory_dump.get(page_num)
            if page_data:
                data_bytes.extend(page_data)
            else:
                logger.debug(f"Page {page_num} (user memory) missing in dump. NDEF parsing might be incomplete.")
                break 
        return bytes(data_bytes)

    def _parse_ndef_from_memory(self) -> None:
        self.ndef_records = []
        if not self.memory_dump or self.tag_type == TagType.MIFARE_CLASSIC_1K: # NDEF on Classic is complex
            if self.tag_type == TagType.MIFARE_CLASSIC_1K:
                logger.debug("NDEF parsing for MIFARE Classic from raw page dump not implemented here (requires MAD).")
            return

        user_data = self._extract_user_memory_bytes()
        if not user_data:
            logger.debug("No user memory data found to parse NDEF from.")
            return

        try:
            i = 0
            while i < len(user_data):
                tlv_type = user_data[i]
                if tlv_type == 0x03: # NDEF Message TLV
                    if i + 1 < len(user_data):
                        tlv_length = user_data[i+1]
                        if tlv_length == 0: # Empty NDEF message
                            logger.debug("Found empty NDEF Message TLV (length 0).")
                            break 
                        
                        # Check for 3-byte length field (0xFF LL HH)
                        if tlv_length == 0xFF:
                            if i + 3 < len(user_data):
                                tlv_length = (user_data[i+2] << 8) + user_data[i+3]
                                value_start_index = i + 4
                            else:
                                logger.warning("Malformed 3-byte NDEF TLV: Not enough bytes for length.")
                                break
                        else: # 1-byte length
                            value_start_index = i + 2
                        
                        value_end_index = value_start_index + tlv_length
                        
                        if value_end_index <= len(user_data):
                            ndef_message_bytes = user_data[value_start_index:value_end_index]
                            self.ndef_records = list(ndef.message_decoder(ndef_message_bytes))
                            logger.info(f"Parsed {len(self.ndef_records)} NDEF records from memory.")
                            break 
                        else:
                            logger.warning(f"NDEF TLV length {tlv_length} exceeds available data (len {len(user_data)} from index {value_start_index}).")
                            break 
                    else: 
                        logger.warning("Malformed NDEF TLV: Type byte found but no Length byte.")
                        break
                elif tlv_type == 0x00: # Null TLV
                    i += 1
                elif tlv_type == 0xFE: # Terminator TLV
                    logger.debug("Terminator TLV found. End of NDEF data.")
                    break
                else: 
                    logger.debug(f"Non-NDEF or unknown TLV type {tlv_type:#02x} found at start of user memory. Assuming no NDEF message.")
                    break 
            
        except ndef.DecodeError as e:
            logger.warning(f"Failed to decode NDEF message from memory: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing NDEF from memory: {e}", exc_info=True)

    def _analyze_protection_status(self) -> None:
        self._is_locked = False # Default to not locked
        self._is_password_protected = False # Default to not password protected

        if not self.memory_dump:
            return

        cfg = self.config
        if self.tag_type in [TagType.NTAG213, TagType.NTAG215, TagType.NTAG216]:
            # NTAG21x: Check CC (page 3) for static lock bits
            cc_data = self.memory_dump.get(3) # Capability Container is page 3
            if cc_data and len(cc_data) == 4:
                # Byte 2 (cc_data[2]) contains lock bits for NTAG213/215/216
                # Bit 3 (0x08): if set, user memory is permanently write-protected (field program_once)
                # Bits 4-7: Lock specific blocks of 16 pages (04h-0Fh, 10h-1Fh etc.)
                # For simplicity, if any of these are set, consider it "locked" in some way.
                # A more granular status would require checking each bit.
                if (cc_data[2] & 0xF8) != 0: # Check bits 3-7
                    self._is_locked = True 
                    logger.debug(f"NTAG CC lock bits found: {cc_data[2]:#02x}")

            # Check password protection (AUTH0 and ACCESS pages)
            auth0_page_num = cfg.get('auth0_page')
            access_page_num = cfg.get('access_page')

            if auth0_page_num is not None:
                auth0_data = self.memory_dump.get(auth0_page_num)
                if auth0_data and len(auth0_data) == 4:
                    first_protected_page = auth0_data[0] # Byte 0 of AUTH0 page
                    # If AUTH0 is less than total_pages (or a specific end marker like 0xFF for NTAG),
                    # it means password protection starts from that page.
                    if first_protected_page < cfg.get('total_pages', 0xFF):
                        self._is_password_protected = True
                        logger.debug(f"NTAG password protection active: AUTH0={first_protected_page:#02x}")
        
        elif self.tag_type == TagType.FUDAN_FM11NT021TT:
            # Fudan NTAG-compatibles: Config page often 60 (0x3C) or similar
            config_page_data = self.memory_dump.get(cfg.get('config_start', 60))
            if config_page_data and len(config_page_data) == 4:
                # Example: Byte 0, Bit 0 for write lock, Bit 1 for password enable.
                # This is highly model-specific for Fudan.
                # Assuming similar to some NTAG-like Fudan models:
                if (config_page_data[0] & 0b00000001): # Example: Bit 0 = User memory write lock
                    self._is_locked = True
                if (config_page_data[0] & 0b10000000): # Example: Bit 7 = Password protection enabled (AUTH_EN)
                    self._is_password_protected = True
                logger.debug(f"Fudan config page {cfg.get('config_start', 60)} data: {config_page_data[0]:#02x}")
        
        elif self.tag_type == TagType.MIFARE_ULTRALIGHT:
            # Basic MIFARE Ultralight has OTP (One-Time Programmable) bits and lock bits
            # Page 2 (OTP bits), Page 3 (Lock bits for pages 3-15)
            otp_data = self.memory_dump.get(2)
            lock_data_p3 = self.memory_dump.get(3) # Lock bits for pages 3-15
            # Further lock bits for pages 0-2 might be in page 2 itself or other config pages for EV1 etc.
            if otp_data and any(b != 0 for b in otp_data): # If any OTP bit is set
                self._is_locked = True # Consider it locked if OTP used
            if lock_data_p3 and any(b != 0 for b in lock_data_p3): # If any lock bit for pages 3-15 is set
                self._is_locked = True
            logger.debug(f"MIFARE Ultralight lock check: OTP={otp_data}, LockP3={lock_data_p3}")


    def get_url_from_ndef(self) -> Optional[str]:
        if not self.ndef_records: return None
        for record in self.ndef_records:
            if isinstance(record, ndef.uri.UriRecord): return record.uri
            if isinstance(record, ndef.text.TextRecord): # Check if text looks like a URL
                if record.text and (record.text.startswith("http://") or record.text.startswith("https://")):
                    return record.text
        return None

    def create_ndef_message_with_url(self, url: str) -> bytes:
        if not url: raise ValueError("URL cannot be empty.")
        # Ensure URL has a scheme, default to https if missing (common for NFC)
        if not ("://" in url):
            url = "https://" + url
            logger.debug(f"Prepended https:// to URL: {url}")
        try:
            uri_record = ndef.UriRecord(url)
            return b''.join(ndef.message_encoder([uri_record]))
        except Exception as e:
            logger.error(f"Error creating NDEF UriRecord for '{url}': {e}")
            raise ndef.EncodeError(f"Failed to create NDEF message for URL '{url}': {e}")

    def get_ndef_tlv_bytes(self, ndef_message_bytes: bytes) -> bytes:
        msg_len = len(ndef_message_bytes)
        
        # NDEF Message TLV: Type (0x03)
        # Length: 1 byte if msg_len <= 254, or 3 bytes (0xFF LL HH) if msg_len > 254
        # Value: ndef_message_bytes
        # Terminator TLV: Type (0xFE)
        
        tlv_data = bytearray()
        tlv_data.append(0x03) # NDEF Message TLV Type
        
        if msg_len <= 254:
            tlv_data.append(msg_len) # Single byte length
        else:
            tlv_data.append(0xFF) # Indicator for 2-byte length
            tlv_data.append((msg_len >> 8) & 0xFF) # Length High Byte
            tlv_data.append(msg_len & 0xFF)        # Length Low Byte
            
        tlv_data.extend(ndef_message_bytes) # NDEF Message Value
        tlv_data.append(0xFE) # Terminator TLV
        
        # Pad with Null TLVs (0x00) if needed to make total length a multiple of PAGE_SIZE_BYTES
        # This is common for Type 2 tags.
        # Note: This padding is for the entire TLV block to be written, not just the NDEF message part.
        # However, usually NDEF data area itself is page aligned.
        # For simplicity here, we assume the TLV block itself might not need page alignment
        # if the write operation handles partial pages or the tag manages it.
        # If strict page alignment of the *entire written block* is needed:
        # while len(tlv_data) % self.PAGE_SIZE_BYTES != 0:
        #    tlv_data.append(0x00) # Null TLV for padding

        return bytes(tlv_data)

    def __str__(self) -> str:
        uid_str = self.uid_hex if self.uid else "N/A"
        type_str = self.type_name
        url = self.get_url_from_ndef() or "N/A"
        prot_parts = []
        if self.is_password_protected is True: prot_parts.append("PwdProtected")
        elif self.is_password_protected is False: prot_parts.append("NoPwd")
        else: prot_parts.append("PwdUnk")
        if self.is_locked is True: prot_parts.append("Locked")
        elif self.is_locked is False: prot_parts.append("Unlocked")
        else: prot_parts.append("LockUnk")
        protection_str = ", ".join(prot_parts) if prot_parts else "ProtectionUnk"
        return (f"NFCTag(UID: {uid_str}, Type: {type_str}, URL: '{url}', Protection: [{protection_str}])")

    def __repr__(self) -> str:
        return f"NFCTag(uid_hex={self.uid_hex!r}, tag_type={self.tag_type.name!r})"

# Example Usage:
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    # Example NTAG215 memory dump (simplified)
    example_ntag215_dump = {
        0: [0x04,0x77,0x3A,0x8A], 1: [0x94,0x48,0x80,0x00], 2: [0x00,0x00,0x00,0x00], 3: [0xE1,0x10,0x3E,0x00], # UID, CC (NTAG215)
        4: [0x03,0x0D,0xD1,0x01], 5: [0x09,0x55,0x01,0x6E], 6: [0x78,0x70,0x2E,0x63], 7: [0x6F,0x6D,0xFE,0x00], # NDEF: http://nxp.com
        # Config pages for NTAG215 (example, may not be readable without auth if protected)
        130: [0x00,0x00,0x00,0x00], # CFG0
        131: [0x85,0x00,0x00,0x00], # AUTH0 (example: 0x85 means no pwd protection, as 133 > 135 total pages)
        132: [0x00,0x00,0x00,0x00], # ACCESS
        133: [0x00,0x00,0x00,0x00], # PWD
        134: [0x00,0x00,0x00,0x00]  # PACK
    }
    tag_215 = NFCTag(
        uid=[0x04,0x77,0x3A,0x8A,0x94,0x48,0x80], 
        atr=[0x3B,0x8F,0x80,0x01,0x80,0x4F,0x0C,0xA0,0x00,0x00,0x03,0x06,0x03,0x3E,0x00,0x00,0x00,0x00,0x00,0x5D], # Example ATR
        memory_dump=example_ntag215_dump
    )
    logger.info(f"Test Tag: {tag_215}")
    logger.info(f"  URL: {tag_215.get_url_from_ndef()}")
    logger.info(f"  Is Password Protected: {tag_215.is_password_protected}")
    logger.info(f"  Is Locked: {tag_215.is_locked}")

    new_url = "aakronline.com/tapnfc"
    ndef_bytes = tag_215.create_ndef_message_with_url(new_url)
    tlv_bytes = tag_215.get_ndef_tlv_bytes(ndef_bytes)
    logger.info(f"NDEF for '{new_url}': {ndef_bytes.hex().upper()}")
    logger.info(f"TLV for '{new_url}': {tlv_bytes.hex().upper()} (len: {len(tlv_bytes)})")
    
    # Test a long URL requiring 3-byte length field for NDEF TLV
    long_url = "https://" + "a" * 250 + ".com"
    try:
        ndef_long_bytes = tag_215.create_ndef_message_with_url(long_url)
        tlv_long_bytes = tag_215.get_ndef_tlv_bytes(ndef_long_bytes) # This should handle 3-byte length
        logger.info(f"TLV for long URL (len {len(ndef_long_bytes)}): {tlv_long_bytes[:10].hex().upper()}... (total len: {len(tlv_long_bytes)})")
        assert tlv_long_bytes[1] == 0xFF # Check for 3-byte length indicator
    except Exception as e:
        logger.error(f"Error with long URL test: {e}")

