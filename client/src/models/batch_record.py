"""
Batch Record Model for the Arc-TAP NFC Utility client application.

This module defines the BatchRecord data class, which represents a batch
NFC tag writing operation, including its configuration, progress, and status.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any, Union
import uuid
import logging
import json # For potential serialization/deserialization if needed beyond DB

# Placeholder for encryption utilities - in a real app, import from utils.security
# For this model, we only care about the fields, not the encryption logic itself.
# The DatabaseService will handle calling actual encryption/decryption.
def decrypt_placeholder(data: Optional[bytes]) -> Optional[str]:
    if data: return f"decrypted_{data.hex()}" # Dummy
    return None

logger = logging.getLogger(__name__)

@dataclass
class BatchRecord:
    """
    Represents a batch NFC tag writing operation.
    
    Attributes:
        destination_url: The primary URL to be written to each tag in the batch.
        quantity: The total number of tags intended for this batch.
        batch_id: A unique identifier for the batch (auto-generated if not provided).
        static_url: An optional static/base URL that might be part of the redirection logic.
        customer_name: Optional name of the customer for whom the batch is being processed.
        customer_id: Optional unique identifier for the customer.
        order_number: Optional order number associated with this batch.
        password: Optional cleartext password to be set on each tag after writing the URL.
                  This is used for input/display; `encrypted_password` is stored in the DB.
        encrypted_password: Optional encrypted version of the password, as bytes, for database storage.
        payment_status: The payment status of the order (e.g., "Pending", "Paid").
        start_uid: The UID of the first tag successfully processed in this batch.
        finish_uid: The UID of the last tag successfully processed in this batch.
        created_at: Timestamp of when the batch record was created.
        updated_at: Timestamp of the last update to the batch record.
        completed: Boolean flag indicating if the batch processing is considered complete.
        tags_written: Count of tags successfully written in this batch.
        errors: Count of errors encountered during the processing of this batch.
        written_uids: List of UIDs of tags that were successfully written.
        error_details: List of dictionaries, each detailing an error encountered for a specific tag.
    """
    
    # Core required fields
    destination_url: str
    quantity: int
    
    # Identifiers and optional metadata
    batch_id: str = field(default_factory=lambda: f"batch_{uuid.uuid4().hex[:12]}") # Shorter UUID
    static_url: Optional[str] = None
    customer_name: Optional[str] = None
    customer_id: Optional[str] = None
    order_number: Optional[str] = None
    
    # Password fields
    password: Optional[str] = None  # For user input or displaying decrypted password
    encrypted_password: Optional[bytes] = None # For database storage
    
    # Status and tracking
    payment_status: str = "Pending"
    start_uid: Optional[str] = None
    finish_uid: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    completed: bool = False
    tags_written: int = 0
    errors: int = 0
    
    # Detailed logging
    written_uids: List[str] = field(default_factory=list)
    error_details: List[Dict[str, Any]] = field(default_factory=list) # e.g., {'uid': str, 'timestamp': datetime, 'message': str}

    def __post_init__(self):
        """Perform validation or initialization after dataclass creation."""
        if self.quantity <= 0:
            raise ValueError("Batch quantity must be a positive integer.")
        if not self.destination_url:
            raise ValueError("Destination URL cannot be empty.")
        
        # If a cleartext password is provided but no encrypted form,
        # it's the responsibility of the service layer (e.g., DatabaseService)
        # to encrypt it before saving. This model just holds the data.
        # Similarly, if encrypted_password is set, password field might be populated
        # by decryption in the service layer when loading from DB.

    def update_progress(self, uid: str, success: bool, error_message: Optional[str] = None) -> None:
        """
        Updates the batch progress based on the processing of a single tag.
        Args:
            uid: The UID of the tag that was processed.
            success: True if the tag was processed successfully, False otherwise.
            error_message: An optional error message if processing failed.
        """
        if uid in self.written_uids and success:
            logger.warning(f"Tag {uid} reported as success but already in written_uids for batch {self.batch_id}.")
            return # Avoid double counting successful writes if re-processed somehow

        if success:
            self.tags_written += 1
            if uid not in self.written_uids:
                 self.written_uids.append(uid)
            if not self.start_uid:
                self.start_uid = uid
            self.finish_uid = uid # Always update to the latest successfully written UID
        else:
            self.errors += 1
            self.error_details.append({
                'uid': uid,
                'timestamp': datetime.now().isoformat(), # Store as ISO string for easier serialization
                'message': error_message or "Unknown processing error"
            })
        
        self.updated_at = datetime.now()
        
        # Check if the batch is considered complete
        if (self.tags_written + self.errors) >= self.quantity:
            self.completed = True
            logger.info(f"Batch {self.batch_id} marked as complete. "
                        f"Written: {self.tags_written}, Errors: {self.errors}, Target: {self.quantity}")

    def get_completion_percentage(self) -> float:
        """Calculates the completion percentage of the batch."""
        if self.quantity == 0:
            return 100.0 if self.completed else 0.0
        
        # Considers processed tags (successful or errored) towards completion
        processed_tags = self.tags_written + self.errors
        percentage = (processed_tags / self.quantity) * 100
        return min(percentage, 100.0) # Cap at 100%

    def get_summary(self) -> str:
        """Provides a human-readable summary string of the batch status."""
        status_str = "Completed" if self.completed else "In Progress"
        summary = (
            f"Batch ID: {self.batch_id} ({status_str})\n"
            f"  Target URL: {self.destination_url}\n"
            f"  Quantity: {self.quantity}\n"
            f"  Successfully Written: {self.tags_written}\n"
            f"  Errors: {self.errors}\n"
            f"  Progress: {self.get_completion_percentage():.2f}%\n"
            f"  Customer: {self.customer_name or 'N/A'}, Order: {self.order_number or 'N/A'}\n"
            f"  UID Range: {self.start_uid or 'N/A'} - {self.finish_uid or 'N/A'}\n"
            f"  Password Set: {'Yes' if self.password or self.encrypted_password else 'No'}\n"
            f"  Last Updated: {self.updated_at.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        return summary

    def to_db_dict(self) -> Dict[str, Any]:
        """
        Prepares a dictionary representation of the batch suitable for database storage.
        Ensures `encrypted_password` is bytes if a password was set.
        Booleans are converted to integers (0 or 1) for SQLite compatibility.
        Datetimes are converted to ISO format strings.
        """
        # The DatabaseService should handle encryption if self.password is set and self.encrypted_password is None.
        # This method just prepares the current state.
        return {
            "batch_id": self.batch_id,
            "destination_url": self.destination_url,
            "static_url": self.static_url,
            "customer_name": self.customer_name,
            "customer_id": self.customer_id,
            "order_number": self.order_number,
            "payment_status": self.payment_status,
            "encrypted_password": self.encrypted_password, # Should be bytes or None
            "quantity": self.quantity,
            "start_uid": self.start_uid,
            "finish_uid": self.finish_uid,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "completed": 1 if self.completed else 0, # For SQLite
            "tags_written": self.tags_written,
            "errors": self.errors
        }

    @classmethod
    def from_db_row(cls, db_row: Union[Dict[str, Any], Any]) -> 'BatchRecord': # Any for sqlite3.Row
        """
        Creates a BatchRecord instance from a database row (e.g., a dictionary or sqlite3.Row).
        Handles decryption of password if `encrypted_password` is present.
        """
        if not isinstance(db_row, dict):
            try: # Attempt to convert sqlite3.Row to dict
                row_dict = dict(db_row)
            except TypeError:
                raise ValueError("db_row must be a dictionary-like object or sqlite3.Row")
        else:
            row_dict = db_row

        # Create a dictionary with only the fields relevant to BatchRecord constructor
        batch_fields_names = {f.name for f in fields(cls)}
        init_data = {k: v for k, v in row_dict.items() if k in batch_fields_names or k == 'destination'} # 'destination' might be old name

        # Rename 'destination' to 'destination_url' if old schema is used
        if 'destination' in init_data and 'destination_url' not in init_data:
            init_data['destination_url'] = init_data.pop('destination')

        # Handle password decryption
        decrypted_password = None
        if 'encrypted_password' in init_data and init_data['encrypted_password']:
            # Use a placeholder for decryption logic here, actual decryption in service layer
            # For the model, we can just note that it was encrypted.
            # If we want the model to hold the decrypted password, the service needs to pass it.
            # Let's assume the service passes the decrypted password as 'password' if successful.
            # For now, if encrypted_password is in row_dict, we try to decrypt.
            decrypted_password = decrypt_placeholder(init_data['encrypted_password']) # Placeholder
            if decrypted_password:
                 init_data['password'] = decrypted_password
            # We don't want to pass encrypted_password directly to constructor if we have cleartext
            if 'encrypted_password' in init_data: # It's already used or failed to decrypt
                pass # Keep it for now, constructor will handle if 'password' is also there
        
        # Convert datetime strings from DB back to datetime objects
        for dt_field in ['created_at', 'updated_at']:
            if dt_field in init_data and isinstance(init_data[dt_field], str):
                try:
                    init_data[dt_field] = datetime.fromisoformat(init_data[dt_field])
                except ValueError:
                    logger.warning(f"Could not parse datetime string '{init_data[dt_field]}' for field '{dt_field}'. Using current time.")
                    init_data[dt_field] = datetime.now()
        
        # Convert SQLite integer (0/1) back to boolean for 'completed'
        if 'completed' in init_data and isinstance(init_data['completed'], int):
            init_data['completed'] = bool(init_data['completed'])

        # Ensure all required fields for BatchRecord constructor are present
        if 'destination_url' not in init_data:
            raise ValueError("Missing 'destination_url' in database row for BatchRecord.")
        if 'quantity' not in init_data:
            raise ValueError("Missing 'quantity' in database row for BatchRecord.")

        # Filter out keys not in BatchRecord constructor to avoid TypeError
        final_init_data = {k: v for k,v in init_data.items() if k in batch_fields_names}

        return cls(**final_init_data)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serializes the batch record to a JSON string."""
        # Prepare a serializable dictionary (e.g., convert datetime to ISO string)
        data_dict = self.to_db_dict() # to_db_dict already converts datetimes
        # Remove encrypted_password from JSON output for security if password field is populated
        if data_dict.get('password') and 'encrypted_password' in data_dict:
            del data_dict['encrypted_password']
        # Add detailed logs if needed
        data_dict['written_uids'] = self.written_uids
        data_dict['error_details'] = self.error_details # Timestamps are already ISO strings
        return json.dumps(data_dict, indent=indent)

    @classmethod
    def from_json(cls, json_string: str) -> 'BatchRecord':
        """Deserializes a batch record from a JSON string."""
        data_dict = json.loads(json_string)
        # written_uids and error_details might be in the JSON, handle them
        written_uids = data_dict.pop('written_uids', [])
        error_details = data_dict.pop('error_details', [])
        
        record = cls.from_db_row(data_dict) # Use from_db_row for consistent field handling
        record.written_uids = written_uids
        record.error_details = error_details
        return record

# Example Usage (for testing this module directly)
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    # Create a batch
    batch1 = BatchRecord(destination_url="https://example.com/productA", quantity=50,
                         customer_name="Test Customer Inc.", order_number="ORD123",
                         password="supersecretpassword") # Provide cleartext password
    
    logger.info(f"Created Batch 1: {batch1.batch_id}")
    logger.info(f"  Password (clear): {batch1.password}")
    logger.info(f"  Encrypted Password (bytes): {batch1.encrypted_password}") # Will be None initially

    # Simulate processing some tags
    batch1.update_progress("UID001", success=True)
    batch1.update_progress("UID002", success=True)
    batch1.update_progress("UID003", success=False, error_message="Tag communication failed")
    
    logger.info(f"\nBatch 1 Summary:\n{batch1.get_summary()}")

    # Simulate database storage preparation (encryption would happen in DatabaseService)
    # For this test, let's assume encryption happened and set encrypted_password
    if batch1.password:
        # Dummy encryption for test
        batch1.encrypted_password = f"encrypted_{batch1.password}".encode() 
    
    db_dict = batch1.to_db_dict()
    logger.info(f"\nBatch 1 for DB: {db_dict}")
    assert isinstance(db_dict['encrypted_password'], bytes)
    assert db_dict['completed'] == 0 # Not yet completed

    # Simulate loading from DB (decryption would happen in DatabaseService or by from_db_row)
    # For this test, from_db_row uses a decrypt_placeholder
    reloaded_batch1 = BatchRecord.from_db_row(db_dict)
    reloaded_batch1.written_uids = batch1.written_uids # Restore these lists if not in db_dict
    reloaded_batch1.error_details = batch1.error_details

    logger.info(f"\nReloaded Batch 1: {reloaded_batch1.batch_id}")
    logger.info(f"  Password (decrypted): {reloaded_batch1.password}")
    logger.info(f"  Encrypted Password (bytes from db_dict): {reloaded_batch1.encrypted_password}") # Should be None if 'password' was populated
    logger.info(f"  Tags written: {reloaded_batch1.tags_written}") # Should be 0 as it's not in db_dict
    
    # Check if password was "decrypted" by placeholder
    if batch1.password:
        assert reloaded_batch1.password == decrypt_placeholder(batch1.encrypted_password)

    # Simulate completing the batch
    for i in range(4, 51): # Process remaining tags up to 50
        batch1.update_progress(f"UID{i:03}", success=True)
    
    assert batch1.completed is True
    assert batch1.tags_written == 50 - 1 # 1 error
    logger.info(f"\nBatch 1 Final Summary:\n{batch1.get_summary()}")

    # Test JSON serialization
    json_output = batch1.to_json(indent=2)
    logger.info(f"\nBatch 1 JSON output:\n{json_output}")
    
    # Test JSON deserialization
    reloaded_from_json = BatchRecord.from_json(json_output)
    logger.info(f"\nBatch 1 Reloaded from JSON: {reloaded_from_json.batch_id}")
    assert reloaded_from_json.batch_id == batch1.batch_id
    assert reloaded_from_json.tags_written == batch1.tags_written
    assert len(reloaded_from_json.error_details) == len(batch1.error_details)

    logger.info("\nBatchRecord tests completed.")

