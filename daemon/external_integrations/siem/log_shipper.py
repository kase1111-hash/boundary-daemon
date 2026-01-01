"""
Log Shipper for SIEM Integration

Provides log shipping capabilities to:
- Apache Kafka for real-time streaming
- AWS S3 for cloud storage
- Google Cloud Storage for cloud storage
- Generic HTTP endpoints

All shippers support:
- Batching for efficiency
- Retry with exponential backoff
- Compression (gzip)
- Signature inclusion for verification
"""

import gzip
import hashlib
import json
import logging
import os
import queue
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Union
from pathlib import Path

logger = logging.getLogger(__name__)


class ShipperProtocol(Enum):
    """Supported shipping protocols."""
    KAFKA = "kafka"
    S3 = "s3"
    GCS = "gcs"
    HTTP = "http"
    FILE = "file"


@dataclass
class ShipperConfig:
    """Configuration for log shippers."""
    # General settings
    protocol: ShipperProtocol = ShipperProtocol.FILE
    batch_size: int = 100
    batch_timeout_seconds: float = 30.0
    max_retries: int = 3
    retry_backoff_base: float = 2.0
    compress: bool = True
    include_signatures: bool = True

    # Kafka settings
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic: str = "boundary-daemon-events"
    kafka_security_protocol: str = "PLAINTEXT"
    kafka_sasl_mechanism: Optional[str] = None
    kafka_sasl_username: Optional[str] = None
    kafka_sasl_password: Optional[str] = None

    # S3 settings
    s3_bucket: str = ""
    s3_prefix: str = "boundary-daemon/logs/"
    s3_region: str = "us-east-1"
    s3_access_key: Optional[str] = None
    s3_secret_key: Optional[str] = None
    s3_endpoint_url: Optional[str] = None  # For S3-compatible storage

    # GCS settings
    gcs_bucket: str = ""
    gcs_prefix: str = "boundary-daemon/logs/"
    gcs_credentials_file: Optional[str] = None

    # HTTP settings
    http_endpoint: str = ""
    http_headers: Dict[str, str] = field(default_factory=dict)
    http_timeout: float = 30.0

    # File settings (fallback/testing)
    file_path: str = "/var/log/boundary-daemon/shipped/"


class LogShipper(ABC):
    """Abstract base class for log shippers."""

    def __init__(self, config: ShipperConfig):
        self.config = config
        self._batch: List[Dict[str, Any]] = []
        self._batch_lock = threading.Lock()
        self._last_flush = time.time()
        self._running = False
        self._flush_thread: Optional[threading.Thread] = None

    @abstractmethod
    def _ship_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Ship a batch of events. Returns True on success."""
        pass

    def add_event(self, event: Dict[str, Any]) -> None:
        """Add an event to the batch."""
        with self._batch_lock:
            self._batch.append(event)

            # Check if batch is full
            if len(self._batch) >= self.config.batch_size:
                self._flush_batch()

    def _flush_batch(self) -> bool:
        """Flush the current batch."""
        with self._batch_lock:
            if not self._batch:
                return True

            events = self._batch.copy()
            self._batch = []
            self._last_flush = time.time()

        # Ship with retries
        return self._ship_with_retry(events)

    def _ship_with_retry(self, events: List[Dict[str, Any]]) -> bool:
        """Ship events with exponential backoff retry."""
        for attempt in range(self.config.max_retries):
            try:
                if self._ship_batch(events):
                    logger.debug(f"Shipped {len(events)} events successfully")
                    return True
            except Exception as e:
                logger.warning(
                    f"Ship attempt {attempt + 1}/{self.config.max_retries} failed: {e}"
                )

            if attempt < self.config.max_retries - 1:
                wait_time = self.config.retry_backoff_base ** attempt
                time.sleep(wait_time)

        logger.error(f"Failed to ship {len(events)} events after {self.config.max_retries} attempts")
        return False

    def _compress_data(self, data: bytes) -> bytes:
        """Compress data using gzip."""
        return gzip.compress(data)

    def _generate_batch_id(self, events: List[Dict[str, Any]]) -> str:
        """Generate a unique batch ID."""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
        content_hash = hashlib.sha256(
            json.dumps(events, sort_keys=True).encode()
        ).hexdigest()[:12]
        return f"{timestamp}_{content_hash}"

    def _flush_loop(self) -> None:
        """Background thread to flush batches on timeout."""
        while self._running:
            time.sleep(1.0)
            with self._batch_lock:
                elapsed = time.time() - self._last_flush
                if self._batch and elapsed >= self.config.batch_timeout_seconds:
                    # Copy and clear
                    events = self._batch.copy()
                    self._batch = []
                    self._last_flush = time.time()

            if events:
                self._ship_with_retry(events)
            events = []

    def start(self) -> None:
        """Start the background flush thread."""
        if self._running:
            return
        self._running = True
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()
        logger.info(f"Log shipper started ({self.config.protocol.value})")

    def stop(self) -> None:
        """Stop the shipper and flush remaining events."""
        self._running = False
        if self._flush_thread:
            self._flush_thread.join(timeout=5.0)
        self._flush_batch()  # Final flush
        logger.info("Log shipper stopped")

    def flush(self) -> bool:
        """Manually flush the current batch."""
        return self._flush_batch()


class KafkaShipper(LogShipper):
    """
    Ship logs to Apache Kafka.

    Requires: kafka-python package
    """

    def __init__(self, config: ShipperConfig):
        super().__init__(config)
        self._producer = None

    def _get_producer(self):
        """Lazy-initialize Kafka producer."""
        if self._producer is None:
            try:
                from kafka import KafkaProducer
            except ImportError:
                raise ImportError(
                    "kafka-python package required for Kafka shipping. "
                    "Install with: pip install kafka-python"
                )

            producer_config = {
                'bootstrap_servers': self.config.kafka_bootstrap_servers.split(','),
                'value_serializer': lambda v: json.dumps(v).encode('utf-8'),
                'compression_type': 'gzip' if self.config.compress else None,
                'acks': 'all',  # Wait for all replicas
                'retries': 3,
            }

            # Add security settings if configured
            if self.config.kafka_security_protocol != "PLAINTEXT":
                producer_config['security_protocol'] = self.config.kafka_security_protocol

            if self.config.kafka_sasl_mechanism:
                producer_config['sasl_mechanism'] = self.config.kafka_sasl_mechanism
                producer_config['sasl_plain_username'] = self.config.kafka_sasl_username
                producer_config['sasl_plain_password'] = self.config.kafka_sasl_password

            self._producer = KafkaProducer(**producer_config)

        return self._producer

    def _ship_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Ship events to Kafka."""
        producer = self._get_producer()

        futures = []
        for event in events:
            # Use event_id as key for partitioning
            key = event.get('event_id', '').encode('utf-8')
            future = producer.send(
                self.config.kafka_topic,
                value=event,
                key=key,
            )
            futures.append(future)

        # Wait for all sends to complete
        producer.flush()

        # Check for errors
        for future in futures:
            try:
                future.get(timeout=10)
            except Exception as e:
                logger.error(f"Kafka send failed: {e}")
                return False

        return True

    def stop(self) -> None:
        """Stop shipper and close Kafka producer."""
        super().stop()
        if self._producer:
            self._producer.close()


class S3Shipper(LogShipper):
    """
    Ship logs to AWS S3 or S3-compatible storage.

    Requires: boto3 package
    """

    def __init__(self, config: ShipperConfig):
        super().__init__(config)
        self._client = None

    def _get_client(self):
        """Lazy-initialize S3 client."""
        if self._client is None:
            try:
                import boto3
            except ImportError:
                raise ImportError(
                    "boto3 package required for S3 shipping. "
                    "Install with: pip install boto3"
                )

            client_kwargs = {
                'region_name': self.config.s3_region,
            }

            if self.config.s3_access_key and self.config.s3_secret_key:
                client_kwargs['aws_access_key_id'] = self.config.s3_access_key
                client_kwargs['aws_secret_access_key'] = self.config.s3_secret_key

            if self.config.s3_endpoint_url:
                client_kwargs['endpoint_url'] = self.config.s3_endpoint_url

            self._client = boto3.client('s3', **client_kwargs)

        return self._client

    def _ship_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Ship events to S3."""
        client = self._get_client()

        # Create batch content
        batch_id = self._generate_batch_id(events)
        timestamp = datetime.utcnow()

        # Organize by date
        date_prefix = timestamp.strftime("%Y/%m/%d/")
        key = f"{self.config.s3_prefix}{date_prefix}{batch_id}.jsonl"

        # Format as JSON lines
        content = '\n'.join(json.dumps(event) for event in events)
        data = content.encode('utf-8')

        # Compress if enabled
        if self.config.compress:
            data = self._compress_data(data)
            key += '.gz'

        # Upload
        try:
            client.put_object(
                Bucket=self.config.s3_bucket,
                Key=key,
                Body=data,
                ContentType='application/x-ndjson',
                Metadata={
                    'batch-id': batch_id,
                    'event-count': str(len(events)),
                    'compressed': str(self.config.compress),
                }
            )
            logger.debug(f"Uploaded batch to s3://{self.config.s3_bucket}/{key}")
            return True
        except Exception as e:
            logger.error(f"S3 upload failed: {e}")
            return False


class GCSShipper(LogShipper):
    """
    Ship logs to Google Cloud Storage.

    Requires: google-cloud-storage package
    """

    def __init__(self, config: ShipperConfig):
        super().__init__(config)
        self._client = None
        self._bucket = None

    def _get_bucket(self):
        """Lazy-initialize GCS client and bucket."""
        if self._bucket is None:
            try:
                from google.cloud import storage
            except ImportError:
                raise ImportError(
                    "google-cloud-storage package required for GCS shipping. "
                    "Install with: pip install google-cloud-storage"
                )

            if self.config.gcs_credentials_file:
                self._client = storage.Client.from_service_account_json(
                    self.config.gcs_credentials_file
                )
            else:
                self._client = storage.Client()

            self._bucket = self._client.bucket(self.config.gcs_bucket)

        return self._bucket

    def _ship_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Ship events to GCS."""
        bucket = self._get_bucket()

        # Create batch content
        batch_id = self._generate_batch_id(events)
        timestamp = datetime.utcnow()

        # Organize by date
        date_prefix = timestamp.strftime("%Y/%m/%d/")
        blob_name = f"{self.config.gcs_prefix}{date_prefix}{batch_id}.jsonl"

        # Format as JSON lines
        content = '\n'.join(json.dumps(event) for event in events)
        data = content.encode('utf-8')

        # Compress if enabled
        if self.config.compress:
            data = self._compress_data(data)
            blob_name += '.gz'

        # Upload
        try:
            blob = bucket.blob(blob_name)
            blob.metadata = {
                'batch-id': batch_id,
                'event-count': str(len(events)),
                'compressed': str(self.config.compress),
            }
            blob.upload_from_string(data, content_type='application/x-ndjson')
            logger.debug(f"Uploaded batch to gs://{self.config.gcs_bucket}/{blob_name}")
            return True
        except Exception as e:
            logger.error(f"GCS upload failed: {e}")
            return False


class FileShipper(LogShipper):
    """
    Ship logs to local files (for testing or air-gapped environments).
    """

    def __init__(self, config: ShipperConfig):
        super().__init__(config)
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        """Ensure output directory exists."""
        Path(self.config.file_path).mkdir(parents=True, exist_ok=True)

    def _ship_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Ship events to local file."""
        batch_id = self._generate_batch_id(events)
        timestamp = datetime.utcnow()

        # Organize by date
        date_dir = Path(self.config.file_path) / timestamp.strftime("%Y/%m/%d")
        date_dir.mkdir(parents=True, exist_ok=True)

        filename = f"{batch_id}.jsonl"

        # Format as JSON lines
        content = '\n'.join(json.dumps(event) for event in events)
        data = content.encode('utf-8')

        # Compress if enabled
        if self.config.compress:
            data = self._compress_data(data)
            filename += '.gz'

        # Write file
        try:
            file_path = date_dir / filename
            with open(file_path, 'wb') as f:
                f.write(data)
            logger.debug(f"Wrote batch to {file_path}")
            return True
        except Exception as e:
            logger.error(f"File write failed: {e}")
            return False


class HTTPShipper(LogShipper):
    """
    Ship logs to HTTP endpoint.
    """

    def __init__(self, config: ShipperConfig):
        super().__init__(config)

    def _ship_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Ship events via HTTP POST."""
        try:
            import urllib.request
            import urllib.error
        except ImportError:
            raise ImportError("urllib required for HTTP shipping")

        # Prepare payload
        batch_id = self._generate_batch_id(events)
        payload = {
            'batch_id': batch_id,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_count': len(events),
            'events': events,
        }

        data = json.dumps(payload).encode('utf-8')

        # Compress if enabled
        if self.config.compress:
            data = self._compress_data(data)

        # Build request
        headers = {
            'Content-Type': 'application/json',
            'X-Batch-ID': batch_id,
            'X-Event-Count': str(len(events)),
        }

        if self.config.compress:
            headers['Content-Encoding'] = 'gzip'

        headers.update(self.config.http_headers)

        request = urllib.request.Request(
            self.config.http_endpoint,
            data=data,
            headers=headers,
            method='POST',
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.config.http_timeout
            ) as response:
                if response.status == 200:
                    return True
                else:
                    logger.warning(f"HTTP response: {response.status}")
                    return False
        except urllib.error.URLError as e:
            logger.error(f"HTTP request failed: {e}")
            return False


def create_shipper(config: ShipperConfig) -> LogShipper:
    """
    Factory function to create appropriate shipper based on protocol.

    Args:
        config: Shipper configuration

    Returns:
        Configured LogShipper instance
    """
    shippers = {
        ShipperProtocol.KAFKA: KafkaShipper,
        ShipperProtocol.S3: S3Shipper,
        ShipperProtocol.GCS: GCSShipper,
        ShipperProtocol.HTTP: HTTPShipper,
        ShipperProtocol.FILE: FileShipper,
    }

    shipper_class = shippers.get(config.protocol)
    if shipper_class is None:
        raise ValueError(f"Unknown protocol: {config.protocol}")

    return shipper_class(config)


if __name__ == '__main__':
    import tempfile

    print("Testing Log Shippers...")

    # Test with file shipper
    with tempfile.TemporaryDirectory() as tmpdir:
        config = ShipperConfig(
            protocol=ShipperProtocol.FILE,
            file_path=tmpdir,
            batch_size=3,
            compress=True,
        )

        shipper = create_shipper(config)
        shipper.start()

        # Add some events
        for i in range(5):
            shipper.add_event({
                'event_id': f'evt_{i}',
                'event_type': 'TEST_EVENT',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'details': f'Test event {i}',
            })

        # Flush and stop
        shipper.stop()

        # List files created
        print(f"\nFiles created in {tmpdir}:")
        for root, dirs, files in os.walk(tmpdir):
            for file in files:
                path = os.path.join(root, file)
                size = os.path.getsize(path)
                print(f"  {path} ({size} bytes)")

    print("\nLog shipper test complete.")
