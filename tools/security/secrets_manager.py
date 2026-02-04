"""
Secrets Manager - Encrypted credential storage.

Supports multiple secret providers:
- Local encrypted (Fernet with machine-derived key) - FREE
- HashiCorp Vault
- AWS Secrets Manager
- Environment variables (fallback)

The default local encryption uses:
- Machine-specific key derivation (machine ID + salt)
- Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256)
- No external dependencies beyond 'cryptography' library

ALL FEATURES ARE FREE - no paid services required.
"""

import os
import json
import hashlib
import platform
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class SecretValue:
    """A retrieved secret value."""
    key: str
    value: str
    provider: str
    cached: bool = False


class SecretsProvider(ABC):
    """Abstract base class for secrets providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        pass

    @abstractmethod
    def get(self, key: str) -> Optional[str]:
        """Get a secret value."""
        pass

    @abstractmethod
    def set(self, key: str, value: str) -> bool:
        """Set a secret value."""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a secret."""
        pass

    @abstractmethod
    def list_keys(self) -> List[str]:
        """List available secret keys."""
        pass

    def is_available(self) -> bool:
        """Check if provider is available."""
        return True


class EnvironmentProvider(SecretsProvider):
    """Fallback provider that reads from environment variables."""

    @property
    def name(self) -> str:
        return "environment"

    def get(self, key: str) -> Optional[str]:
        return os.environ.get(key)

    def set(self, key: str, value: str) -> bool:
        # Can't persist env vars, but set for current process
        os.environ[key] = value
        return True

    def delete(self, key: str) -> bool:
        if key in os.environ:
            del os.environ[key]
            return True
        return False

    def list_keys(self) -> List[str]:
        # Return keys that look like secrets
        secret_patterns = ['KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'CREDENTIAL']
        return [k for k in os.environ.keys()
                if any(p in k.upper() for p in secret_patterns)]


class LocalEncryptedProvider(SecretsProvider):
    """
    Local encrypted storage using Fernet.

    Uses machine-specific key derivation:
    - Machine UUID (or hostname + platform as fallback)
    - Salt stored alongside encrypted data
    - PBKDF2 key derivation with 100,000 iterations

    This is FREE - uses only the 'cryptography' library.
    """

    def __init__(self, storage_path: str = None):
        """
        Initialize local encrypted storage.

        Args:
            storage_path: Path to store encrypted secrets
        """
        self.storage_path = Path(storage_path or ".moltbook/secrets.enc")
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

        self._fernet = None
        self._data = {}
        self._load()

    @property
    def name(self) -> str:
        return "local_encrypted"

    def _get_machine_id(self) -> str:
        """Get a unique machine identifier."""
        # Try to get machine UUID
        try:
            # Linux
            if Path("/etc/machine-id").exists():
                return Path("/etc/machine-id").read_text().strip()
            # macOS
            import subprocess
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True
            )
            for line in result.stdout.split("\n"):
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2]
        except Exception:
            pass

        # Fallback: hostname + platform
        return f"{platform.node()}-{platform.system()}-{platform.machine()}"

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key from machine ID."""
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.backends import default_backend
            import base64

            machine_id = self._get_machine_id().encode()

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )

            key = base64.urlsafe_b64encode(kdf.derive(machine_id))
            return key

        except ImportError:
            logger.warning("cryptography library not installed - secrets will not be encrypted")
            return None

    def _get_fernet(self):
        """Get or create Fernet instance."""
        if self._fernet:
            return self._fernet

        try:
            from cryptography.fernet import Fernet
            import base64

            # Load or create salt
            salt_path = self.storage_path.parent / ".salt"
            if salt_path.exists():
                salt = salt_path.read_bytes()
            else:
                salt = os.urandom(16)
                salt_path.write_bytes(salt)
                # Make salt file readable only by owner
                os.chmod(salt_path, 0o600)

            key = self._derive_key(salt)
            if key:
                self._fernet = Fernet(key)

        except ImportError:
            logger.warning("cryptography library not installed")

        return self._fernet

    def _load(self):
        """Load encrypted data from disk."""
        if not self.storage_path.exists():
            self._data = {}
            return

        fernet = self._get_fernet()
        if not fernet:
            # Fall back to plaintext (not recommended)
            try:
                self._data = json.loads(self.storage_path.read_text())
            except Exception:
                self._data = {}
            return

        try:
            encrypted = self.storage_path.read_bytes()
            decrypted = fernet.decrypt(encrypted)
            self._data = json.loads(decrypted.decode())
        except Exception as e:
            logger.error(f"Failed to load secrets: {e}")
            self._data = {}

    def _save(self):
        """Save encrypted data to disk."""
        fernet = self._get_fernet()
        data_bytes = json.dumps(self._data).encode()

        if fernet:
            encrypted = fernet.encrypt(data_bytes)
            self.storage_path.write_bytes(encrypted)
        else:
            # Fall back to plaintext (not recommended)
            self.storage_path.write_text(json.dumps(self._data))

        # Secure file permissions
        os.chmod(self.storage_path, 0o600)

    def get(self, key: str) -> Optional[str]:
        return self._data.get(key)

    def set(self, key: str, value: str) -> bool:
        self._data[key] = value
        self._save()
        return True

    def delete(self, key: str) -> bool:
        if key in self._data:
            del self._data[key]
            self._save()
            return True
        return False

    def list_keys(self) -> List[str]:
        return list(self._data.keys())

    def is_available(self) -> bool:
        try:
            from cryptography.fernet import Fernet
            return True
        except ImportError:
            return False


class VaultProvider(SecretsProvider):
    """HashiCorp Vault provider."""

    def __init__(self, url: str = None, token: str = None, path: str = "secret/data"):
        """
        Initialize Vault provider.

        Args:
            url: Vault server URL
            token: Vault token
            path: Secret path prefix
        """
        self.url = url or os.environ.get("VAULT_ADDR", "http://localhost:8200")
        self.token = token or os.environ.get("VAULT_TOKEN")
        self.path = path
        self._client = None

    @property
    def name(self) -> str:
        return "vault"

    def _get_client(self):
        """Get or create Vault client."""
        if self._client:
            return self._client

        try:
            import hvac
            self._client = hvac.Client(url=self.url, token=self.token)
            return self._client
        except ImportError:
            logger.warning("hvac library not installed - Vault provider unavailable")
            return None

    def get(self, key: str) -> Optional[str]:
        client = self._get_client()
        if not client:
            return None

        try:
            response = client.secrets.kv.read_secret_version(path=key, mount_point=self.path)
            return response['data']['data'].get('value')
        except Exception as e:
            logger.debug(f"Vault get failed for {key}: {e}")
            return None

    def set(self, key: str, value: str) -> bool:
        client = self._get_client()
        if not client:
            return False

        try:
            client.secrets.kv.create_or_update_secret(
                path=key,
                secret={'value': value},
                mount_point=self.path
            )
            return True
        except Exception as e:
            logger.error(f"Vault set failed for {key}: {e}")
            return False

    def delete(self, key: str) -> bool:
        client = self._get_client()
        if not client:
            return False

        try:
            client.secrets.kv.delete_metadata_and_all_versions(
                path=key, mount_point=self.path
            )
            return True
        except Exception:
            return False

    def list_keys(self) -> List[str]:
        client = self._get_client()
        if not client:
            return []

        try:
            response = client.secrets.kv.list_secrets(path="", mount_point=self.path)
            return response['data']['keys']
        except Exception:
            return []

    def is_available(self) -> bool:
        try:
            import hvac
            client = self._get_client()
            return client and client.is_authenticated()
        except Exception:
            return False


class AWSSecretsProvider(SecretsProvider):
    """AWS Secrets Manager provider."""

    def __init__(self, region: str = None, prefix: str = "moltbook/"):
        """
        Initialize AWS Secrets Manager provider.

        Args:
            region: AWS region
            prefix: Secret name prefix
        """
        self.region = region or os.environ.get("AWS_REGION", "us-east-1")
        self.prefix = prefix
        self._client = None

    @property
    def name(self) -> str:
        return "aws"

    def _get_client(self):
        """Get or create AWS client."""
        if self._client:
            return self._client

        try:
            import boto3
            self._client = boto3.client('secretsmanager', region_name=self.region)
            return self._client
        except ImportError:
            logger.warning("boto3 library not installed - AWS provider unavailable")
            return None

    def get(self, key: str) -> Optional[str]:
        client = self._get_client()
        if not client:
            return None

        try:
            response = client.get_secret_value(SecretId=f"{self.prefix}{key}")
            return response['SecretString']
        except Exception:
            return None

    def set(self, key: str, value: str) -> bool:
        client = self._get_client()
        if not client:
            return False

        try:
            # Try to update existing
            client.put_secret_value(
                SecretId=f"{self.prefix}{key}",
                SecretString=value
            )
            return True
        except client.exceptions.ResourceNotFoundException:
            # Create new
            try:
                client.create_secret(
                    Name=f"{self.prefix}{key}",
                    SecretString=value
                )
                return True
            except Exception:
                return False
        except Exception:
            return False

    def delete(self, key: str) -> bool:
        client = self._get_client()
        if not client:
            return False

        try:
            client.delete_secret(
                SecretId=f"{self.prefix}{key}",
                ForceDeleteWithoutRecovery=True
            )
            return True
        except Exception:
            return False

    def list_keys(self) -> List[str]:
        client = self._get_client()
        if not client:
            return []

        try:
            paginator = client.get_paginator('list_secrets')
            keys = []
            for page in paginator.paginate():
                for secret in page['SecretList']:
                    name = secret['Name']
                    if name.startswith(self.prefix):
                        keys.append(name[len(self.prefix):])
            return keys
        except Exception:
            return []

    def is_available(self) -> bool:
        try:
            import boto3
            return True
        except ImportError:
            return False


class SecretsManager:
    """
    Unified secrets management with multiple provider support.

    Tries providers in order until a secret is found.
    Default order: local_encrypted -> vault -> aws -> environment

    Usage:
        manager = SecretsManager()
        api_key = manager.get("MOLTBOOK_API_KEY")
        manager.set("MY_SECRET", "value123")
    """

    def __init__(self, providers: List[SecretsProvider] = None,
                 cache_enabled: bool = True):
        """
        Initialize the secrets manager.

        Args:
            providers: List of providers to use (in priority order)
            cache_enabled: Whether to cache retrieved secrets in memory
        """
        if providers:
            self.providers = providers
        else:
            # Default provider chain
            self.providers = [
                LocalEncryptedProvider(),
                EnvironmentProvider(),
            ]
            # Add optional providers if available
            vault = VaultProvider()
            if vault.is_available():
                self.providers.insert(1, vault)
            aws = AWSSecretsProvider()
            if aws.is_available():
                self.providers.insert(1, aws)

        self.cache_enabled = cache_enabled
        self._cache: Dict[str, str] = {}

    def get(self, key: str, required: bool = False, default: str = None) -> Optional[str]:
        """
        Get a secret value.

        Args:
            key: Secret key name
            required: Raise error if not found
            default: Default value if not found

        Returns:
            Secret value or default
        """
        # Check cache first
        if self.cache_enabled and key in self._cache:
            return self._cache[key]

        # Try each provider
        for provider in self.providers:
            try:
                value = provider.get(key)
                if value is not None:
                    if self.cache_enabled:
                        self._cache[key] = value
                    logger.debug(f"Secret {key} retrieved from {provider.name}")
                    return value
            except Exception as e:
                logger.debug(f"Provider {provider.name} failed for {key}: {e}")

        if required:
            raise KeyError(f"Required secret not found: {key}")

        return default

    def set(self, key: str, value: str, provider_name: str = None) -> bool:
        """
        Set a secret value.

        Args:
            key: Secret key name
            value: Secret value
            provider_name: Specific provider to use (default: first writable)

        Returns:
            True if successful
        """
        # Update cache
        if self.cache_enabled:
            self._cache[key] = value

        # Find provider
        if provider_name:
            for provider in self.providers:
                if provider.name == provider_name:
                    return provider.set(key, value)
            raise ValueError(f"Provider not found: {provider_name}")

        # Use first provider (usually local_encrypted)
        for provider in self.providers:
            try:
                if provider.set(key, value):
                    logger.info(f"Secret {key} stored in {provider.name}")
                    return True
            except Exception:
                continue

        return False

    def delete(self, key: str) -> bool:
        """
        Delete a secret from all providers.

        Args:
            key: Secret key name

        Returns:
            True if deleted from at least one provider
        """
        # Clear cache
        self._cache.pop(key, None)

        deleted = False
        for provider in self.providers:
            try:
                if provider.delete(key):
                    deleted = True
            except Exception:
                continue

        return deleted

    def list_keys(self) -> List[str]:
        """List all available secret keys across providers."""
        keys = set()
        for provider in self.providers:
            try:
                keys.update(provider.list_keys())
            except Exception:
                continue
        return sorted(keys)

    def clear_cache(self):
        """Clear the in-memory secret cache."""
        self._cache.clear()

    def get_provider_status(self) -> Dict[str, bool]:
        """Get availability status of all providers."""
        return {
            provider.name: provider.is_available()
            for provider in self.providers
        }


# Global instance
_secrets_manager: Optional[SecretsManager] = None


def get_secrets_manager() -> SecretsManager:
    """Get or create the global secrets manager."""
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager


def get_secret(key: str, required: bool = False, default: str = None) -> Optional[str]:
    """
    Get a secret value.

    Args:
        key: Secret key
        required: Raise error if not found
        default: Default value

    Returns:
        Secret value
    """
    return get_secrets_manager().get(key, required=required, default=default)


def set_secret(key: str, value: str) -> bool:
    """
    Set a secret value.

    Args:
        key: Secret key
        value: Secret value

    Returns:
        True if successful
    """
    return get_secrets_manager().set(key, value)
