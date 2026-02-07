"""
Secrets Manager - Abstraction layer for secrets management.
"""

import os
from abc import ABC, abstractmethod
from typing import Optional


class SecretsError(Exception):
    pass


class SecretsBackend(ABC):
    @abstractmethod
    def get_secret(self, name: str) -> Optional[str]:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass


class EnvironmentBackend(SecretsBackend):
    def get_secret(self, name: str) -> Optional[str]:
        return os.getenv(name)

    def is_available(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return "environment"


class VaultBackend(SecretsBackend):
    def __init__(self):
        self._client = None
        self._vault_addr = os.getenv("VAULT_ADDR")
        self._vault_token = self._get_vault_token()

    def _get_vault_token(self) -> Optional[str]:
        token_path = os.getenv("VAULT_TOKEN_PATH", "/run/secrets/vault-token")
        if os.path.exists(token_path):
            try:
                with open(token_path, "r") as f:
                    return f.read().strip()
            except Exception:
                pass
        return os.getenv("VAULT_TOKEN")

    def get_secret(self, name: str) -> Optional[str]:
        if not self.is_available():
            return None
        try:
            import hvac
            client = hvac.Client(url=self._vault_addr, token=self._vault_token)
            secret_path = os.getenv("VAULT_SECRET_PATH", "secret/data/tines")
            response = client.secrets.kv.v2.read_secret_version(
                path=secret_path.replace("secret/data/", "")
            )
            if response and "data" in response and "data" in response["data"]:
                return response["data"]["data"].get(name)
        except Exception:
            pass
        return None

    def is_available(self) -> bool:
        return bool(self._vault_addr and self._vault_token)

    @property
    def name(self) -> str:
        return "vault"


class AWSSecretsBackend(SecretsBackend):
    def __init__(self):
        self._client = None
        self._region = os.getenv("AWS_SECRETS_REGION", os.getenv("AWS_REGION"))
        self._secret_name = os.getenv("AWS_SECRET_NAME", "tines/api-credentials")

    def get_secret(self, name: str) -> Optional[str]:
        if not self.is_available():
            return None
        try:
            import json
            import boto3
            client = boto3.client("secretsmanager", region_name=self._region)
            response = client.get_secret_value(SecretId=self._secret_name)
            if "SecretString" in response:
                secrets = json.loads(response["SecretString"])
                return secrets.get(name)
        except Exception:
            pass
        return None

    def is_available(self) -> bool:
        return bool(self._region)

    @property
    def name(self) -> str:
        return "aws"


class SecretsManager:
    _instance: Optional["SecretsManager"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._backends: list[SecretsBackend] = []
        self._cache: dict[str, str] = {}
        self._active_backend: Optional[str] = None
        self._init_backends()
        self._initialized = True

    def _init_backends(self) -> None:
        preferred = os.getenv("SECRETS_MANAGER", "env").lower()
        if preferred == "vault":
            self._backends.append(VaultBackend())
        elif preferred == "aws":
            self._backends.append(AWSSecretsBackend())
        self._backends.append(EnvironmentBackend())
        for backend in self._backends:
            if backend.is_available():
                self._active_backend = backend.name
                break

    def get_secret(self, name: str, required: bool = False) -> Optional[str]:
        if name in self._cache:
            return self._cache[name]
        for backend in self._backends:
            if not backend.is_available():
                continue
            value = backend.get_secret(name)
            if value:
                self._cache[name] = value
                return value
        if required:
            raise SecretsError(f"Required secret '{name}' not found")
        return None

    def get_tines_tenant(self) -> str:
        return self.get_secret("TINES_TENANT", required=True)

    def get_tines_token(self) -> str:
        return self.get_secret("TINES_API_TOKEN", required=True)

    def clear_cache(self) -> None:
        self._cache.clear()

    def get_status(self) -> dict:
        return {
            "active_backend": self._active_backend,
            "backends": [{"name": b.name, "available": b.is_available()} for b in self._backends],
            "cached_keys": list(self._cache.keys()),
        }


def get_secret(name: str, required: bool = False) -> Optional[str]:
    return SecretsManager().get_secret(name, required)
