from __future__ import annotations

from abc import ABC, abstractmethod
import json
import os
from pathlib import Path
import re
from typing import Any

from cryptography.fernet import Fernet

PROJECT_SLUG_REGEX = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
SECRET_NAME_REGEX = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
RESERVED_NAMES = frozenset({"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "HOME", "SHELL"})
MAX_SECRET_VALUE_LENGTH = 4096
MAX_SECRETS_PER_PROJECT = 50


class SecretValidationError(ValueError):
    """Raised when secret project slug, name, or value violates security constraints."""
    pass


def validate_project_slug(project: str) -> None:
    if not project or not PROJECT_SLUG_REGEX.match(project):
        raise SecretValidationError(
            f"Invalid project slug '{project}'. Must match ^[a-z0-9][a-z0-9-]{{0,40}}$"
        )


def validate_secret_name(name: str) -> None:
    if not name or not SECRET_NAME_REGEX.match(name):
        raise SecretValidationError(
            f"Invalid secret name '{name}'. Must match ^[A-Z][A-Z0-9_]{{0,63}}$"
        )
    if name in RESERVED_NAMES:
        raise SecretValidationError(
            f"Secret name '{name}' is reserved and cannot be used"
        )


def validate_secret_value(value: str) -> None:
    # Important: Never echo the value back in error messages
    if not isinstance(value, str):
        raise SecretValidationError("Secret value must be a string")
    if len(value) > MAX_SECRET_VALUE_LENGTH:
        raise SecretValidationError(
            f"Secret value exceeds maximum allowed length of {MAX_SECRET_VALUE_LENGTH} characters"
        )
    if "\n" in value or "\r" in value:
        raise SecretValidationError("Secret value must not contain newline characters")


class SecretsStore(ABC):
    """Abstract interface for project-scoped secrets storage."""

    @abstractmethod
    def put(self, project: str, name: str, value: str) -> None:
        """Store an encrypted secret for a project."""
        pass

    @abstractmethod
    def get_all(self, project: str) -> dict[str, str]:
        """Retrieve all decrypted secrets for a project as name:value."""
        pass

    @abstractmethod
    def delete(self, project: str, name: str) -> bool:
        """Delete a secret for a project. Returns True if deleted, False if not found."""
        pass

    @abstractmethod
    def list_names(self, project: str) -> list[str]:
        """List all secret names for a project without returning values."""
        pass


class LocalEncryptedStore(SecretsStore):
    """Local encrypted secrets store using Fernet symmetric encryption.
    
    Master key from SECRETS_MASTER_KEY env, or auto-generated at backend/.secrets_master.key (0600).
    Ciphertexts stored in backend/.secrets_store.json (0600).
    """

    def __init__(
        self,
        master_key: str | bytes | None = None,
        key_file_path: Path | str | None = None,
        store_file_path: Path | str | None = None,
    ):
        base_dir = Path(__file__).resolve().parent
        self.key_file_path = Path(key_file_path) if key_file_path else base_dir / ".secrets_master.key"
        self.store_file_path = Path(store_file_path) if store_file_path else base_dir / ".secrets_store.json"
        
        self.master_key = self._resolve_master_key(master_key)
        self.cipher = Fernet(self.master_key)

    def _resolve_master_key(self, explicit_key: str | bytes | None) -> bytes:
        if explicit_key:
            return explicit_key.encode("utf-8") if isinstance(explicit_key, str) else explicit_key

        env_key = os.getenv("SECRETS_MASTER_KEY", "").strip()
        if env_key:
            return env_key.encode("utf-8")

        if self.key_file_path.exists():
            key_data = self.key_file_path.read_bytes().strip()
            if key_data:
                return key_data

        # Generate new key and save with 0600 permissions
        new_key = Fernet.generate_key()
        self.key_file_path.parent.mkdir(parents=True, exist_ok=True)
        # Write with 0600 permissions
        fd = os.open(str(self.key_file_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "wb") as f:
            f.write(new_key)
        os.chmod(str(self.key_file_path), 0o600)
        return new_key

    def _load_data(self) -> dict[str, dict[str, str]]:
        if not self.store_file_path.exists():
            return {}
        try:
            with open(self.store_file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return {}
                return json.loads(content)
        except Exception:
            return {}

    def _save_data(self, data: dict[str, dict[str, str]]) -> None:
        self.store_file_path.parent.mkdir(parents=True, exist_ok=True)
        temp_file = self.store_file_path.with_suffix(".tmp")
        fd = os.open(str(temp_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.chmod(str(temp_file), 0o600)
        os.replace(str(temp_file), str(self.store_file_path))
        os.chmod(str(self.store_file_path), 0o600)

    def put(self, project: str, name: str, value: str) -> None:
        validate_project_slug(project)
        validate_secret_name(name)
        validate_secret_value(value)

        data = self._load_data()
        proj_data = data.setdefault(project, {})
        if name not in proj_data and len(proj_data) >= MAX_SECRETS_PER_PROJECT:
            raise SecretValidationError(
                f"Maximum limit of {MAX_SECRETS_PER_PROJECT} secrets reached for project '{project}'"
            )

        encrypted = self.cipher.encrypt(value.encode("utf-8")).decode("utf-8")
        proj_data[name] = encrypted
        self._save_data(data)

    def get_all(self, project: str) -> dict[str, str]:
        validate_project_slug(project)
        data = self._load_data()
        proj_data = data.get(project, {})
        result: dict[str, str] = {}
        for k, v in proj_data.items():
            try:
                decrypted = self.cipher.decrypt(v.encode("utf-8")).decode("utf-8")
                result[k] = decrypted
            except Exception:
                # Corrupted ciphertext
                continue
        return result

    def delete(self, project: str, name: str) -> bool:
        validate_project_slug(project)
        validate_secret_name(name)
        data = self._load_data()
        if project in data and name in data[project]:
            del data[project][name]
            if not data[project]:
                del data[project]
            self._save_data(data)
            return True
        return False

    def list_names(self, project: str) -> list[str]:
        validate_project_slug(project)
        data = self._load_data()
        return sorted(list(data.get(project, {}).keys()))


class SSMStore(SecretsStore):
    """AWS Systems Manager Parameter Store secrets implementation.
    
    Uses default credential chain only (IAM role or AWS_PROFILE).
    Path convention: /secure-deploy/<project>/<NAME>
    """

    def __init__(self, region_name: str | None = None, client: Any | None = None):
        self.region_name = region_name or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
        if client is not None:
            self._client = client
        else:
            import boto3
            # NEVER read access keys from code, DB, or API input. Use default credential chain only.
            self._client = boto3.client("ssm", region_name=self.region_name)

    def _param_name(self, project: str, name: str) -> str:
        return f"/secure-deploy/{project}/{name}"

    def put(self, project: str, name: str, value: str) -> None:
        validate_project_slug(project)
        validate_secret_name(name)
        validate_secret_value(value)

        current_names = self.list_names(project)
        if name not in current_names and len(current_names) >= MAX_SECRETS_PER_PROJECT:
            raise SecretValidationError(
                f"Maximum limit of {MAX_SECRETS_PER_PROJECT} secrets reached for project '{project}'"
            )

        self._client.put_parameter(
            Name=self._param_name(project, name),
            Value=value,
            Type="SecureString",
            Overwrite=True,
        )

    def get_all(self, project: str) -> dict[str, str]:
        validate_project_slug(project)
        base_path = f"/secure-deploy/{project}/"
        results: dict[str, str] = {}
        next_token: str | None = None

        while True:
            kwargs: dict[str, Any] = {
                "Path": base_path,
                "WithDecryption": True,
                "Recursive": True,
            }
            if next_token:
                kwargs["NextToken"] = next_token

            response = self._client.get_parameters_by_path(**kwargs)
            for param in response.get("Parameters", []):
                param_name = param.get("Name", "")
                secret_name = param_name.rsplit("/", 1)[-1]
                results[secret_name] = param.get("Value", "")

            next_token = response.get("NextToken") if isinstance(response, dict) else None
            if not next_token or not isinstance(next_token, str):
                break

        return results

    def delete(self, project: str, name: str) -> bool:
        validate_project_slug(project)
        validate_secret_name(name)
        try:
            self._client.delete_parameter(Name=self._param_name(project, name))
            return True
        except self._client.exceptions.ParameterNotFound:
            return False
        except Exception as e:
            # Check for ParameterNotFound in error response
            if "ParameterNotFound" in str(e):
                return False
            raise

    def list_names(self, project: str) -> list[str]:
        validate_project_slug(project)
        base_path = f"/secure-deploy/{project}/"
        names: list[str] = []
        next_token: str | None = None

        while True:
            kwargs: dict[str, Any] = {
                "Path": base_path,
                "WithDecryption": False,
                "Recursive": True,
            }
            if next_token:
                kwargs["NextToken"] = next_token

            response = self._client.get_parameters_by_path(**kwargs)
            for param in response.get("Parameters", []):
                param_name = param.get("Name", "")
                secret_name = param_name.rsplit("/", 1)[-1]
                names.append(secret_name)

            next_token = response.get("NextToken") if isinstance(response, dict) else None
            if not next_token or not isinstance(next_token, str):
                break

        return sorted(names)


def get_secrets_store() -> SecretsStore:
    """Factory selecting the active SecretsStore based on SECRETS_BACKEND env var."""
    backend = os.getenv("SECRETS_BACKEND", "local").strip().lower()
    if backend == "ssm":
        return SSMStore()
    return LocalEncryptedStore()
