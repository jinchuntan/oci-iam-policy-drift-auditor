from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def _to_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _to_int(value: str | None, default: int) -> int:
    if value is None or value.strip() == "":
        return default
    return int(value)


@dataclass(frozen=True)
class AppConfig:
    oci_config_file: str
    oci_config_profile: str
    oci_region: str | None
    root_compartment_ocid: str | None
    include_subcompartments: bool
    audit_lookback_hours: int
    output_dir: Path
    object_storage_namespace: str | None
    object_storage_bucket: str | None
    object_storage_prefix: str
    auto_discover_bucket: bool
    fail_on_upload_error: bool

    @classmethod
    def from_env(cls) -> "AppConfig":
        load_dotenv(override=False)

        config_file_default = str(Path.home() / ".oci" / "config")

        oci_config_file = os.getenv("OCI_CONFIG_FILE", "").strip() or config_file_default
        oci_config_profile = os.getenv("OCI_CONFIG_PROFILE", "").strip() or "DEFAULT"

        return cls(
            oci_config_file=oci_config_file,
            oci_config_profile=oci_config_profile,
            oci_region=os.getenv("OCI_REGION", "").strip() or None,
            root_compartment_ocid=os.getenv("OCI_ROOT_COMPARTMENT_OCID", "").strip() or None,
            include_subcompartments=_to_bool(os.getenv("OCI_INCLUDE_SUBCOMPARTMENTS"), True),
            audit_lookback_hours=_to_int(os.getenv("OCI_AUDIT_LOOKBACK_HOURS"), 24),
            output_dir=Path(os.getenv("OCI_OUTPUT_DIR", "output")),
            object_storage_namespace=os.getenv("OCI_OBJECT_STORAGE_NAMESPACE", "").strip() or None,
            object_storage_bucket=os.getenv("OCI_OBJECT_STORAGE_BUCKET", "").strip() or None,
            object_storage_prefix=os.getenv("OCI_OBJECT_STORAGE_PREFIX", "iam-policy-drift-audit").strip("/"),
            auto_discover_bucket=_to_bool(os.getenv("OCI_AUTO_DISCOVER_BUCKET"), True),
            fail_on_upload_error=_to_bool(os.getenv("OCI_FAIL_ON_UPLOAD_ERROR"), True),
        )
