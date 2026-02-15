from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import UploadResult


class ObjectStorageUploader:
    def __init__(self, object_storage_client: Any, namespace: str, bucket: str, prefix: str) -> None:
        self.object_storage_client = object_storage_client
        self.namespace = namespace
        self.bucket = bucket
        self.prefix = prefix.strip("/")

    def upload_file(self, file_path: Path, content_type: str) -> UploadResult:
        object_name = f"{self.prefix}/{file_path.name}" if self.prefix else file_path.name

        with file_path.open("rb") as stream:
            self.object_storage_client.put_object(
                namespace_name=self.namespace,
                bucket_name=self.bucket,
                object_name=object_name,
                put_object_body=stream,
                content_type=content_type,
            )

        return UploadResult(
            namespace=self.namespace,
            bucket=self.bucket,
            object_name=object_name,
            uri=f"oci://{self.bucket}@{self.namespace}/{object_name}",
        )
