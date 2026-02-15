from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CompartmentInfo:
    id: str
    name: str


@dataclass(frozen=True)
class UploadResult:
    namespace: str
    bucket: str
    object_name: str
    uri: str
