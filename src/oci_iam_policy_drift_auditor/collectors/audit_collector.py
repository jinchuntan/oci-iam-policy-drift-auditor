from __future__ import annotations

from datetime import datetime
from typing import Any

from oci.pagination import list_call_get_all_results


class AuditCollector:
    def __init__(self, audit_client: Any) -> None:
        self.audit_client = audit_client

    def list_events(
        self,
        compartment_ocid: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[Any]:
        return list_call_get_all_results(
            self.audit_client.list_events,
            compartment_id=compartment_ocid,
            start_time=start_time,
            end_time=end_time,
        ).data
