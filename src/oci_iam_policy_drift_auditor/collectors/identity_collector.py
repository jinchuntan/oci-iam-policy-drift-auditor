from __future__ import annotations

from typing import Any

from oci.pagination import list_call_get_all_results

from ..models import CompartmentInfo


class IdentityCollector:
    def __init__(self, identity_client: Any) -> None:
        self.identity_client = identity_client

    def list_compartments(
        self,
        tenancy_ocid: str,
        root_compartment_ocid: str | None,
        include_subcompartments: bool,
    ) -> list[CompartmentInfo]:
        root_id = root_compartment_ocid or tenancy_ocid

        if root_compartment_ocid:
            root = self.identity_client.get_compartment(root_id).data
            root_name = root.name
        else:
            tenancy = self.identity_client.get_tenancy(tenancy_ocid).data
            root_name = tenancy.name

        compartments: list[CompartmentInfo] = [CompartmentInfo(id=root_id, name=root_name)]

        if include_subcompartments:
            if root_id == tenancy_ocid:
                response = list_call_get_all_results(
                    self.identity_client.list_compartments,
                    compartment_id=root_id,
                    compartment_id_in_subtree=True,
                    access_level="ACCESSIBLE",
                    lifecycle_state="ACTIVE",
                )
                for item in response.data:
                    compartments.append(CompartmentInfo(id=item.id, name=item.name))
            else:
                queue = [root_id]
                visited: set[str] = set()
                while queue:
                    parent_id = queue.pop(0)
                    if parent_id in visited:
                        continue
                    visited.add(parent_id)

                    response = list_call_get_all_results(
                        self.identity_client.list_compartments,
                        compartment_id=parent_id,
                        compartment_id_in_subtree=False,
                        access_level="ACCESSIBLE",
                        lifecycle_state="ACTIVE",
                    )
                    for item in response.data:
                        compartments.append(CompartmentInfo(id=item.id, name=item.name))
                        queue.append(item.id)
        else:
            response = list_call_get_all_results(
                self.identity_client.list_compartments,
                compartment_id=root_id,
                compartment_id_in_subtree=False,
                access_level="ACCESSIBLE",
                lifecycle_state="ACTIVE",
            )
            for item in response.data:
                compartments.append(CompartmentInfo(id=item.id, name=item.name))

        unique = {item.id: item for item in compartments}
        return sorted(unique.values(), key=lambda item: item.name.lower())

    def list_policies(self, compartment_ocid: str) -> list[Any]:
        return list_call_get_all_results(
            self.identity_client.list_policies,
            compartment_id=compartment_ocid,
        ).data

    def list_groups(self, tenancy_ocid: str) -> list[Any]:
        return list_call_get_all_results(
            self.identity_client.list_groups,
            compartment_id=tenancy_ocid,
        ).data

    def list_users(self, tenancy_ocid: str) -> list[Any]:
        return list_call_get_all_results(
            self.identity_client.list_users,
            compartment_id=tenancy_ocid,
        ).data

    def list_user_group_memberships_for_users(self, tenancy_ocid: str, user_ids: list[str]) -> list[Any]:
        memberships: list[Any] = []
        seen: set[str] = set()

        for user_id in user_ids:
            response = list_call_get_all_results(
                self.identity_client.list_user_group_memberships,
                compartment_id=tenancy_ocid,
                user_id=user_id,
            )
            for membership in response.data:
                membership_id = getattr(membership, "id", None)
                if membership_id and membership_id in seen:
                    continue
                if membership_id:
                    seen.add(membership_id)
                memberships.append(membership)

        return memberships

    def list_dynamic_groups(self, tenancy_ocid: str) -> list[Any]:
        return list_call_get_all_results(
            self.identity_client.list_dynamic_groups,
            compartment_id=tenancy_ocid,
        ).data
