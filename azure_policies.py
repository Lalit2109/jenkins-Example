"""
Firewall Policy discovery helpers.

Enumerates Azure Firewall Policies across all subscriptions visible to the
current credential. Falls back to an empty list if Azure SDK is not available
or credentials are not configured.
"""

from typing import List, Dict


def list_firewall_policies() -> List[Dict]:
    """Return a catalog of firewall policies across subscriptions.

    Each item: {
        "id": str,
        "name": str,
        "subscription_id": str,
        "resource_group": str,
        "location": str
    }
    """
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore
        from azure.mgmt.resource import SubscriptionClient  # type: ignore
        from azure.mgmt.network import NetworkManagementClient  # type: ignore
    except Exception:
        # SDK not available in this environment
        return []

    policies: List[Dict] = []
    try:
        cred = DefaultAzureCredential()
        sub_client = SubscriptionClient(cred)
        for sub in sub_client.subscriptions.list():
            sub_id = sub.subscription_id
            net = NetworkManagementClient(cred, sub_id)
            for p in net.firewall_policies.list_all():
                p_id = p.id or ""
                rg = ""
                try:
                    rg = p_id.split("/resourceGroups/")[1].split("/")[0]
                except Exception:
                    rg = ""
                policies.append({
                    "id": p_id,
                    "name": p.name,
                    "subscription_id": sub_id,
                    "resource_group": rg,
                    "location": p.location,
                })
        policies.sort(key=lambda x: (x["subscription_id"], x["resource_group"], x["name"]))
        return policies
    except Exception:
        # In case of auth or permission issues, return empty for now
        return []


