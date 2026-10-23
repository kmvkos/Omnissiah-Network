"""Restore only a previously committed Omnissiah nft ACL, before wg0 startup."""
import json
import os
import sys

from vpn_acl_policy import LinuxACL, PolicyRejected


def main():
    node = os.environ.get("OMNISSIAH_NODE_NAME", "")
    addresses = tuple(filter(None, os.environ.get(
        "OMNISSIAH_PROTECTED_MANAGEMENT_IPV4", "").split(",")))
    if not node or not addresses:
        raise PolicyRejected("Missing trusted node identity or management list")
    result = LinuxACL(node_name=node, protected_ips=addresses).restore_on_boot()
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (PolicyRejected, OSError, ValueError) as exc:
        print("ACL boot restore FAILED: " + str(exc), file=sys.stderr)
        sys.exit(1)
