"""Pure Cognitor validation: no database, subprocess or WireGuard."""
import base64
from pathlib import Path
import sys
from types import SimpleNamespace as Node

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vpn_cognitor_validation import CognitorValidationError, validate_draft

KEY = base64.b64encode(bytes(range(32))).decode()
KEY2 = base64.b64encode(bytes(range(32, 64))).decode()
MAGOS = Node(id=3, role="Magos")
POOL = "10.77.0.0/24"


def draft(**overrides):
    data = dict(name="client_laptop", address="10.77.0.5/32",
                public_key=KEY, parent=MAGOS, pool=POOL,
                occupied_ips=["10.77.0.0/24", "10.77.0.2/32",
                              "10.77.0.3/32", "10.77.0.4/32"],
                occupied_names=["magos01", "magos02", "magos03"],
                occupied_keys=[KEY2])
    data.update(overrides)
    return validate_draft(**data)


def test_only_public_key_is_returned_with_unprovisioned_state():
    result = draft()
    assert result == {"name": "client_laptop", "address": "10.77.0.5/32",
                      "public_key": KEY, "parent_id": 3, "status": "draft"}
    assert "private_key" not in result
    assert "preshared_key" not in result


@pytest.mark.parametrize("value", [
    "10.77.0.2/32", "10.77.0.3/32", "10.77.0.4/32", "10.77.0.0/32",
    "10.77.0.255/32", "10.77.0.5/24", "0.0.0.0/0",
    "10.77.1.5/32", "10.77.0.5/33", "::1/128",
])
def test_reject_network_invalid_duplicate_and_non_host_addresses(value):
    with pytest.raises(CognitorValidationError):
        draft(address=value)


@pytest.mark.parametrize("value", ["client_1", "client-laptop", "A3"])
def test_valid_names(value):
    assert draft(name=value)["name"] == value


@pytest.mark.parametrize("value", ["", "../x", "client one", "1first", "x" * 51, "аdmin"])
def test_reject_bad_names(value):
    with pytest.raises(CognitorValidationError):
        draft(name=value)


def test_reject_name_duplicate_case_insensitive_and_key_duplicate():
    with pytest.raises(CognitorValidationError, match="занято"):
        draft(name="MAGOS01")
    with pytest.raises(CognitorValidationError, match="ключ уже"):
        draft(occupied_keys=[KEY])


def test_reject_omni_or_missing_parent():
    for parent in (None, Node(id=1, role="Omnissiah"), Node(id=4, role="Cognitor")):
        with pytest.raises(CognitorValidationError, match="только Magos"):
            draft(parent=parent)


@pytest.mark.parametrize("key", [None, "not-a-key", "A" * 44, KEY[:-1], KEY + "X", " "])
def test_reject_malformed_public_keys(key):
    with pytest.raises(CognitorValidationError):
        draft(public_key=key)


def test_duplicate_persisted_client_address_rejected():
    with pytest.raises(CognitorValidationError, match="уже используется"):
        draft(occupied_ips=["10.77.0.5/32"])
