import asyncio
from types import SimpleNamespace

import pytest

from ansible_collections.velocloud.api.plugins.module_utils.topology import (
    BgpInput,
    RoutedInterfaceInput,
    WanLinkSettingsInput,
    apply_bgp,
    apply_routed_interfaces,
    apply_wan_link_settings,
)


class _Resolvers:
    async def resolve(self, _identity, name):
        return SimpleNamespace(segment_id={"Global Segment": 0, "Corp": 1}[name])


class RecordingPipeline:
    def __init__(self):
        self.patches = []
        self.resolvers = _Resolvers()

    async def apply(self, state, module, patch):
        self.patches.append({"module": module, "patch": patch})
        return state


def _routed(**ri):
    pipeline = RecordingPipeline()
    asyncio.run(
        apply_routed_interfaces(pipeline, object(), [RoutedInterfaceInput(**ri)])
    )
    return pipeline.patches[0]["patch"]["routed_interfaces"][ri["name"]]


def _ge6(**sub):
    return {
        "name": "GE6",
        "addressing": {"type": "STATIC", "cidr": "10.1.100.1/24"},
        "subinterfaces": [
            {
                "subinterface_id": 102,
                "vlan_id": 102,
                "segment_id": "Corp",
                "addressing": {"type": "STATIC", "cidr": "10.1.102.1/24"},
                **sub,
            }
        ],
    }


def test_undeclared_subinterface_fields_are_forwarded():
    sub = _routed(**_ge6(trusted=True, rpf="LOOSE"))["subinterfaces"][0]
    assert sub["trusted"] is True
    assert sub["rpf"] == "LOOSE"
    assert sub["segment_id"] == 1
    assert sub["addressing"]["cidr_ip"] == "10.1.102.1"


def test_nested_subinterface_fields_are_forwarded():
    sub = _routed(**_ge6(ospf={"enabled": True, "cost": 5}))["subinterfaces"][0]
    assert sub["ospf"] == {"enabled": True, "cost": 5}


def test_unset_subinterface_fields_are_not_sent():
    sub = _routed(**_ge6())["subinterfaces"][0]
    assert "trusted" not in sub
    assert "rpf" not in sub


def test_undeclared_parent_fields_are_forwarded():
    iface = _routed(name="GE7", trusted=True, rpf="DISABLED")
    assert iface["trusted"] is True
    assert iface["rpf"] == "DISABLED"


def test_camel_case_keys_are_accepted():
    sub = _routed(**_ge6(pingResponse=False))["subinterfaces"][0]
    assert sub["ping_response"] is False


def test_bad_value_names_the_interface():
    with pytest.raises(ValueError, match=r"GE6 subinterface 102.*rpf"):
        _routed(**_ge6(rpf="LOSE"))


def test_misspelled_subinterface_key_is_refused():
    with pytest.raises(ValueError, match=r"GE6 subinterface 102.*'rfp'"):
        _routed(**_ge6(rfp="LOOSE"))


def test_misspelled_nested_key_is_refused():
    with pytest.raises(ValueError, match=r"'ospf\.helo_timer'"):
        _routed(**_ge6(ospf={"helo_timer": 5}))


def test_misspelled_parent_key_is_refused():
    with pytest.raises(ValueError, match=r"GE7.*'trustd'"):
        _routed(name="GE7", trustd=True)


def test_misspelled_wan_link_key_is_refused():
    spec = WanLinkSettingsInput(name="ISP1", interfaces=["GE3"], encrypt_ovrlay=False)
    with pytest.raises(ValueError, match=r"ISP1.*'encrypt_ovrlay'"):
        asyncio.run(apply_wan_link_settings(RecordingPipeline(), object(), [spec]))


def test_misspelled_bgp_neighbor_key_is_refused():
    spec = BgpInput(
        asn="65001",
        neighbors=[
            {"neighbor_ip": "10.0.0.1", "neighbor_as": "65002", "defualt_route": True}
        ],
    )
    with pytest.raises(ValueError, match=r"10\.0\.0\.1.*'defualt_route'"):
        asyncio.run(apply_bgp(RecordingPipeline(), object(), spec))
