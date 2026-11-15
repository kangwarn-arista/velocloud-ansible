# Copyright: (c) 2026, Kangwarn Chinthammit
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Topology specs and apply helpers for declarative VeloCloud provisioning.

Pydantic input models and helpers that translate playbook input into VCO
config-module patches used by the velocloud.api modules.

Public surface:

  Pydantic input specs:
    SegmentSpec, ProfileSpec, ProfileFirewallSpec,
    WanLinkInput, WanLinkSettingsInput, WanAddressing,
    RoutedInterfaceInput, RoutedInterfaceAddressing, SubInterfaceInput,
    DhcpServerInput, SwitchedInterfaceInput, InterfaceConfig, VlanInput,
    BgpInput, BgpNeighborInput, HaNodeInput, HaInput,
    StaticRouteInput, RoutesInput, SegmentConfigInput,
    LoopbackOspfInput, LoopbackInterfaceInput,
    BizPolicySlaInput, BizPolicyQosInput, BizPolicyMatchInput, BizPolicyActionInput, BizPolicyRuleInput,
    EdgeSite, EdgeSpec, TopologyConfig

  CIDR helpers:
    split_cidr, prefix_to_netmask, addressing_patch

  Apply functions (ConfigPipeline patches):
    apply_wan_links, apply_routed_interfaces, apply_switched_interfaces,
    apply_vlans, apply_wan_link_settings, apply_bgp, apply_routes, apply_ha,
    apply_loopback_interfaces, apply_bizpolicy

  Resource orchestrators:
    ensure_segment, create_profile_only, attach_segments_to_profile,
    enable_console_firewall, ensure_profile, create_edge_only, ensure_edge
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from loguru import logger
from pydantic import BaseModel, Field, model_validator
from pydantic_core import MISSING

from pyvelo.client import VcoClient
from pyvelo.client.enums.edge import ModelNumber
from pyvelo.client.enums.configuration import ConfigurationModuleName
from pyvelo.client.models.configuration.device_settings.root import (
    EdgeHaSettings,
    LoopbackInterface,
)
from pyvelo.client.enums.enterprise import NetworkSegmentType
from pyvelo.client.models.configuration.common import SegmentMetadata
from pyvelo.client.models.configuration.device_settings.common import (
    IPv4AddressingType,
    WanOverlay,
)
from pyvelo.client.models.configuration.device_settings.lan import LanPortMode
from pyvelo.client.models.configuration.device_settings.refs import (
    DeviceSettingsRefs,
    DeviceSettingsSegmentRef,
)
from pyvelo.client.models.configuration.device_settings.segment import (
    BgpNeighbor,
    CssProviderRef,
    DeviceSegment,
    DnsProvider,
    DynamicVpnConfig,
    EdgeToEdgeDetail,
    SegmentAuthentication,
    SegmentBfd,
    SegmentBgp,
    SegmentCss,
    SegmentDns,
    SegmentEdgeDirect,
    SegmentHandoffGateways,
    SegmentHubInterconnect,
    SegmentMulticast,
    SegmentNat,
    SegmentNetflow,
    SegmentOspf,
    SegmentSyslog,
    SegmentVpn,
    StaticRoute,
)
from pyvelo.client.models.configuration.firewall.rule_action import OutboundRuleAction
from pyvelo.client.models.configuration.firewall.rule_match import OutboundRuleMatch
from pyvelo.client.models.configuration.firewall.rules import FirewallOutboundRule
from pyvelo.client.models.configuration.firewall.segment import FirewallSegment
from pyvelo.client.models.configuration.firewall.services import (
    ConsoleService,
    FirewallServices,
)
from pyvelo.client.models.configuration.qos.rule import (
    QosRule,
    QosRuleAction,
    QosRuleMatch,
    RouteAction,
)
from pyvelo.client.models.configuration.qos.scheduler import QosScheduler, QosSettings
from pyvelo.client.models.configuration.qos.segment import CosMapping, QosSegment
from pyvelo.client.models.configuration.wan.link import WanLink
from pyvelo.client.models.enterprise import NetworkSegmentData
from pyvelo.client.schemas.edge import CreateEdge, CreateEdgeResult, Site
from pyvelo.client.schemas.enterprise import (
    GetEnterpriseEdges,
    GetEnterpriseNetworkSegments,
    InsertEnterpriseNetworkSegment,
)
from pyvelo.client.schemas.profiles import CreateProfile, GetEnterpriseConfigurations
from pyvelo_intent.config.pipeline import ConfigPipeline
from pyvelo_intent.config.state import ConfigState
from pyvelo.core.identity import SegmentIdentity


# ---------------------------------------------------------------------------
# CIDR helpers
# ---------------------------------------------------------------------------


def split_cidr(cidr: str) -> tuple[str, int]:
    """Split 'x.x.x.x/n' into (ip, prefix_len)."""
    ip, prefix = cidr.split("/")
    return ip, int(prefix)


def prefix_to_netmask(prefix: int) -> str:
    bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return f"{(bits >> 24) & 0xFF}.{(bits >> 16) & 0xFF}.{(bits >> 8) & 0xFF}.{bits & 0xFF}"


def addressing_patch(
    type: IPv4AddressingType,
    cidr: str | None = None,
    gateway: str | None = None,
) -> dict[str, Any]:
    patch: dict[str, Any] = {"type": type}
    if type == "STATIC" and cidr:
        ip, prefix = split_cidr(cidr)
        patch.update(
            {
                "cidr_ip": ip,
                "cidr_prefix": prefix,
                "netmask": prefix_to_netmask(prefix),
            }
        )
        if gateway:
            patch["gateway"] = gateway
    return patch


# ---------------------------------------------------------------------------
# Input specs (Pydantic)
# ---------------------------------------------------------------------------


class SegmentSpec(BaseModel):
    name: str
    type: NetworkSegmentType = NetworkSegmentType.REGULAR
    description: str = ""
    segment_id: int = 1
    delegate_to_enterprise: bool = True
    delegate_to_enterprise_proxy: bool = True


class ProfileFirewallSpec(BaseModel):
    console_enabled: bool = False


class ProfileSpec(BaseModel):
    name: str
    description: str = ""
    segments: list[str] = Field(default_factory=list)
    firewall: ProfileFirewallSpec = Field(default_factory=ProfileFirewallSpec)


class WanAddressing(BaseModel):
    type: IPv4AddressingType = "DHCP"
    cidr: str | None = None
    gateway: str | None = None


class WanLinkInput(BaseModel):
    """WAN-facing routed interface — maps to device_settings.routed_interfaces."""

    name: str
    addressing: WanAddressing = Field(default_factory=WanAddressing)
    wan_overlay: WanOverlay = "AUTO_DISCOVERED"
    nat_direct: bool = False
    segment_id: str = "Global Segment"


class WanLinkSettingsInput(BaseModel):
    """WAN link properties — maps to wan.links (bandwidth, mode, discovery, etc.)."""

    name: str
    type: str = "WIRED"
    interfaces: list[str] = Field(default_factory=list)
    mode: str = "PUBLIC"
    discovery: str = "AUTO_DISCOVERED"
    upstream_mbps: str | None = None
    downstream_mbps: str | None = None


class RoutedInterfaceAddressing(BaseModel):
    type: IPv4AddressingType = "STATIC"
    cidr: str | None = None
    gateway: str | None = None


class SubInterfaceInput(BaseModel):
    """Sub-interface — nested under a routed interface."""

    subinterface_id: int
    vlan_id: int
    segment_id: str = "Global Segment"
    addressing: RoutedInterfaceAddressing = Field(
        default_factory=RoutedInterfaceAddressing
    )
    advertise: bool = False


class DhcpServerInput(BaseModel):
    enabled: bool = True
    lease_time_seconds: int = 86400


class RoutedInterfaceInput(BaseModel):
    """LAN-side routed interface — maps to device_settings.routed_interfaces."""

    name: str
    segment_id: str = "Global Segment"
    addressing: RoutedInterfaceAddressing = Field(
        default_factory=RoutedInterfaceAddressing
    )
    advertise: bool = False
    override: bool = False
    disabled: bool = False
    nat_direct: bool = False
    dhcp_server: DhcpServerInput | None = None
    subinterfaces: list[SubInterfaceInput] = Field(default_factory=list)


class SwitchedInterfaceInput(BaseModel):
    """Switched (LAN) port — maps to device_settings.lan.interfaces."""

    name: str
    port_mode: LanPortMode = "trunk"
    untagged_vlan: int | None = None
    vlan_ids: list[int] = Field(default_factory=list)
    override: bool = False
    disabled: bool = False


class InterfaceConfig(BaseModel):
    routed: list[RoutedInterfaceInput] = Field(default_factory=list)
    switched: list[SwitchedInterfaceInput] = Field(default_factory=list)


class VlanInput(BaseModel):
    """VLAN/LAN network definition — maps to device_settings.lan.networks.

    ``state=absent`` deletes the VLAN by vlan_id; only ``vlan_id`` is required.
    """

    vlan_id: int
    state: Literal["present", "absent"] = "present"
    name: str = ""
    segment_id: str = "Global Segment"
    cidr: str = ""
    dhcp_enabled: bool = False
    dhcp_lease_time_seconds: int = 86400
    interfaces: list = ["GE1", "GE2"]
    advertise: bool = True

    @model_validator(mode="after")
    def _require_fields_for_present(self) -> "VlanInput":
        if self.state == "present" and (not self.name or not self.cidr):
            raise ValueError("name and cidr are required when state=present")
        return self


class BgpNeighborInput(BaseModel):
    neighbor_ip: str
    neighbor_as: str
    description: str = ""
    enable_bfd: bool = False
    enable_md5: bool = False
    md5_password: str = ""
    uplink: bool = False
    allow_as: bool = False
    max_hop: str = "1"
    keepalive: str = "60"
    holdtime: str = "180"
    connect: str = "120"


class BgpInput(BaseModel):
    """BGP config — maps to device_settings.segments.<segment>.bgp."""

    enabled: bool = True
    asn: str
    segment_id: str = "Global Segment"
    connected_routes: bool = True
    overlay_prefix: bool = False
    propagate_uplink: bool = False
    router_id: str | None = None
    keepalive: str = "60"
    holdtime: str = "180"
    enable_graceful_restart: bool = False
    neighbors: list[BgpNeighborInput] = Field(default_factory=list)


class HaNodeInput(BaseModel):
    """Maps to EdgeHaNode — one node in an active/standby HA pair."""

    serial_number: str | None = None
    instance_id: Literal[1, 2]


class HaInput(BaseModel):
    """HA config — maps to device_settings.ha."""

    enabled: bool = False
    interface: str = "GE1"
    unique_lan_macs: bool = False  # wire alias: vmacoverride
    unique_wan_macs: bool = False  # wire alias: wanmacoverride
    nodes: list[HaNodeInput] | None = None  # None = leave nodes untouched; [] = clear
    ha_graceful_switchover: bool = False
    ha_failover_count: float = 7
    preempt_switchover: bool = False  # wire alias: preEmptSwitchover


class LoopbackOspfInput(BaseModel):
    enabled: bool = False
    area: list[Any] = Field(default_factory=list)


class LoopbackInterfaceInput(BaseModel):
    """Loopback interface — maps to device_settings.loopback_interfaces."""

    name: str
    cidr_ip: str
    segment_id: str = "Global Segment"
    advertise: bool = True
    ping_response: bool = True
    disable_ipv4: bool = False
    disable_ipv6: bool = True
    description: str | None = None
    ospf: LoopbackOspfInput = Field(default_factory=LoopbackOspfInput)


class StaticRouteInput(BaseModel):
    """Static route — maps to device_settings.segments.<segment>.routes.static.

    Accepts either a 'cidr' shorthand (e.g. "10.0.0.0/24") or explicit
    destination + netmask + cidr_prefix. 'gateway' is always required.
    """

    cidr: str | None = None
    destination: str | None = None
    netmask: str | None = None
    cidr_prefix: int | None = None
    gateway: str
    cost: int = 0
    preferred: bool = True
    description: str | None = None
    wan_interface: str = ""
    vlan_id: int | None = None
    advertise: bool = True
    subinterface_id: int = -1

    @model_validator(mode="after")
    def _expand_cidr(self) -> "StaticRouteInput":
        if self.cidr:
            ip, prefix = split_cidr(self.cidr)
            self.destination = self.destination or ip
            self.cidr_prefix = (
                self.cidr_prefix if self.cidr_prefix is not None else prefix
            )
            self.netmask = self.netmask or prefix_to_netmask(prefix)
        if not (self.destination and self.netmask and self.cidr_prefix is not None):
            raise ValueError("Provide 'cidr' or all of destination/netmask/cidr_prefix")
        return self


class RoutesInput(BaseModel):
    """Routes config — maps to device_settings.segments.<segment>.routes."""

    segment_id: str = "Global Segment"
    static: list[StaticRouteInput] = Field(default_factory=list)
    static_v6: list[StaticRouteInput] = Field(default_factory=list)


class BizPolicySlaInput(BaseModel):
    """SLA thresholds for a business-policy rule action."""

    latency_ms: str = "0"
    jitter_ms: str = "0"
    loss_pct: str = "0.0"


class BizPolicyQosInput(BaseModel):
    """QoS scheduler priority for a business-policy rule action."""

    priority: Literal["high", "normal", "low"] = "normal"


class BizPolicyMatchInput(BaseModel):
    """Match criteria for a business-policy rule.

    Field names use the SDK short aliases (dip/dsm/sip/ssm/appid/...) to match
    what VCO surfaces over the wire.
    """

    # Addressing
    dip: str = "any"
    dsm: str = "255.255.255.255"
    sip: str = "any"
    ssm: str = "255.255.255.255"
    # L4
    proto: int = -1
    sport_low: int = -1
    sport_high: int = -1
    dport_low: int = -1
    dport_high: int = -1
    # Classification
    appid: int = -1
    classid: int = -1
    dscp: int = -1
    svlan: int = -1
    dvlan: int = -1


class BizPolicyActionInput(BaseModel):
    """Action portion of a business-policy rule."""

    route_type: str = "edge2Any"  # edge2Edge|edge2Cloud|edge2DataCenter|edge2Any
    route_policy: Literal["auto", "gateway"] = "auto"
    link_policy: str = "auto"  # auto|fixed|preferred|available|required
    service_group: str = "ALL"  # ALL|PUBLIC_WIRED|PRIVATE_WIRED|...
    service_class: str = "transactional"  # → QoS.type
    wan_link: str = "auto"
    interface: str = "auto"
    qos: BizPolicyQosInput = Field(default_factory=BizPolicyQosInput)
    sla: BizPolicySlaInput | None = None


class BizPolicyRuleInput(BaseModel):
    """One business-policy rule. ``state=absent`` deletes the rule by name."""

    name: str
    state: Literal["present", "absent"] = "present"
    match: BizPolicyMatchInput = Field(default_factory=BizPolicyMatchInput)
    action: BizPolicyActionInput = Field(default_factory=BizPolicyActionInput)


class SegmentConfigInput(BaseModel):
    """Per-segment config block: BGP, routes, and/or biz policy under one segment_id."""

    segment_id: str
    bgp: BgpInput | None = None
    routes: RoutesInput | None = None
    bizpolicy: list[BizPolicyRuleInput] = Field(default_factory=list)


class EdgeSite(BaseModel):
    city: str = ""
    state: str = ""
    country: str = ""
    name: str = ""


class EdgeSpec(BaseModel):
    name: str
    profile: str
    model_number: ModelNumber
    edge_license_id: int
    site: EdgeSite | None = None
    wan_links: list[WanLinkInput] = Field(default_factory=list)
    wan_link_settings: list[WanLinkSettingsInput] = Field(default_factory=list)
    interfaces: InterfaceConfig = Field(default_factory=InterfaceConfig)
    vlans: list[VlanInput] = Field(default_factory=list)
    segment_config: list[SegmentConfigInput] = Field(default_factory=list)
    bgp: list[BgpInput] = Field(default_factory=list)  # legacy; prefer segment_config


class TopologyConfig(BaseModel):
    enterprise_id: int | None = None
    segments: list[SegmentSpec] = Field(default_factory=list)
    profiles: list[ProfileSpec] = Field(default_factory=list)
    edges: list[EdgeSpec] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Segment
# ---------------------------------------------------------------------------


async def ensure_segment(
    client: VcoClient, enterprise_id: int, spec: SegmentSpec
) -> SegmentMetadata:
    """Create segment if missing. Always returns metadata for downstream use."""
    existing = await client.get_enterprise_network_segments(
        GetEnterpriseNetworkSegments(enterprise_id=enterprise_id)
    )
    match = next((s for s in existing if s.name == spec.name), None)
    if match is not None:
        logger.info(
            "Segment '{}' already exists (id={}, segment_id={}). Skipping.",
            match.name,
            match.id_,
            match.data.segment_id,
        )
        return SegmentMetadata(
            segment_id=match.data.segment_id,
            name=match.name,
            type_=match.type_,
            segment_logical_id=match.logical_id,
        )

    created = await client.insert_enterprise_network_segment(
        InsertEnterpriseNetworkSegment(
            name=spec.name,
            type_=spec.type,
            description=spec.description,
            data=NetworkSegmentData(
                segment_id=spec.segment_id,
                delegate_to_enterprise=spec.delegate_to_enterprise,
                delegate_to_enterprise_proxy=spec.delegate_to_enterprise_proxy,
            ),
            enterprise_id=enterprise_id,
        )
    )
    logger.info(
        "Created segment '{}': id={} logical_id={}",
        created.name,
        created.id_,
        created.logical_id,
    )
    return SegmentMetadata(
        segment_id=spec.segment_id,
        name=created.name,
        type_=created.type_,
        segment_logical_id=created.logical_id,
    )


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


def _module_has_segment(segments: list[Any], seg: SegmentMetadata) -> bool:
    return any(
        s.segment.segment_id == seg.segment_id or s.segment.name == seg.name
        for s in segments
    )


def _factory_device_segment(seg: SegmentMetadata) -> DeviceSegment:
    """VCO ``getDefaultDeviceSettingsSegment`` using pyvelo models.

    VPN dynamic defaults to off (pyvelo's DynamicVpnConfig.enabled is True).
    """
    return DeviceSegment(
        segment=seg,
        vpn=SegmentVpn(
            edge_to_edge_detail=EdgeToEdgeDetail(
                dynamic=DynamicVpnConfig(enabled=False)
            )
        ),
        multicast=SegmentMulticast(),
        ospf=SegmentOspf(),
        bgp=SegmentBgp(),
        authentication=SegmentAuthentication(ref="deviceSettings:authentication"),
        nat=SegmentNat(),
        netflow=SegmentNetflow(enabled=False),
        syslog=SegmentSyslog(),
        dns=SegmentDns(
            primary_provider=DnsProvider(ref="deviceSettings:dns:primaryProvider"),
            backup_provider=DnsProvider(ref="deviceSettings:dns:backupProvider"),
            private_providers=DnsProvider(ref="deviceSettings:dns:privateProviders"),
        ),
        css=SegmentCss(enabled=False, provider=CssProviderRef()),
        bfd=SegmentBfd(),
        edge_direct=SegmentEdgeDirect(),
        hub_interconnect=SegmentHubInterconnect(enabled=False),
        handoff_controllers=SegmentHandoffGateways(),
        handoff_gateways=SegmentHandoffGateways(),
    )


@dataclass(frozen=True)
class _QosRuleSpec:
    name: str
    appid: int = -1
    classid: int = -1
    proto: int = -1
    qos_type: str = "transactional"
    priority: str = "normal"
    route_type: str = "edge2Any"
    cloud_policy: str = "gateway"
    edge_policy: str = "gateway"
    dc_policy: str = "gateway"
    top_route_policy: str | None = "auto"


# Stock business-policy catalog from VCO getDefaultQosSegment / defaultSegmentQosRules.
_DEFAULT_QOS_RULES: tuple[_QosRuleSpec, ...] = (
    _QosRuleSpec(
        "Box", appid=767, qos_type="bulk", priority="high", top_route_policy=None
    ),
    _QosRuleSpec("Speedtest", appid=1465, qos_type="bulk", priority="high"),
    _QosRuleSpec(
        "Skype",
        appid=183,
        qos_type="transactional",
        priority="low",
        cloud_policy="direct",
    ),
    _QosRuleSpec(
        "Business Application", classid=4, qos_type="transactional", priority="high"
    ),
    _QosRuleSpec(
        "Remote Desktop", classid=15, qos_type="transactional", priority="high"
    ),
    _QosRuleSpec(
        "Business Collaboration", classid=5, qos_type="realtime", priority="high"
    ),
    _QosRuleSpec("Email bulk/DATA", classid=6, qos_type="bulk", priority="high"),
    _QosRuleSpec(
        "Infrastructure", classid=9, qos_type="transactional", priority="normal"
    ),
    _QosRuleSpec(
        "Web",
        classid=19,
        qos_type="transactional",
        priority="normal",
        cloud_policy="direct",
    ),
    _QosRuleSpec(
        "Authentication", classid=3, qos_type="transactional", priority="normal"
    ),
    _QosRuleSpec("Management", classid=11, qos_type="transactional", priority="normal"),
    _QosRuleSpec(
        "Network Service", classid=13, qos_type="transactional", priority="normal"
    ),
    _QosRuleSpec(
        "Tunneling and VPN", classid=18, qos_type="transactional", priority="normal"
    ),
    _QosRuleSpec("Audio/Video", classid=2, qos_type="realtime", priority="high"),
    _QosRuleSpec("File Sharing", classid=7, qos_type="bulk", priority="normal"),
    _QosRuleSpec(
        "Internet Instant Messaging",
        classid=10,
        qos_type="transactional",
        priority="low",
        cloud_policy="direct",
    ),
    _QosRuleSpec(
        "Anonymizers And Proxies",
        classid=1,
        qos_type="transactional",
        priority="low",
        cloud_policy="direct",
    ),
    _QosRuleSpec(
        "Gaming",
        classid=8,
        qos_type="transactional",
        priority="low",
        cloud_policy="direct",
    ),
    _QosRuleSpec(
        "Media",
        classid=12,
        qos_type="transactional",
        priority="low",
        cloud_policy="direct",
    ),
    _QosRuleSpec(
        "Social Networking",
        classid=16,
        qos_type="transactional",
        priority="low",
        cloud_policy="direct",
    ),
    _QosRuleSpec(
        "Peer to Peer",
        classid=14,
        qos_type="bulk",
        priority="low",
        cloud_policy="direct",
    ),
    _QosRuleSpec(
        "Storage and Backup",
        classid=17,
        qos_type="bulk",
        priority="low",
        cloud_policy="direct",
    ),
)

_DEFAULT_QOS_DEFAULTS: tuple[_QosRuleSpec, ...] = (
    _QosRuleSpec(
        "Default-Internet-UDP",
        proto=17,
        qos_type="realtime",
        priority="high",
        route_type="edge2Cloud",
        cloud_policy="gateway",
        edge_policy="auto",
        dc_policy="auto",
        top_route_policy=None,
    ),
    _QosRuleSpec(
        "Default-Internet-Other",
        qos_type="transactional",
        priority="normal",
        route_type="edge2Cloud",
        cloud_policy="direct",
        edge_policy="auto",
        dc_policy="auto",
        top_route_policy=None,
    ),
    _QosRuleSpec(
        "Default-Any-UDP",
        proto=17,
        qos_type="realtime",
        priority="high",
        route_type="edge2Any",
        cloud_policy="gateway",
        edge_policy="gateway",
        dc_policy="auto",
        top_route_policy=None,
    ),
    _QosRuleSpec(
        "Default-Any-Other",
        qos_type="transactional",
        priority="normal",
        route_type="edge2Any",
        cloud_policy="gateway",
        edge_policy="gateway",
        dc_policy="auto",
        top_route_policy=None,
    ),
)


def _factory_qos_rule(spec: _QosRuleSpec, *, match_ssm_any: bool) -> QosRule:
    def _route(policy: str) -> RouteAction:
        return RouteAction(route_policy=policy)

    action = QosRuleAction(
        route_type=spec.route_type,  # type: ignore[arg-type]
        edge_to_edge_route_action=_route(spec.edge_policy),
        edge_to_data_center_route_action=_route(spec.dc_policy),
        edge_to_cloud_route_action=_route(spec.cloud_policy),
        qos=QosSettings(
            type_=spec.qos_type,  # type: ignore[arg-type]
            rx_scheduler=QosScheduler(priority=spec.priority),  # type: ignore[arg-type]
            tx_scheduler=QosScheduler(priority=spec.priority),  # type: ignore[arg-type]
        ),
    )
    if spec.top_route_policy is not None:
        action.route_policy = spec.top_route_policy
    match = QosRuleMatch(
        application_id=spec.appid,
        application_class_id=spec.classid,
        proto=spec.proto,
    )
    if match_ssm_any:
        match.source_subnet_mask = "any"
        match.destination_subnet_mask = "any"
    return QosRule(name=spec.name, match=match, action=action)


def _factory_qos_segment(seg: SegmentMetadata) -> QosSegment:
    """VCO ``getDefaultQosSegment``: stock 22 rules, 4 defaults, default CoS."""
    return QosSegment(
        segment=seg,
        cos_mapping=CosMapping(),
        rules=[
            _factory_qos_rule(spec, match_ssm_any=True) for spec in _DEFAULT_QOS_RULES
        ],
        defaults=[
            _factory_qos_rule(spec, match_ssm_any=False)
            for spec in _DEFAULT_QOS_DEFAULTS
        ],
    )


def _factory_firewall_segment(seg: SegmentMetadata) -> FirewallSegment:
    """VCO ``getDefaultFirewallSegment``: AllowAny outbound, logging off."""
    return FirewallSegment(
        segment=seg,
        firewall_logging_enabled=False,
        outbound=[
            FirewallOutboundRule(
                name="AllowAny",
                match=OutboundRuleMatch(),
                action=OutboundRuleAction(allow_or_deny="allow"),
            )
        ],
    )


def _ref_logical_id(ref: object) -> str:
    if isinstance(ref, dict):
        return str(ref.get("logicalId") or ref.get("logical_id") or "")
    return str(getattr(ref, "logical_id", "") or "")


def _segment_refs_list(raw: object) -> list:
    if raw is None or raw is MISSING:
        return []
    if isinstance(raw, list):
        return list(raw)
    return [raw]


def _attach_device_settings_refs(
    state: ConfigState,
    seg: SegmentMetadata,
    seg_type: NetworkSegmentType,
    enterprise_object_id: int,
) -> bool:
    mod = state.profile_config.device_settings
    new_ref = DeviceSettingsSegmentRef(
        ref="deviceSettings:segment",
        object_="NETWORK_SEGMENT",
        type_=seg_type,
        configuration_id=state.profile_config.id_,
        module_id=mod.id_,
        logical_id=seg.segment_logical_id,
        enterprise_object_id=enterprise_object_id,
        name=seg.name,
    )
    target_lid = str(seg.segment_logical_id)

    if isinstance(mod.refs, DeviceSettingsRefs) or mod.refs is MISSING:
        refs = (
            mod.refs
            if isinstance(mod.refs, DeviceSettingsRefs)
            else DeviceSettingsRefs()
        )
        existing_refs = _segment_refs_list(refs.segment)
        if any(_ref_logical_id(r) == target_lid for r in existing_refs):
            logger.info("Segment ref for '{}' already attached — skipping.", seg.name)
            return False
        existing_refs.append(new_ref)
        refs.segment = existing_refs
        mod.refs = refs
        logger.info("Added DeviceSettingsSegmentRef for '{}'.", seg.name)
        return True

    refs_dict: dict = {} if mod.refs is None or mod.refs == {} else dict(mod.refs)
    existing_refs = _segment_refs_list(refs_dict.get("deviceSettings:segment"))
    if any(_ref_logical_id(r) == target_lid for r in existing_refs):
        logger.info("Segment ref for '{}' already attached — skipping.", seg.name)
        return False
    existing_refs.append(new_ref.model_dump(by_alias=True, exclude_unset=True))
    refs_dict["deviceSettings:segment"] = existing_refs
    mod.refs = refs_dict
    logger.info("Added DeviceSettingsSegmentRef for '{}'.", seg.name)
    return True


def attach_segments_to_profile(
    state: ConfigState,
    seg: SegmentMetadata,
    seg_type: NetworkSegmentType,
    enterprise_object_id: int,
) -> bool:
    """Attach a segment using VCO UI factory defaults (deviceSettings + QOS + firewall).

    Mirrors ConfigureProfileViewService: three module updates, each getting a
    factory-default segment body rather than a clone of Global Segment.
    ``pipeline.save()`` persists whichever modules this mutates.
    """
    mutated = False
    profile = state.profile_config

    ds_mod = profile.device_settings
    if not _module_has_segment(ds_mod.data.segments, seg):
        ds_mod.data.segments.append(_factory_device_segment(seg))
        mutated = True
        logger.info("Added factory DeviceSegment '{}'.", seg.name)

    if _attach_device_settings_refs(state, seg, seg_type, enterprise_object_id):
        mutated = True

    if profile.has_module(ConfigurationModuleName.QOS):
        qos_mod = profile.qos
        if not _module_has_segment(qos_mod.data.segments, seg):
            qos_mod.data.segments.append(_factory_qos_segment(seg))
            mutated = True
            logger.info("Added factory QosSegment '{}'.", seg.name)
    else:
        logger.warning(
            "Profile has no QOS module — skipping QOS attach for '{}'.", seg.name
        )

    if profile.has_module(ConfigurationModuleName.FIREWALL):
        fw_mod = profile.firewall
        if not _module_has_segment(fw_mod.data.segments, seg):
            fw_mod.data.segments.append(_factory_firewall_segment(seg))
            mutated = True
            logger.info("Added factory FirewallSegment '{}'.", seg.name)
    else:
        logger.warning(
            "Profile has no firewall module — skipping firewall attach for '{}'.",
            seg.name,
        )

    return mutated


async def enable_console_firewall(
    pipeline: ConfigPipeline, state: ConfigState
) -> ConfigState:
    """Enable firewall console access on a profile."""
    services = FirewallServices(console=ConsoleService(enabled=True))
    return await pipeline.apply(
        state,
        module="firewall",
        patch={"services": services.model_dump(by_alias=False, exclude_unset=True)},
    )


async def create_profile_only(
    client: VcoClient, enterprise_id: int, spec: ProfileSpec
) -> int:
    """Create a profile (no segment attachment, no firewall patches). Returns profile_id."""
    created = await client.create_enterprise_profile(
        CreateProfile(
            name=spec.name,
            description=spec.description,
            enterprise_id=enterprise_id,
        )
    )
    logger.info("Created profile '{}' → id={}", spec.name, created.id_)
    return created.id_


async def ensure_profile(
    client: VcoClient,
    pipeline: ConfigPipeline,
    enterprise_id: int,
    spec: ProfileSpec,
) -> int | None:
    """Create profile if missing, attach segments, apply firewall patch.

    Returns profile_id if newly created, None if skipped.
    """
    existing = await client.get_enterprise_configurations(
        GetEnterpriseConfigurations(enterprise_id=enterprise_id)
    )
    match = next((p for p in existing if p.name == spec.name), None)
    if match is not None:
        logger.info(
            "Profile '{}' already exists (id={}). Skipping.", match.name, match.id_
        )
        return None

    profile_id = await create_profile_only(client, enterprise_id, spec)
    state = await pipeline.load_profile(profile_id, enterprise_id=enterprise_id)

    if spec.segments:
        all_segments = await client.get_enterprise_network_segments(
            GetEnterpriseNetworkSegments(enterprise_id=enterprise_id)
        )
        for seg_name in spec.segments:
            seg_record = next((s for s in all_segments if s.name == seg_name), None)
            if seg_record is None:
                logger.warning(
                    "Segment '{}' not found on VCO — skipping attachment to profile '{}'.",
                    seg_name,
                    spec.name,
                )
                continue
            seg_meta = SegmentMetadata(
                segment_id=seg_record.data.segment_id,
                name=seg_record.name,
                type_=seg_record.type_,
                segment_logical_id=seg_record.logical_id,
            )
            attach_segments_to_profile(
                state, seg_meta, seg_record.type_, seg_record.id_
            )

    if spec.firewall.console_enabled:
        state = await enable_console_firewall(pipeline, state)
        logger.info("Console access enabled for profile '{}'.", spec.name)

    await pipeline.save(state)
    return profile_id


# ---------------------------------------------------------------------------
# Edge config patches
# ---------------------------------------------------------------------------


async def apply_wan_links(
    pipeline: ConfigPipeline,
    state: ConfigState,
    specs: list[WanLinkInput],
) -> ConfigState:
    """Patch device_settings.routed_interfaces for WAN-facing (overlay-bearing) ports."""
    if not specs:
        return state
    patch = {
        wl.name: {
            "addressing": addressing_patch(
                wl.addressing.type, wl.addressing.cidr, wl.addressing.gateway
            ),
            "wan_overlay": wl.wan_overlay,
            "segment_id": wl.segment_id,
            "nat_direct": wl.nat_direct,
        }
        for wl in specs
    }
    return await pipeline.apply(
        state, module="device_settings", patch={"routed_interfaces": patch}
    )


async def apply_routed_interfaces(
    pipeline: ConfigPipeline,
    state: ConfigState,
    specs: list[RoutedInterfaceInput],
) -> ConfigState:
    """Patch device_settings.routed_interfaces for LAN-side ports (with optional sub-interfaces)."""
    if not specs:
        return state
    patch: dict[str, Any] = {}
    for ri in specs:
        iface: dict[str, Any] = {
            "segment_id": ri.segment_id,
            "advertise": ri.advertise,
            "override": ri.override,
            "disabled": ri.disabled,
            "wan_overlay": "DISABLED",
            "nat_direct": ri.nat_direct,
        }
        if not ri.disabled:
            iface["addressing"] = addressing_patch(
                ri.addressing.type, ri.addressing.cidr, ri.addressing.gateway
            )
        if ri.dhcp_server:
            iface["dhcp_server"] = {
                "enabled": ri.dhcp_server.enabled,
                "lease_time_seconds": ri.dhcp_server.lease_time_seconds,
            }
        if ri.subinterfaces:
            subifs = []
            for si in ri.subinterfaces:
                seg_identity = await pipeline.resolvers.resolve(
                    SegmentIdentity, si.segment_id
                )
                subifs.append(
                    {
                        "subinterface_id": si.subinterface_id,
                        "subinterface_type": "SUB_INTERFACE",
                        "vlan_id": si.vlan_id,
                        "segment_id": seg_identity.segment_id,
                        "addressing": addressing_patch(
                            si.addressing.type,
                            si.addressing.cidr,
                            si.addressing.gateway,
                        ),
                        "advertise": si.advertise,
                        "override": True,
                    }
                )
            iface["subinterfaces"] = subifs
        patch[ri.name] = iface
    switched_cleanup = {ri.name: None for ri in specs}
    return await pipeline.apply(
        state,
        module="device_settings",
        patch={
            "routed_interfaces": patch,
            "lan": {"interfaces": switched_cleanup},
        },
    )


async def apply_switched_interfaces(
    pipeline: ConfigPipeline,
    state: ConfigState,
    specs: list[SwitchedInterfaceInput],
) -> ConfigState:
    """Patch device_settings.lan.interfaces for switched (LAN) ports."""
    if not specs:
        return state
    patch: dict[str, Any] = {}
    for si in specs:
        iface: dict[str, Any] = {
            "type": "wired",
            "port_mode": si.port_mode,
            "override": si.override,
            "disabled": si.disabled,
        }
        if si.untagged_vlan is not None:
            iface["untagged_vlan"] = si.untagged_vlan
        if si.vlan_ids:
            iface["vlan_ids"] = si.vlan_ids
        patch[si.name] = iface
    routed_cleanup = {si.name: None for si in specs}
    return await pipeline.apply(
        state,
        module="device_settings",
        patch={
            "routed_interfaces": routed_cleanup,
            "lan": {"interfaces": patch},
        },
    )


async def apply_vlans(
    pipeline: ConfigPipeline,
    state: ConfigState,
    specs: list[VlanInput],
) -> ConfigState:
    """Patch device_settings.lan.networks for VLAN/LAN network definitions.

    Each VLAN has a per-VLAN state: ``present`` (default) creates or updates
    the VLAN; ``absent`` deletes it via the pyvelo keyed-list merge semantics
    (None value pops the entry; deleting a nonexistent VLAN is a no-op).
    """
    if not specs:
        return state
    patch: dict[str, Any] = {}
    for vlan in specs:
        if vlan.state == "absent":
            patch[str(vlan.vlan_id)] = None
            continue
        cidr_ip, cidr_prefix = split_cidr(vlan.cidr)
        entry: dict[str, Any] = {
            # "override": True,
            "name": vlan.name,
            "vlan_id": vlan.vlan_id,
            "segment_id": vlan.segment_id,
            "cidr_ip": cidr_ip,
            "cidr_prefix": cidr_prefix,
            "netmask": prefix_to_netmask(cidr_prefix),
            "interfaces": vlan.interfaces,
        }
        entry["advertise"] = vlan.advertise
        if vlan.dhcp_enabled:
            entry["dhcp"] = {
                "enabled": True,
                "lease_time_seconds": vlan.dhcp_lease_time_seconds,
            }
        else:
            entry["dhcp"] = {"enabled": False}
        patch[str(vlan.vlan_id)] = entry
    return await pipeline.apply(
        state, module="device_settings", patch={"lan": {"networks": patch}}
    )


async def apply_wan_link_settings(
    pipeline: ConfigPipeline,
    state: ConfigState,
    specs: list[WanLinkSettingsInput],
) -> ConfigState:
    """Patch wan.links for bandwidth, mode, discovery, and interface binding."""
    if not specs:
        return state
    patch: dict[str, Any] = {}
    for cfg in specs:
        raw = cfg.model_dump(exclude_unset=True)
        name = raw.pop("name")
        link = WanLink.model_validate({"name": name, **raw})
        patch[name] = link.model_dump(by_alias=True, exclude_unset=True)
    return await pipeline.apply(state, module="wan", patch={"links": patch})


async def apply_bgp(
    pipeline: ConfigPipeline,
    state: ConfigState,
    spec: BgpInput,
) -> ConfigState:
    """Patch device_settings.segments.<segment>.bgp."""
    neighbors_patch: dict[str, Any] = {}
    for n in spec.neighbors:
        raw = n.model_dump(exclude_unset=True, exclude={"description"})
        neighbor = BgpNeighbor.model_validate(raw)
        dumped = neighbor.model_dump(by_alias=True, exclude_unset=True)
        if n.description:
            dumped["tag"] = n.description
        neighbors_patch[n.neighbor_ip] = dumped

    raw_bgp = spec.model_dump(exclude_unset=True, exclude={"segment_id", "neighbors"})
    seg_bgp = SegmentBgp.model_validate(raw_bgp)
    bgp_patch = seg_bgp.model_dump(by_alias=True, exclude_unset=True)
    if neighbors_patch:
        bgp_patch["neighbors"] = neighbors_patch

    return await pipeline.apply(
        state,
        module="device_settings",
        patch={"segments": {spec.segment_id: {"bgp": bgp_patch}}},
    )


async def apply_routes(
    pipeline: ConfigPipeline,
    state: ConfigState,
    spec: RoutesInput,
) -> ConfigState:
    """Patch device_settings.segments.<segment>.routes."""
    routes_patch: dict[str, Any] = {}

    if spec.static:
        routes_patch["static"] = [
            StaticRoute(
                destination=r.destination,
                netmask=r.netmask,
                cidr_prefix=str(r.cidr_prefix),
                gateway=r.gateway,
                cost=r.cost,
                preferred=r.preferred,
                description=r.description,
                wan_interface=r.wan_interface,
                vlan_id=r.vlan_id,
                advertise=r.advertise,
                subinterface_id=r.subinterface_id,
            ).model_dump(by_alias=True, exclude_unset=True)
            for r in spec.static
        ]

    if spec.static_v6:
        routes_patch["staticV6"] = [
            StaticRoute(
                destination=r.destination,
                netmask=r.netmask,
                cidr_prefix=str(r.cidr_prefix),
                gateway=r.gateway,
                cost=r.cost,
                preferred=r.preferred,
                description=r.description,
                wan_interface=r.wan_interface,
                vlan_id=r.vlan_id,
                advertise=r.advertise,
                subinterface_id=r.subinterface_id,
            ).model_dump(by_alias=True, exclude_unset=True)
            for r in spec.static_v6
        ]

    return await pipeline.apply(
        state,
        module="device_settings",
        patch={"segments": {spec.segment_id: {"routes": routes_patch}}},
    )


async def apply_ha(
    pipeline: ConfigPipeline,
    state: ConfigState,
    spec: HaInput,
) -> ConfigState:
    """Patch device_settings.ha."""
    raw = spec.model_dump(exclude_unset=True, exclude={"nodes"})
    ha = EdgeHaSettings.model_validate(raw)
    patch = ha.model_dump(by_alias=True, exclude_unset=True)
    if spec.nodes is not None:
        patch["nodes"] = [n.model_dump() for n in spec.nodes]
    return await pipeline.apply(state, module="device_settings", patch={"ha": patch})


async def apply_loopback_interfaces(
    pipeline: ConfigPipeline,
    state: ConfigState,
    specs: list[LoopbackInterfaceInput],
) -> ConfigState:
    """Patch device_settings.loopback_interfaces.

    merge_patch() does not handle dict[str, VcoModel] fields — it falls through
    to a scalar assignment that stores raw dicts, breaking serialization. We
    bypass pipeline.apply() and mutate the DeviceSettingsData directly: merging
    into existing LoopbackInterface instances (which merge_patch handles fine)
    or constructing new ones. get_changed_modules() detects the mutation via
    model_dump() comparison, so save() still works correctly.
    """
    if not specs:
        return state

    target_config = (
        state.edge_config
        if (state.target_type == "edge" and state.edge_config is not None)
        else state.profile_config
    )
    ds_data = target_config.get_module(ConfigurationModuleName.DEVICE_SETTINGS).data

    for lo in specs:
        seg_identity = await pipeline.resolvers.resolve(SegmentIdentity, lo.segment_id)
        raw: dict[str, Any] = {
            "cidr_ip": lo.cidr_ip,
            "segment_id": seg_identity.segment_id,
            "advertise": lo.advertise,
            "ping_response": lo.ping_response,
            "disable_ipv4": lo.disable_ipv4,
            "disable_ipv6": lo.disable_ipv6,
            "ospf": {"enabled": lo.ospf.enabled, "area": lo.ospf.area},
        }
        if lo.description is not None:
            raw["description"] = lo.description

        existing = ds_data.loopback_interfaces.get(lo.name)
        if existing is not None:
            existing.merge_patch(raw)
        else:
            ds_data.loopback_interfaces[lo.name] = LoopbackInterface.model_validate(raw)

    return state


_ROUTE_ACTION_KEYS: dict[str, list[str]] = {
    "edge2Edge": ["edge2EdgeRouteAction"],
    "edge2DataCenter": ["edge2DataCenterRouteAction"],
    "edge2Cloud": ["edge2CloudRouteAction"],
    "edge2Any": [
        "edge2EdgeRouteAction",
        "edge2DataCenterRouteAction",
        "edge2CloudRouteAction",
    ],
}


def _build_bizpolicy_rule_patch(rule: BizPolicyRuleInput) -> dict[str, Any]:
    """Construct a single QoS rule patch dict in VCO wire format."""
    action_patch: dict[str, Any] = {
        "route_type": rule.action.route_type,
        "edge2EdgeRouteAction": {},
        "edge2DataCenterRouteAction": {},
        "edge2CloudRouteAction": {},
        "QoS": {
            "type": rule.action.service_class,
            "rx_scheduler": {"priority": rule.action.qos.priority},
            "tx_scheduler": {"priority": rule.action.qos.priority},
        },
    }

    route_action_keys = _ROUTE_ACTION_KEYS.get(
        rule.action.route_type, ["edge2DataCenterRouteAction"]
    )
    route_action_cfg: dict[str, Any] = {
        "route_policy": rule.action.route_policy,
        "link_policy": rule.action.link_policy,
        "service_group": rule.action.service_group,
    }
    if rule.action.wan_link != "auto":
        route_action_cfg["wan_link"] = rule.action.wan_link
    if rule.action.interface != "auto":
        route_action_cfg["interface"] = rule.action.interface

    for key in route_action_keys:
        cfg = route_action_cfg
        # edge2Any fans out across all three route-action blocks. The cloud
        # leg can't honor route_policy=auto, so override to "gateway".
        if (
            key == "edge2CloudRouteAction"
            and rule.action.route_type == "edge2Any"
            and rule.action.route_policy == "auto"
        ):
            cfg = {**route_action_cfg, "route_policy": "gateway"}
        action_patch[key] = cfg

    if rule.action.sla is not None:
        action_patch["sla"] = rule.action.sla.model_dump()

    match_patch = rule.match.model_dump(exclude_defaults=True)

    return {
        "name": rule.name,
        "match": match_patch,
        "action": action_patch,
    }


async def apply_bizpolicy(
    pipeline: ConfigPipeline,
    state: ConfigState,
    segment_id: str,
    rules: list[BizPolicyRuleInput],
) -> ConfigState:
    """Patch qos.segments.<segment>.rules.

    Each rule has a per-rule state: ``present`` (default) creates or updates
    the rule by name; ``absent`` deletes it via the pyvelo keyed-list merge
    semantics (None value pops the entry; deleting a nonexistent rule is a
    no-op).
    """
    if not rules:
        return state

    rules_patch: dict[str, Any] = {}
    for rule in rules:
        if rule.state == "absent":
            rules_patch[rule.name] = None
        else:
            rules_patch[rule.name] = _build_bizpolicy_rule_patch(rule)

    return await pipeline.apply(
        state,
        module="qos",
        patch={"segments": {segment_id: {"rules": rules_patch}}},
    )


# ---------------------------------------------------------------------------
# Edge
# ---------------------------------------------------------------------------


async def create_edge_only(
    client: VcoClient,
    enterprise_id: int,
    spec: EdgeSpec,
    profile_id: int,
) -> CreateEdgeResult:
    """Create the edge (no config patches). Returns the create result."""
    site: Site | Any = MISSING
    if spec.site:
        s = spec.site
        site = Site(
            name=s.name or spec.name,
            city=s.city or MISSING,
            state=s.state or MISSING,
            country=s.country or MISSING,
        )

    result = await client.create_edge(
        CreateEdge(
            name=spec.name,
            configuration_id=profile_id,
            model_number=spec.model_number,
            edge_license_id=spec.edge_license_id,
            enterprise_id=enterprise_id,
            site=site,
        )
    )
    logger.info(
        "Created edge '{}': id={} activation_key={}",
        spec.name,
        result.id_,
        result.activation_key,
    )
    return result


async def ensure_edge(
    client: VcoClient,
    pipeline: ConfigPipeline,
    enterprise_id: int,
    spec: EdgeSpec,
    profile_id: int,
) -> CreateEdgeResult | None:
    """Create edge if missing and apply all config patches. Returns None if skipped."""
    existing = await client.get_enterprise_edges(
        GetEnterpriseEdges(enterprise_id=enterprise_id)
    )
    match = next((e for e in existing if e.name == spec.name), None)
    if match is not None:
        logger.info(
            "Edge '{}' already exists (id={}). Skipping.", match.name, match.id_
        )
        return None

    result = await create_edge_only(client, enterprise_id, spec, profile_id)
    state: ConfigState = await pipeline.load(result.id_, enterprise_id=enterprise_id)

    state = await apply_wan_links(pipeline, state, spec.wan_links)
    state = await apply_routed_interfaces(pipeline, state, spec.interfaces.routed)
    state = await apply_switched_interfaces(pipeline, state, spec.interfaces.switched)
    state = await apply_vlans(pipeline, state, spec.vlans)
    state = await apply_wan_link_settings(pipeline, state, spec.wan_link_settings)
    for seg_cfg in spec.segment_config:
        if seg_cfg.bgp is not None:
            bgp_spec = seg_cfg.bgp.model_copy(update={"segment_id": seg_cfg.segment_id})
            state = await apply_bgp(pipeline, state, bgp_spec)
        if seg_cfg.routes is not None:
            routes_spec = seg_cfg.routes.model_copy(
                update={"segment_id": seg_cfg.segment_id}
            )
            state = await apply_routes(pipeline, state, routes_spec)
    for bgp_spec in spec.bgp:
        state = await apply_bgp(pipeline, state, bgp_spec)

    await pipeline.save(state)
    return result
