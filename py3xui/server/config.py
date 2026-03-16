"""
    This module contains the ServerConfig class which represents server configuration
    information in XUI API.
"""

from typing import Any
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator

from py3xui.inbound.inbound import Inbound

# pylint: disable=too-few-public-methods
class ServerConfigFields:
    """Stores fields returned by XUI API for parsing."""

    API = "api"
    INBOUNDS = "inbounds"
    OUTBOUNDS = "outbounds"

    METRICS = "metrics"
    POLICY = "policy"
    STATS = "stats"
    LOG = "log"

    OBSERVATORY = "observatory"
    BURST_OBSERVATORY = "burstObservatory"

    ROUTING = "routing"
    REVERSE = "reverse"
    TRANSPORT = "transport"

    DNS = "dns"
    FAKEDNS = "fakeDns"


class ApiInfo(BaseModel):
    """Represents API configuration information.

    Attributes:
        services (list[str]): List of enabled API services.
        tag (str): The tag used to identify the API inbound.
    """

    services: list[str]
    tag: str


class Server(BaseModel):
    """Represents a DNS server entry.

    Attributes:
        address (str): The address of the DNS server.
        disableCache (bool): Whether DNS caching is disabled for this server.
        domains (list[str]): List of domains routed to this server.
        expectIPs (list[str]): Expected IP ranges; responses outside these ranges are dropped.
        finalQuery (bool): Whether this server is used as the final query fallback.
        port (int): The port of the DNS server.
        queryStrategy (str): IP version strategy for queries (e.g. UseIPv4, UseIPv6, UseIP).
        skipFallback (bool): Whether to skip this server during fallback resolution.
        unexpectedIPs (list[str]): IP ranges considered unexpected; matching responses are rejected.
    """

    address: str
    disableCache: bool
    domains: list[str]
    expectIPs: list[str]
    finalQuery: bool
    port: int
    queryStrategy: str
    skipFallback: bool
    unexpectedIPs: list[str]


class DNSInfo(BaseModel):
    """Represents DNS configuration information."""
    enableParallelQuery: bool
    queryStrategy: str
    servers: list[Server]
    tag: str


class LogInfo(BaseModel):
    """Represents log configuration information."""
    access: str
    dnsLog: bool
    error: str
    loglevel: str
    maskAddress: str


class MetricsInfo(BaseModel):
    """Represents metrics configuration information."""
    listen: str
    tag: str


class LevelPolicy(BaseModel):
    """Represents levels policy configuration information."""
    statsUserDownlink: bool
    statsUserUplink: bool

class SystemPolicy(BaseModel):
    """Represents system-level policy configuration.

    Attributes:
        statsInboundDownlink (bool): Whether to collect inbound downlink statistics.
        statsInboundUplink (bool): Whether to collect inbound uplink statistics.
        statsOutboundDownlink (bool): Whether to collect outbound downlink statistics.
        statsOutboundUplink (bool): Whether to collect outbound uplink statistics.
    """

    statsInboundDownlink: bool
    statsInboundUplink: bool
    statsOutboundDownlink: bool
    statsOutboundUplink: bool


class PolicyInfo(BaseModel):
    """Represents policy configuration information."""
    levels: dict[str, LevelPolicy]
    system: SystemPolicy


class RoutingRule(BaseModel):
    """Represents a single routing rule.

    Attributes:
        type (str): The rule type (e.g. field).
        inboundTag (list[str]): List of inbound tags this rule matches.
        outboundTag (str): The outbound tag traffic is forwarded to.
    """

    type: str
    outboundTag: str


class Routing(BaseModel):
    """Represents traffic routing configuration.

    Attributes:
        domainStrategy (str): How domains are resolved before routing (e.g. AsIs, IPIfNonMatch).
        rules (list[RoutingRule]): Ordered list of routing rules applied to traffic.
    """

    domainStrategy: str
    rules: list[RoutingRule]


class ServerConfig(BaseModel):
    """Represents server configuration information in XUI API.

    Attributes:
        api (ApiInfo): API configuration information including host, port and security settings.
        inbounds (list[Inbound]): List of inbound connection configurations.
        metrics (MetricsInfo): Metrics collection and reporting configuration.
        policy (PolicyInfo): Server policy settings including timeouts and resource limits.
        stats (Any | None): Statistics configuration, or None if not configured.
        log (LogInfo): Logging configuration including log level and output settings.
        observatory (Any | None): Observatory configuration for connection testing,
        or None if not configured.
        burstObservatory (Any | None): Burst observatory configuration for rapid connection testing,
        or None if not configured.
        routing (Routing): Traffic routing rules and configuration.
        reverse (Any | None): Reverse proxy configuration, or None if not configured.
        transport (Any | None): Transport layer configuration, or None if not configured.
        dns (DNSInfo): DNS resolution configuration and server settings.
        fakeDns (Any | None): Fake DNS configuration for DNS interception,
        or None if not configured.
    """

    api: ApiInfo
    inbounds: list[Inbound]

    metrics: MetricsInfo
    policy: PolicyInfo
    stats: Any | None
    log: LogInfo

    observatory: Any | None
    burstObservatory: Any | None

    routing: Routing
    reverse: Any | None
    transport: Any | None

    dns: DNSInfo
    fakeDns: Any | None = Field(
        default=None,
        validation_alias=AliasChoices(ServerConfigFields.FAKEDNS, "fakedns"),
    )

    model_config = ConfigDict(
        populate_by_name=True,
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_data(cls, data):
        """Normalizes the input data to ensure it conforms to expected formats and defaults."""
        if not isinstance(data, dict):
            return data

        inbounds = data.get("inbounds")
        if not isinstance(inbounds, list):
            return data

        for inbound in inbounds:
            if not isinstance(inbound, dict):
                continue

            inbound.setdefault("enable", True)

            if inbound.get("streamSettings") is None:
                inbound.pop("streamSettings", None)

            if inbound.get("sniffing") is None:
                inbound["sniffing"] = {"enabled": False}

            settings = inbound.get("settings")
            if isinstance(settings, dict):
                clients = settings.get("clients")
                if isinstance(clients, list):
                    for client in clients:
                        if isinstance(client, dict):
                            client.setdefault("enable", True)

        return data
