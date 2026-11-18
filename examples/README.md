# velocloud.api examples

Each playbook shows one collection workflow. They run on the controller
(`hosts: localhost`). Addresses are RFC 5737 documentation prefixes and RFC 1918
LAN space. Replace them, plus license and operator-profile IDs, before pointing
the playbooks at a real orchestrator.

Device activation is out of scope. Gateway and edge modules return activation
keys; `create_edges.yml` prints the edge keys on purpose.

## Playbooks

Run operator playbooks with a Vault file. Run the edge playbooks after
`generate_token.yml` has saved a token.

| Playbook | What it shows |
|---|---|
| [create_gateways.yml](create_gateways.yml) | Operator gateways in a gateway pool (`velocloud.api.gateway`). |
| [create_enterprise.yml](create_enterprise.yml) | An enterprise bound to that pool (`velocloud.api.enterprise`). |
| [generate_token.yml](generate_token.yml) | Operator login, create or download a named API token, print it, and save it. |
| [create_segment_and_profile.yml](create_segment_and_profile.yml) | A segment attached to a profile with console and SSH (`velocloud.api.segment`, `velocloud.api.profile`). |
| [create_edges.yml](create_edges.yml) | Edges with switched LAN, routed interfaces, loopback, WAN overlay, and HA. Prints activation keys. |
| [configure_cloudvpn.yml](configure_cloudvpn.yml) | CloudVPN hub designation (`velocloud.api.profile_vpn`). |
| [configure_bizpolicy.yml](configure_bizpolicy.yml) | A realtime business-policy rule (`velocloud.api.edge_segment`). |

Suggested order: gateways, enterprise, generate token, segment and profile,
edges, CloudVPN, business policy.

## Authentication

Operator playbooks (`create_gateways.yml`, `create_enterprise.yml`,
`generate_token.yml`) take `vco_host`, `vco_username`, and `vco_password`
through an Ansible Vault file:

```yaml
vco_host: vco.example.com
vco_username: operator@example.com
vco_password: replace-me
```

```sh
uv run ansible-playbook examples/create_gateways.yml -e @vco-vault.yml --ask-vault-pass
uv run ansible-playbook examples/create_enterprise.yml -e @vco-vault.yml --ask-vault-pass
uv run ansible-playbook examples/generate_token.yml -e @vco-vault.yml --ask-vault-pass
```

`generate_token.yml` prints the token and writes
`examples/.tokens/<SHA-256 of vco_host>.token` (file mode `0600`, directory
`0700`). Do not commit that file. Override `vco_token_file` to save it
elsewhere. `vco_token_name` defaults to `ansible-collection-example`.

Edge playbooks load that saved token (or `-e vco_token=...`):

```sh
uv run ansible-playbook examples/create_segment_and_profile.yml \
    -e vco_host=vco.example.com -e vco_enterprise_id=1
uv run ansible-playbook examples/create_edges.yml \
    -e vco_host=vco.example.com -e vco_enterprise_id=1
uv run ansible-playbook examples/configure_cloudvpn.yml \
    -e vco_host=vco.example.com -e vco_enterprise_id=1
uv run ansible-playbook examples/configure_bizpolicy.yml \
    -e vco_host=vco.example.com -e vco_enterprise_id=1
```

Copy the enterprise id printed by `create_enterprise.yml`. Set
`vco_verify_ssl: false` only for an orchestrator with a self-signed certificate.

## Extra vars

| Variable | Purpose |
|---|---|
| `vco_host` | Orchestrator hostname or `host:port`. Required. |
| `vco_username` / `vco_password` | Operator login for gateway, enterprise, and token generation. |
| `vco_token` | Operator API token. Skips the saved token file on edge playbooks. |
| `vco_verify_ssl` | TLS verification. Default `true`. |
| `vco_enterprise_id` | Enterprise id for SDK modules. Printed by `create_enterprise.yml`. |
| `vco_edge_license_id` | Edge license id. Default `1`. |
| `vco_gateway_pool_id` | Existing gateway pool. Default `1`. |

`configuration_id: 6` in [vars/enterprise.yml](vars/enterprise.yml) must match a
segmented operator profile on your orchestrator.

## What the edge examples configure

**Segment and profile** — Corp Segment attached to Example-Profile, with
console access and SSH from `192.0.2.1`.

**Edges** — `hub-1` (private plus public WAN) and `branch-ha` (switched LAN on
GE5, routed GE2 with a VLAN sub-interface, loopback, dual public WAN, HA on
GE1).

**CloudVPN** — Example-Profile backhaul with `hub-1` as the hub.

**Business policy** — RTSP/RTP realtime traffic prefers the private wired group
on `branch-ha`.
