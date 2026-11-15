#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Kangwarn Chinthammit
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: profile

short_description: Manage VeloCloud configuration profiles

version_added: "0.1.0"

description:
    - Create or delete a configuration profile in a VeloCloud enterprise.
    - On create, optionally attach a list of pre-existing segments and/or enable
      firewall console access. Segment attach writes factory-default entries on
      deviceSettings, QOS (stock business-policy catalog), and firewall
      (AllowAny outbound), matching the VCO UI rather than cloning Global
      Segment.
    - When the profile exists by name and top-level fields differ, the module
      logs a warning and skips by default. Pass C(force=true) to delete and
      recreate. The pyvelo SDK does not expose an in-place update for profiles.
    - Existing profiles are NOT mutated to add new segments — use C(force) to
      recreate, or attach segments by editing the profile in the VCO UI.

options:
    vco_host:
        description: VCO hostname or IP.
        required: true
        type: str
    api_token:
        description: API token (mutually exclusive with username/password).
        required: false
        type: str
    username:
        description: VCO username (used with password).
        required: false
        type: str
    password:
        description: VCO password (used with username).
        required: false
        type: str
    enterprise_id:
        description: Enterprise ID. Auto-resolved from JWT for token auth.
        required: false
        type: int
    verify_ssl:
        description: Verify the VCO TLS certificate.
        required: false
        type: bool
        default: true
    state:
        description: present ensures the profile exists; absent deletes it.
        required: false
        type: str
        choices: [present, absent]
        default: present
    name:
        description: Profile name.
        required: true
        type: str
    description:
        description: Free-form description.
        required: false
        type: str
        default: ""
    segments:
        description: List of segment names to attach (must already exist in the enterprise).
        required: false
        type: list
        elements: str
        default: []
    firewall:
        description: Firewall sub-config; currently supports console_enabled.
        required: false
        type: dict
        default: {}
    force:
        description: Delete and recreate if profile exists with drift.
        required: false
        type: bool
        default: false

requirements:
    - pyvelo
    - requests

author:
    - Kangwarn Chinthammit (@kangwarn-arista)
"""

EXAMPLES = r"""
- name: Create a profile and attach segments
  velocloud.api.profile:
    vco_host: vco.example.com
    api_token: "{{ vco_api_token }}"
    name: Demo-Profile
    description: Created by Ansible
    segments:
      - Demo-Segment
    firewall:
      console_enabled: true

- name: Delete a profile
  velocloud.api.profile:
    vco_host: vco.example.com
    api_token: "{{ vco_api_token }}"
    name: Demo-Profile
    state: absent
"""

RETURN = r"""
changed:
    description: Whether the profile was created, deleted, or recreated.
    type: bool
    returned: always
profile:
    description: Profile record (id, name).
    type: dict
    returned: when state=present and profile exists or was created
drift:
    description: Field-level diff between spec and existing profile.
    type: dict
    returned: when an existing profile differs from the spec
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.velocloud.api.plugins.module_utils.sdk_args import (
    common_argspec,
    common_argspec_constraints,
)

try:
    from ansible_collections.velocloud.api.plugins.module_utils.auth import (
        build_client,
        resolve_enterprise_id,
        run_async,
    )
    from ansible_collections.velocloud.api.plugins.module_utils.diff import (
        profile_drift,
    )
    from pyvelo.client.models.configuration.common import SegmentMetadata
    from pyvelo.client.schemas.configuration import DeleteConfiguration
    from pyvelo.client.schemas.enterprise import GetEnterpriseNetworkSegments
    from pyvelo.client.schemas.profiles import GetEnterpriseConfigurations
    from pyvelo_intent.config.pipeline import ConfigPipeline
    from ansible_collections.velocloud.api.plugins.module_utils.topology import (
        ProfileFirewallSpec,
        ProfileSpec,
        attach_segments_to_profile,
        create_profile_only,
        enable_console_firewall,
    )

    HAS_PYVELO = True
    PYVELO_IMPORT_ERROR = None
except ImportError as e:
    HAS_PYVELO = False
    PYVELO_IMPORT_ERROR = str(e)


def _profile_to_dict(prof) -> dict:
    return {
        "id": prof.id_,
        "name": prof.name,
        "description": getattr(prof, "description", None),
    }


async def _async_main(module: AnsibleModule, params: dict) -> dict:
    fw_dict = params.get("firewall") or {}
    spec = ProfileSpec(
        name=params["name"],
        description=params["description"],
        segments=params["segments"],
        firewall=ProfileFirewallSpec(**fw_dict),
    )
    enterprise_id = resolve_enterprise_id(params)
    state = params["state"]
    force = params["force"]
    check_mode = module.check_mode

    client = build_client(params)
    async with client:
        existing_list = await client.get_enterprise_configurations(
            GetEnterpriseConfigurations(enterprise_id=enterprise_id)
        )
        existing = next((p for p in existing_list if p.name == spec.name), None)

        if state == "absent":
            if existing is None:
                return {"changed": False}
            if not check_mode:
                await client.delete_enterprise_profile(
                    DeleteConfiguration(id_=existing.id_, enterprise_id=enterprise_id)
                )
            return {"changed": True, "profile": _profile_to_dict(existing)}

        # state == "present"
        spec_dict = {"name": spec.name, "description": spec.description}

        if existing is not None:
            drift = profile_drift(spec_dict, existing)
            if not drift:
                return {"changed": False, "profile": _profile_to_dict(existing)}

            if not force:
                module.warn(
                    f"Profile '{spec.name}' exists but drifts from spec; "
                    "pass force=true to delete and recreate. Note: this will not "
                    "compare attached segments or firewall settings."
                )
                return {
                    "changed": False,
                    "profile": _profile_to_dict(existing),
                    "drift": drift,
                }

            if not check_mode:
                await client.delete_enterprise_profile(
                    DeleteConfiguration(id_=existing.id_, enterprise_id=enterprise_id)
                )

        if check_mode:
            return {"changed": True, "profile": {"name": spec.name, "id": None}}

        # Create the profile
        profile_id = await create_profile_only(client, enterprise_id, spec)

        # Attach segments + apply firewall via the config pipeline
        if spec.segments or spec.firewall.console_enabled:
            pipeline = ConfigPipeline(client)
            cfg_state = await pipeline.load_profile(
                profile_id, enterprise_id=enterprise_id
            )

            if spec.segments:
                all_segments = await client.get_enterprise_network_segments(
                    GetEnterpriseNetworkSegments(enterprise_id=enterprise_id)
                )
                for seg_name in spec.segments:
                    seg_record = next(
                        (s for s in all_segments if s.name == seg_name), None
                    )
                    if seg_record is None:
                        module.warn(
                            f"Segment '{seg_name}' not found; skipping attachment."
                        )
                        continue
                    seg_meta = SegmentMetadata(
                        segment_id=seg_record.data.segment_id,
                        name=seg_record.name,
                        type_=seg_record.type_,
                        segment_logical_id=seg_record.logical_id,
                    )
                    attach_segments_to_profile(
                        cfg_state, seg_meta, seg_record.type_, seg_record.id_
                    )

            if spec.firewall.console_enabled:
                cfg_state = await enable_console_firewall(pipeline, cfg_state)

            await pipeline.save(cfg_state)

        return {
            "changed": True,
            "profile": {"id": profile_id, "name": spec.name},
        }


def main() -> None:
    argspec = common_argspec()
    argspec.update(
        state=dict(type="str", choices=["present", "absent"], default="present"),
        name=dict(type="str", required=True),
        description=dict(type="str", default=""),
        segments=dict(type="list", elements="str", default=[]),
        firewall=dict(type="dict", default={}),
        force=dict(type="bool", default=False),
    )

    module = AnsibleModule(
        argument_spec=argspec,
        supports_check_mode=True,
        **common_argspec_constraints(),
    )

    if not HAS_PYVELO:
        module.fail_json(msg=f"pyvelo SDK not available: {PYVELO_IMPORT_ERROR}")

    try:
        result = run_async(_async_main(module, module.params))
    except ValueError as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        import traceback

        module.fail_json(
            msg=f"velocloud.api.profile failed: {type(e).__name__}: {e}",
            exception=traceback.format_exc(),
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
