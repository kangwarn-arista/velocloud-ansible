"""Static checks for collection examples: YAML parses and site data stays generic."""

from pathlib import Path
import re

import yaml

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"

# Customer names, lab passwords, and CGNAT/link-local lab prefixes must not leak.
FORBIDDEN = (
    re.compile(r"paypal", re.I),
    re.compile(r"vcadm", re.I),
    re.compile(r"velocloud123", re.I),
    re.compile(r"100\.64\."),
    re.compile(r"169\.254\.129"),
    re.compile(r"arista act", re.I),
    re.compile(r"console_pass", re.I),
    re.compile(r"api_password", re.I),
)

STANDALONE_PLAYBOOKS = (
    "create_gateways.yml",
    "create_enterprise.yml",
    "generate_token.yml",
    "create_segment_and_profile.yml",
    "create_edges.yml",
    "configure_cloudvpn.yml",
    "configure_bizpolicy.yml",
)


def _yaml_files():
    return sorted(p for p in EXAMPLES.rglob("*.yml") if ".tokens" not in p.parts)


def test_example_yaml_parses():
    files = _yaml_files()
    assert files
    for path in files:
        loaded = yaml.safe_load(path.read_text())
        assert loaded is not None, path


def test_example_files_are_anonymized():
    for path in _yaml_files():
        text = path.read_text()
        for pattern in FORBIDDEN:
            match = pattern.search(text)
            assert match is None, f"{path} contains {pattern.pattern!r}: {match.group(0)!r}"


def test_standalone_playbooks_run_on_controller():
    for name in STANDALONE_PLAYBOOKS:
        plays = yaml.safe_load((EXAMPLES / name).read_text())
        assert plays[0]["hosts"] == "localhost"
        assert plays[0]["connection"] == "local"


def test_example_playbooks_are_unnumbered():
    names = {path.name for path in EXAMPLES.glob("*.yml")}
    assert names == set(STANDALONE_PLAYBOOKS)
    assert not any(name[0].isdigit() for name in names)
    assert "site.yml" not in names
    assert "configure.yml" not in names
