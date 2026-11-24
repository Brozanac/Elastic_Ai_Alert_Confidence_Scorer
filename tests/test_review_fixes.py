import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import llm_explainer
from main import app
from scorer import detect_alert_type, is_external_ip

client = TestClient(app)
SAMPLES = Path(__file__).resolve().parents[1] / "sample_alerts"


def load_sample(name: str) -> dict:
    return json.loads((SAMPLES / name).read_text())


# --- Bug 1: network / file alerts were classified as process_execution -----

@pytest.mark.parametrize(
    "sample, expected_type",
    [
        ("network_sensitive_port.json", "network"),
        ("suspicious_file_download.json", "file_or_malware"),
    ],
)
def test_api_classifies_non_process_alerts_correctly(sample, expected_type):
    response = client.post("/score-alert/full", json=load_sample(sample))

    assert response.status_code == 200
    body = response.json()
    assert body["alert_type"] == expected_type
    assert body["confidence"]["score"] > 0


def test_empty_process_block_is_not_process_execution():
    alert = {"process": {"parent": {}}, "network": {"direction": "outbound"}}
    assert detect_alert_type(alert) == "network"


def test_real_process_is_still_process_execution():
    alert = {"process": {"name": "powershell.exe", "parent": {}}}
    assert detect_alert_type(alert) == "process_execution"


def test_empty_file_placeholder_does_not_hide_privilege_escalation():
    alert = {
        "rule": {"name": "Possible Privilege Escalation via Admin Group Change"},
        "process": {"parent": {}},
        "file": {"hash": {}},
    }
    assert detect_alert_type(alert) == "privilege_escalation"


# --- Bug 2: internal IPs were matched by text prefix ------------------------

CONTEXT = {"trusted_internal_subnets": ["10.", "192.168.", "172.16.0.0/12"]}


@pytest.mark.parametrize(
    "ip, external",
    [
        ("10.1.2.3", False),
        ("192.168.0.5", False),
        ("172.20.1.1", False),      # inside 172.16.0.0/12
        ("100.1.2.3", True),        # "10" text prefix trap, but public
        ("10.evil.example", True),  # not an IP at all
        ("8.8.8.8", True),
    ],
)
def test_is_external_ip_uses_real_networks(ip, external):
    assert is_external_ip(ip, CONTEXT) is external


def test_malformed_ip_value_does_not_crash():
    # A list is not a valid IP: we cannot prove it is internal, so it counts as external.
    assert is_external_ip(["8.8.8.8"], CONTEXT) is True


def test_invalid_subnet_entry_is_skipped_not_crashing():
    context = {"trusted_internal_subnets": ["fd00:", "not-a-subnet", "10."]}
    assert is_external_ip("10.0.0.1", context) is False
    assert is_external_ip("8.8.8.8", context) is True


# --- Bug 3: /environment-context exposed admin users without auth -----------

def test_environment_context_requires_api_key(monkeypatch):
    monkeypatch.setenv("APP_API_KEY", "test-key")
    assert client.get("/environment-context").status_code == 401

    ok = client.get("/environment-context", headers={"X-API-Key": "test-key"})
    assert ok.status_code == 200


# --- Bug 4: missing APP_API_KEY let everyone in (fail-open) -----------------

def test_protected_endpoints_fail_closed_without_configured_key(monkeypatch):
    monkeypatch.delenv("APP_API_KEY", raising=False)
    monkeypatch.delenv("ALLOW_UNAUTHENTICATED", raising=False)

    assert client.get("/alerts/history").status_code == 401
    assert client.get("/environment-context").status_code == 401


def test_explicit_dev_opt_out_allows_access(monkeypatch):
    monkeypatch.delenv("APP_API_KEY", raising=False)
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "true")

    assert client.get("/environment-context").status_code == 200


# --- Bug 5: secrets were sent to the external LLM unredacted ----------------

def test_llm_prompt_is_redacted_before_leaving_the_system(monkeypatch):
    monkeypatch.setattr(llm_explainer, "is_llm_configured", lambda: True)

    fake_client = MagicMock()
    fake_client.responses.create.return_value = MagicMock(output_text="ok")

    alert = {
        "rule": {"name": "PowerShell with secret", "severity": "high"},
        "process": {
            "name": "powershell.exe",
            "command_line": "powershell -c password=SuperSecret123 api_key=sk-test12345678901234567890",
        },
    }

    with patch.object(llm_explainer, "OpenAI", return_value=fake_client):
        llm_explainer.generate_llm_explanation(
            alert,
            {"evidence": ["Seen token=abcdef1234567890 in args"]},
            {},
            [],
        )

    sent_prompt = fake_client.responses.create.call_args.kwargs["input"]
    assert "SuperSecret123" not in sent_prompt
    assert "sk-test12345678901234567890" not in sent_prompt
    assert "abcdef1234567890" not in sent_prompt  # secret inside score_result
    assert "[REDACTED]" in sent_prompt
