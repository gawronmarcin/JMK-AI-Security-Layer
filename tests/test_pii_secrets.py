"""Unit tests for pii_secrets.py (R2). All data is synthetic.

Run: pytest tests/test_pii_secrets.py -q
"""
from __future__ import annotations

import asyncio
import base64
import time

import pytest

from aicl.controls.pii_secrets import PiiInput, PiiOutput, SecretsInput, SecretsOutput
from aicl.models import Action, Origin, RequestContext, Segment, Stage

# ----------------------------- helpers -------------------------------------- #
PESEL = "44051401458"                      # synthetic, valid checksum
IBAN = "PL61 1090 1014 0000 0712 1981 2874"  # public documentation example
CARD = "4111 1111 1111 1111"               # public test card
AWS = "AKIAIOSFODNN7EXAMPLE"               # AWS documentation example
JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
       "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk")


def run(control, text, *, action="redact", stage=Stage.output, origin=Origin.assistant,
        decoded=(), cfg_extra=None):
    ctx = RequestContext(
        request_id="r", session_id="s", endpoint="chat", stage=stage, identity="t", role="t",
        profile="balanced", model="m", policy_version="v",
        segments=[Segment(idx=0, text=text, norm=text.lower(), decoded=list(decoded), origin=origin)])
    return asyncio.run(control().evaluate(ctx, {"action": action, **(cfg_extra or {})}))


def kinds(decision):
    return sorted({m.kind for m in decision.matches})


# ----------------------------- PII ------------------------------------------ #
@pytest.mark.parametrize("text,kind", [
    ("write to jan.kowalski@example.com please", "email"),
    (f"PESEL: {PESEL}", "pesel"),
    (f"IBAN {IBAN}", "iban"),
    (f"card {CARD}", "credit_card"),
    ("tel +48 600 123 456", "phone_pl"),
    ("call 600 123 456", "phone_pl"),
    ("host 192.168.1.10 down", "ip_address"),
])
def test_pii_negative_detected(text, kind):                       # negative = must be caught
    d = run(PiiOutput, text)
    assert kind in kinds(d) and d.action == Action.redact


@pytest.mark.parametrize("text", [
    "Order 123456789 shipped",              # bare 9 digits is not a phone
    "PESEL 44051401459",                    # wrong checksum
    "Card 4111 1111 1111 1112",             # fails Luhn
    "version 1.2.3.4.5",                    # 5 parts is not an IPv4
    "timestamp 1696350000000",              # 13 digits, not a card
    "IBAN PL00 0000 0000 0000 0000 0000 0000",  # fails mod-97
    "Please summarise the ticket for the customer.",
])
def test_pii_positive_passes(text):                               # positive = must pass
    assert run(PiiOutput, text).action == Action.allow


def test_pii_span_points_into_original_and_mask_hides_value():
    text = "mail jan.kowalski@example.com ok"
    m = run(PiiOutput, text).matches[0]
    assert text[m.start:m.end] == "jan.kowalski@example.com"
    assert "kowalski" not in m.masked


def test_iban_followed_by_uppercase_word_keeps_exact_span():
    text = f"IBAN {IBAN} THE end"
    m = run(PiiOutput, text).matches[0]
    assert text[m.start:m.end] == IBAN


def test_pii_input_ignores_system_prompt_but_scans_user():
    assert run(PiiInput, "a@b.com", stage=Stage.input, origin=Origin.system).action == Action.allow
    assert run(PiiInput, "a@b.com", stage=Stage.input, origin=Origin.user).action == Action.redact


def test_pii_types_param_restricts_detectors():
    d = run(PiiOutput, f"a@b.com {PESEL}", cfg_extra={"types": ["email"]})
    assert kinds(d) == ["email"]


def test_pii_action_follows_cfg():
    assert run(PiiOutput, "a@b.com", action="block").action == Action.block
    assert run(PiiOutput, "a@b.com", action="flag").action == Action.flag


# ----------------------------- secrets -------------------------------------- #
@pytest.mark.parametrize("text,kind", [
    (f"key {AWS}", "aws_access_key"),
    (f"Authorization {JWT}", "jwt"),
    ("password: hunter2x", "password_assignment"),
    ("hasło: Tajne123", "password_assignment"),
    ("api_key=sk_live_4eC39HqLyjWDarjtT1zdp7dc", "api_key_generic"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----", "private_key_block"),
])
def test_secrets_negative_detected(text, kind):
    d = run(SecretsOutput, text)
    assert kind in kinds(d) and d.action == Action.redact


@pytest.mark.parametrize("text", [
    "password: ********",
    "password = ${DB_PASSWORD}",
    "api_key = your_api_key_here_1234",
    "token: abcabcabcabcabcabc",
    "akiaiosfodnn7example",                 # secrets are case-sensitive
    "Reset your password in settings",
])
def test_secrets_positive_passes(text):
    assert run(SecretsOutput, text).action == Action.allow


def test_truncated_private_key_is_redacted_to_end():
    text = "x -----BEGIN PRIVATE KEY-----\nMIIabc"
    m = run(SecretsOutput, text).matches[0]
    assert m.end == len(text)


def test_secret_masks_never_contain_raw_value():
    d = run(SecretsOutput, f"{AWS} {JWT} password: hunter2x")
    blob = " ".join(m.masked for m in d.matches)
    assert AWS not in blob and JWT not in blob and "hunter2x" not in blob
    assert any(m.masked == "AKIA" + "*" * 16 for m in d.matches)


def test_decoded_only_secret_has_no_span_and_is_flagged():
    b64 = base64.b64encode(AWS.encode()).decode()
    d = run(SecretsInput, f"decode {b64}", stage=Stage.input, origin=Origin.user, decoded=[AWS])
    m = d.matches[0]
    assert m.in_decoded and m.start is None and m.end is None


def test_secret_in_text_and_decoded_reported_once():
    d = run(SecretsInput, AWS, stage=Stage.input, origin=Origin.user, decoded=[AWS])
    assert len(d.matches) == 1 and not d.matches[0].in_decoded


def test_plain_secret_does_not_hide_different_encoded_secret_of_same_kind():
    other = "AKIA" + "B7Q2M4XK9P3L8W1Q"  # second, different key; split so scanners don't flag the repo
    d = run(SecretsInput, f"{AWS} and more", stage=Stage.input, origin=Origin.user, decoded=[other])
    assert [m.in_decoded for m in d.matches] == [False, True]


def test_threat_ids_come_from_policy_cfg():
    d = run(SecretsOutput, f"key {AWS}", cfg_extra={"threat_ids": ["TH-99"]})
    assert d.threat_ids == ["TH-99"]
    assert run(SecretsOutput, f"key {AWS}").threat_ids == ["TH-04"]  # fallback without policy


def test_pii_does_not_scan_decoded_view():
    d = run(PiiOutput, "nothing here", decoded=["jan@example.com"])
    assert d.action == Action.allow


# ----------------------------- performance (target, not a claim) ------------ #
def test_hot_path_is_cheap_and_no_pathological_backtracking():
    typical = "Please summarise the ticket for the customer. " * 45     # ~2 KB
    # Warmup
    for _ in range(5):
        run(PiiOutput, typical); run(SecretsOutput, typical)
    samples = []
    for _ in range(5):
        t0 = time.perf_counter()
        for _ in range(20):
            run(PiiOutput, typical); run(SecretsOutput, typical)
        samples.append((time.perf_counter() - t0) * 1000 / 40)
    per_eval_ms = sorted(samples)[len(samples) // 2]
    assert per_eval_ms < 15, per_eval_ms
    for nasty in ["1 " * 50_000, "a" * 200_000, "-----BEGIN PRIVATE KEY-----" * 2000]:
        t0 = time.perf_counter(); run(PiiOutput, nasty); run(SecretsOutput, nasty)
        assert time.perf_counter() - t0 < 2.0
