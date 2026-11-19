"""Controlled synthetic MI input for an installed Router acceptance harness.

Use the exact MI dependency pinned by Dockerfile.mi. This module does not install
or authenticate dependencies, start services, or assert anything about real models.
"""

from datetime import datetime, timezone
from dataclasses import replace
from decimal import Decimal
import hashlib
from pathlib import Path

MI_REVISION = "d65891668b7e79f7b666c021f02a1b4bf8c4ca9c"
EVALUATED_AT = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
PRODUCED_AT = datetime(2026, 10, 26, 11, 59, tzinfo=timezone.utc)
MAX_BYTES = 256 * 1024
EXPECTED_SHA256 = "c63233c4ad8ccd79f87ea01e18e0d79559f8802474f399442f0e8a99d67db74f"
VARIANT_SHA256 = {
    "stale": "fcfd20a3e30abb80adf63291f62772318ec444ff2f93bc654cb7e62ae7e64691",
    "withdrawn": "c7090c7fdf6670fec532bef0ada37cad74b734d398f8d167dc98fecd1b878c12",
    "incompatible": "e8fdf18ef2b2b77586b237b8cc490af6293e60c651741874dbf3e4782599b1aa",
}
TRUST_SHA256 = {
    "fresh": "1ece5e277ee0296701f111f08f765f5da27642ce206cd4bb6f68fc9959c32f99",
    "stale": "bea868e5cfbf88f9b1aa2a641516e3dfe29862f0f252fd57ddbd5c07a6875a99",
    "withdrawn": "898b621ba176b2fe0b957809125d189f6b7ad0609a9f60d25f5a010e98eac056",
    "incompatible": "9f3c6ef8fede8875ca9343b39ef6c37f4c2fe3171b031dd7a590e1ff68cae117",
}
PAYLOAD_SCHEMA = "mi.public-evidence-working/2"


def validate_cut(kind, cut):
    """Validate both independently pinned inputs at installed boundaries."""
    expected = {"fresh": EXPECTED_SHA256, **VARIANT_SHA256}
    if (kind not in expected or not isinstance(cut, tuple) or len(cut) != 2 or
            not all(isinstance(part, bytes) and len(part) <= MAX_BYTES for part in cut) or
            hashlib.sha256(cut[0]).hexdigest() != expected[kind] or
            hashlib.sha256(cut[1]).hexdigest() != TRUST_SHA256[kind]):
        raise ValueError("invalid independently pinned MI publication or trust reference mismatch")


def evidence():
    """Construct original public test evidence, without acquiring any source."""
    from model_intelligence.contract import Applicability, PublicEvidence
    from model_intelligence.evidence import Evidence, Model, ModelClaim, NativeLimit, Observation

    configuration = (("reasoning_effort", "high"), ("variant", "high"))
    # The identity is used only to exercise a configured Router association.
    # The asserted limit, interface and provenance are invented test data.
    subject = Model(
        "foundry-synthetic-id", "openai", "gpt-6-sol",
        revision="fixture-1", channel="worker_bridged",
        interface_id="foundry-synthetic-api", interface_provider_id="foundry-synthetic-provider",
        interface_version="1", configuration=configuration,
    )
    scope = Applicability(
        "foundry-controlled-fixture/1", subject.channel, configuration,
        frozenset({"foundry-synthetic-source"}),
    )
    observation = Observation(
        "foundry-observation-1", "foundry-synthetic-source", "community", "documentation",
        "https://example.invalid/foundry-controlled-fixture", datetime(2026, 10, 25, tzinfo=timezone.utc),
        "public", "foundry-owned-synthetic", observed_at=datetime(2026, 10, 25, tzinfo=timezone.utc),
        # An artificial test window, not a real-source freshness policy.
        fresh_until=datetime(2100, 1, 1, tzinfo=timezone.utc),
    )
    limit = NativeLimit("foundry.input", "input-allowance", Decimal("4096"), "tokens", "fixture-basis", "advertised")
    claim = ModelClaim(subject, limit, claim_id="foundry-claim-1", observation_id=observation.observation_id,
                       effective_from=observation.retrieved_at)
    return PublicEvidence(scope, Evidence((observation,), (claim,)), ((observation.observation_id, "fixture-1"),))


def evidence_variant(kind):
    """Return a controlled negative cut without changing its subject or scope."""
    from model_intelligence.contract import SourceNotice

    public = evidence()
    observation = public.evidence.observations[0]
    if kind == "stale":
        return replace(public, evidence=replace(public.evidence, observations=(
            replace(observation, fresh_until=datetime(2026, 10, 26, tzinfo=timezone.utc)),
        )))
    if kind == "withdrawn":
        return replace(public, notices=(SourceNotice(
            "critical", observation.observation_id, frozenset({"statement:foundry-claim-1"}),
            EVALUATED_AT, "revocation", True,
        ),))
    if kind == "incompatible":
        return replace(public, applicability=replace(public.applicability, scope_id="foundry-incompatible-fixture/1"))
    raise ValueError("unknown synthetic evidence variant")


def publish_fixture(directory: Path, *, publication_path: str, kind: str = "fresh"):
    """Publish into an existing directory and return strict Router trust configuration.

    publication_path is the path visible to the eventual Router process, not
    necessarily the host path. The caller independently protects the resulting
    trust configuration and verifies the installed MI revision.
    """
    from model_intelligence.contract import encode_public_evidence
    from model_intelligence.producer import publish, retained
    from model_intelligence.publication import CutReference

    expected_digest = EXPECTED_SHA256 if kind == "fresh" else VARIANT_SHA256[kind]
    expected = CutReference(1, PAYLOAD_SCHEMA, expected_digest)
    public = evidence() if kind == "fresh" else evidence_variant(kind)
    data, encoded = encode_public_evidence(public, produced_at=PRODUCED_AT, payload_schema=PAYLOAD_SCHEMA)
    if encoded != expected:
        raise ValueError("controlled-fixture-reference-mismatch")
    actual = publish(directory, public, expected=public.applicability, produced_at=PRODUCED_AT, max_bytes=MAX_BYTES)
    if actual != expected or retained(directory, max_bytes=MAX_BYTES) != (data, expected, public):
        raise ValueError("controlled-fixture-publication-mismatch")
    subject = public.evidence.claims[0].subject
    return {
        "schema_version": 1,
        "publication": publication_path,
        "reference": {"format_version": 1, "payload_schema": PAYLOAD_SCHEMA, "sha256": expected_digest},
        "scope": {"scope_id": public.applicability.scope_id, "channel": subject.channel,
                  "configuration": dict(subject.configuration), "source_ids": sorted(public.applicability.source_ids)},
        "bindings": [{
            "identity": {"provider": subject.provider_id, "model": subject.provider_model_id, "variant": "high"},
            "subject": {"model_id": subject.model_id, "provider_id": subject.provider_id,
                        "provider_model_id": subject.provider_model_id, "physical_model_id": subject.physical_model_id,
                        "revision": subject.revision, "channel": subject.channel, "interface_id": subject.interface_id,
                        "interface_provider_id": subject.interface_provider_id, "interface_version": subject.interface_version,
                        "configuration": dict(subject.configuration)},
            "dimension": "foundry.input", "meaning": "input-allowance", "basis": "fixture-basis",
        }],
        "max_bytes": MAX_BYTES,
    }
