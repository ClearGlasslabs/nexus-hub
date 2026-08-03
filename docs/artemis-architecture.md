# ClearGlassInc Artemis: governed intelligence platform

## Diagnosis

The incident template contains no concrete stack, symptom, expected/actual result,
environment, or evidence. An exact root cause would therefore be invented. The
minimum diagnostic input is: **one failing correlation/trace ID, UTC time window,
deployment version, environment, expected result, and observed result**. Until
then, the most probable failure domain in this event-driven design is an
API/data-flow or deployment/configuration contract violation at a boundary.

Trace a failure from UI `traceparent` -> gateway request -> AIP workflow run ->
Foundry object/action transaction -> stream offset -> Gotham operational object.
At every boundary record input/output schema version, ontology version, policy
decision ID, artifact digest, and latency. Compare a failing trace with a known-good
trace from the same compartment. This separates deterministic contract faults from
intermittent, load-sensitive timing faults.

### Ranked hypotheses and proof plan

| Rank | Hypothesis | Impact | Prove or disprove |
|---|---|---:|---|
| 1 | Ontology/API schema drift or partial deployment | High | Compare Apollo release manifests and Foundry ontology/action versions; validate payloads at ingress and egress. |
| 2 | Policy context/coalition markings missing | High | Correlate deny decision IDs; replay authorization with the same subject, purpose, mission, and object labels. Never log raw sensitive attributes. |
| 3 | Stale cache/search index | Medium | Compare authoritative object revision with cache/index revision and force a scoped cache bypass. |
| 4 | Async race, duplicate, or out-of-order event | High | Inspect event ID, aggregate sequence, producer time, ingest time, partition, offset, retry, and idempotency record. |
| 5 | External model/tool timeout or contract change | Medium | Inspect spans, circuit-breaker state, retry budget, tool schema validation, and model-router fallback choice. |

Add runtime assertions for mission ID, classification, ontology version, event ID,
and artifact digest. Inspect browser network timing and response bodies, set
breakpoints before action submission and after state reconciliation, query the
dead-letter stream and idempotency store, and compare environment variables by
**names and digests**, not secret values. The smallest safe response is to halt the
affected rollout, pin the last known-good immutable artifact, and replay only
idempotent events after validating the mismatch.

## System Architecture

```text
Analyst UI / Commander UI (Next.js, live map, cases, approvals)
  -> mTLS API gateway (OIDC, purpose-of-use, rate/size/schema gates)
    -> Python mission API / workflow coordinator / policy decision point
      -> AIP Logic workflows + governed model/tool router
      -> Foundry Ontology objects, links, actions, functions
      -> Gotham investigations, tracks, operational intelligence
      -> event bus (partition by mission/aggregate; schema registry; DLQ)
    -> retrieval broker (lexical + vector + geotemporal; authorization before rank)
Foundry pipelines -> lakehouse bronze/silver/gold -> ontology projections
Telemetry -> OpenTelemetry traces/metrics/logs + evaluation and audit dashboards
Apollo -> signed promotion, environment policy, canary, health gate, rollback
```

**Gotham** is the operational investigation and entity-tracking surface.
**Foundry** integrates governed data and exposes business semantics through the
**Ontology** (typed objects, links, actions, and functions). **AIP** hosts governed
LLM-assisted workflows, agents, tools, and evaluations. **Apollo** continuously
deploys signed versions across disconnected and heterogeneous environments while
enforcing rollout and rollback policy.

The UI never calls a model or data store directly. The gateway propagates W3C trace
context and an authorization context. Services are stateless; long-running work is
a durable state machine. Every command has an idempotency key. Every emitted event
uses an outbox transaction and carries `event_id`, `aggregate_id`, `sequence`,
`schema_version`, `occurred_at`, `mission_id`, markings, and lineage references.

## Data and Ontology

Core objects are `Entity`, `Observation`, `Source`, `Location`, `Event`, `Track`,
`Mission`, `Case`, `Hypothesis`, `Assessment`, `Alert`, `IntelProduct`,
`ActionPackage`, `OperatorDecision`, `Feedback`, `WorkflowRun`, `ModelRun`,
`EvaluationRun`, and `ChangeCandidate`. Links are temporal and typed: `OBSERVED_AT`,
`DERIVED_FROM`, `SAME_AS`, `ASSOCIATED_WITH`, `SUPPORTS`, `CONTRADICTS`,
`PART_OF_MISSION`, and `PRODUCED_BY`.

Facts are append-only assertions, not destructive truth updates:

```sql
CREATE TABLE assertion (
  assertion_id UUID PRIMARY KEY,
  subject_id UUID NOT NULL,
  predicate TEXT NOT NULL,
  object_json JSONB NOT NULL,
  valid_from TIMESTAMPTZ NOT NULL,
  valid_to TIMESTAMPTZ,
  observed_at TIMESTAMPTZ NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  confidence NUMERIC(5,4) CHECK (confidence BETWEEN 0 AND 1),
  source_id UUID NOT NULL,
  derivation_id UUID,
  mission_id UUID NOT NULL,
  classification TEXT NOT NULL,
  compartments TEXT[] NOT NULL,
  releasability TEXT[] NOT NULL,
  ontology_version TEXT NOT NULL
);
```

Confidence is calibrated and decomposed into source reliability, information
credibility, corroboration, and model uncertainty; it is never authorization.
Bitemporal state distinguishes when a claim was valid from when Artemis learned
it. Lineage forms a DAG from source bytes and transform versions to assertion and
product. Entity resolution retains candidates and evidence rather than silently
merging identities. Ontology actions (`OpenCase`, `AttachEvidence`,
`SubmitAssessment`, `ApproveActionPackage`) validate invariants and policy, giving
humans and agents the same governed verbs.

## AI and Agent Design

The analyst copilot retrieves cited, permitted evidence; explains contradictions;
and drafts assessments. The commander copilot summarizes mission state, options,
uncertainty, and dissent. A coordinator executes bounded roles: triage -> enrich ->
resolve entities -> correlate -> challenge -> summarize -> recommend. Agents share
artifact references, not hidden conversational memory.

Tools have typed input/output, short-lived delegated credentials, classification
ceilings, time/cost limits, and audit hooks. Read tools may query ontology or
retrieval. Draft tools may create an unsubmitted product. Actions affecting cases,
alerts, dissemination, tasking, or operations stop at an explicit approval state.
No model can approve its own output, alter policy, expand its tools, or promote a
candidate. Treat retrieved text as untrusted data and reject tool instructions
inside it.

```text
RECEIVED -> TRIAGED -> ENRICHED -> CORRELATED -> DRAFTED
  -> AWAITING_HUMAN_APPROVAL -> APPROVED -> EXECUTED -> VERIFIED
                              \-> REJECTED
Any state -> QUARANTINED (policy/schema/integrity fault)
```

The router chooses only from an approved catalog using data classification,
mission latency SLO, capability, observed quality, and cost. It records selection
features and fallback reason. Timeouts are deadline-derived; retries are bounded,
jittered, and restricted to safe/idempotent calls. Circuit breakers prevent retry
storms.

## Self-Improvement Loop

1. Capture structured feedback (accept/edit/reject plus reason), corrections,
   queries, alert disposition, workflow outcomes, latency, and mission results.
2. De-identify where possible, preserve sampling weights, and join outcomes to the
   exact prompt, workflow, model, tool, policy, ontology, and dataset versions.
3. Build leakage-controlled, time-split evaluation sets with mission-owner review.
4. An offline optimizer proposes a prompt patch, workflow graph change, heuristic,
   or router policy. It cannot change goals, permissions, approval gates, or itself.
5. Run deterministic unit/contract tests, frozen mission evals, safety/red-team
   suites, subgroup calibration, latency/load tests, and shadow replay.
6. Package candidate plus evidence as signed immutable artifacts. Independent
   mission, model-risk, and security reviewers approve according to risk tier.
7. Apollo deploys shadow -> small canary -> progressive rollout. Automated gates
   watch precision, recall, false-negative cost, calibration error, p95 latency,
   policy violations, override rate, and operator trust.
8. Roll back automatically to the pinned baseline on a hard safety signal or
   statistically credible regression. Preserve decisions in an append-only,
   externally anchored audit log.

Use champion/challenger assignment only within equivalent policy boundaries.
Analyze experiments sequentially with predeclared metrics and guardrails; never
optimize click acceptance alone. Drift monitors cover input distributions,
label/outcome delay, ontology coverage, retrieval quality, calibration, and
operator cohorts. Human edits become training signals only after provenance and
quality checks, preventing automation bias and feedback poisoning.

## Full-Stack Implementation

Suggested repository boundaries:

```text
apps/web/                 Next.js server components, maps, cases, approval UX
services/mission_api/     Python FastAPI commands/queries and SSE subscriptions
services/orchestrator/    durable workflows, outbox, idempotency, compensation
services/retrieval/       policy-filtered hybrid/geotemporal retrieval
services/evaluation/      datasets, scorers, experiment analysis, drift monitors
packages/contracts/       generated JSON Schema/OpenAPI/AsyncAPI clients
policy/                   reviewed policy-as-code and classification lattice
foundry/                  pipelines, ontology definitions, actions/functions
apollo/                   signed release channels, canary and rollback policy
```

A command handler authenticates the human, validates at trust boundaries, obtains
an authorization decision, and commits state plus outbox atomically. A consumer
first inserts `(consumer, event_id)` into an idempotency ledger, rejects sequence
gaps to quarantine, applies the transition, and advances the checkpoint in one
transaction. The UI reconciles server-authoritative revisions rather than assuming
optimistic writes succeeded.

An ontology query is always scoped before retrieval:

```python
def visible_alerts(client, principal, mission_id, since):
    decision = policy.authorize(
        principal=principal, action="Alert.read", resource={"mission": mission_id},
        purpose="mission_operations",
    )
    decision.require_allowed()
    return client.objects.Alert.where(
        missionId=mission_id,
        updatedAt={"gte": since},
        markings={"within": decision.maximum_markings},
    ).order_by("updatedAt", "desc").take(200)
```

The reference Python controller in `artemis/improvement.py` makes promotion
fail-closed, binds approvals to candidate content, requires independent approvers,
and emits a deterministic evidence digest. Production persistence should enforce
separation of duties and signatures outside the application process.

## Security and Governance

OIDC/WebAuthn identifies users; workload identity and mTLS identify services.
Authorization combines RBAC duties with ABAC labels, mission membership,
need-to-know, purpose-of-use, compartments, nationality/releasability, and temporal
constraints. Enforce policy at gateway, service, Foundry Ontology action, search
filter, and export—not just in the UI. Apply row/entity security before retrieval,
column/property masking before prompt construction, and output policy after model
generation.

Use per-compartment encryption keys, egress allowlists, confidential secret stores,
short-lived credentials, signed builds/SBOMs, admission policy, read-only roots,
and isolated tool runners with no ambient network. Logs are structured, redacted,
hash-chained, retention-controlled, and forwarded to an immutable store. Prompt,
model, dataset, policy, ontology, workflow, and code versions are first-class audit
fields. Break-glass access is time-bound, dual-authorized, alerted, and reviewed.

## Regression tests

* Contract tests for every OpenAPI, event schema, Foundry action, and tool version.
* Property tests for classification lattice noninterference and temporal queries.
* Duplicate, reorder, delay, timeout, retry-storm, and partition fault injection.
* Cross-tenant/compartment retrieval tests proving zero unauthorized candidates.
* Golden trace replay from gateway through ontology and event consumption.
* Candidate-gate tests for stale approvals, missing evals, metric regressions,
  policy failures, unknown risk tiers, and deterministic audit digests.
* Apollo canary rollback drills and restoration/replay verification.

Hidden risks include delayed outcome labels, correlated model graders, stale vector
indexes, partial ontology migrations, cached authorization, clock skew, poison-pill
events, duplicate side effects, prompt injection through source documents, and a
canary population that excludes difficult missions.

## Scenario Walkthrough

At 02:14:07Z a coalition sensor observation arrives with source signature,
classification labels, event ID, and aggregate sequence. Foundry validates its
schema, stores immutable raw bytes, derives normalized assertions, and projects an
ontology `Observation`; the outbox publishes its reference. Gotham associates it
with an active track. The triage workflow detects unusual motion, retrieves only
mission-authorized historical tracks, and opens a draft alert.

Enrichment agents query weather and track history through governed tools. The
correlator proposes—but does not silently merge—an identity at 0.78 calibrated
confidence. A challenger cites conflicting evidence. The commander copilot creates
an action package containing options, sources, uncertainty, dissent, and expected
consequences. Because dissemination is operationally significant, the workflow
halts at `AWAITING_HUMAN_APPROVAL`.

The operator rejects the identity, links the correct entity, selects reason
`temporal_impossibility`, and approves only a watch action. Artemis records both
decisions and later joins the verified outcome. Offline evaluation discovers that
the resolver overweights spatial similarity when timestamps have high uncertainty.
It proposes a bounded scoring/prompt change, builds a time-split evaluation set,
and shows improved precision without recall or latency regression. Reviewers
approve the content-bound candidate; Apollo shadows it, canaries it, and promotes
it. The baseline remains pinned for instant rollback. The platform has improved a
specific governed behavior without changing its mission, authority, or approval
requirements.

## Recommended fix for the unspecified incident

Do not change production behavior until the requested trace bundle exists. First,
add or verify end-to-end correlation and boundary version fields, capture one
failing and one successful trace, and compare them. If schema/release mismatch is
confirmed, roll back the single incompatible consumer or pin the compatible
contract—the smallest safe change. Long term, generate clients from versioned
contracts, require compatibility checks in CI, deploy producers before consumers
when appropriate, and use Apollo progressive delivery with automated golden-trace
and rollback gates.
