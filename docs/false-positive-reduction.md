# False Positive Reduction in FrameSeven

## Architecture (implemented in prompts 05-07)

FrameSeven uses a Detect → Verify → Score → Gate pipeline:

1. **Detect** — a tool produces a hypothesis (potential finding).
2. **Verify** — generic signal modules (Baseline, Differential, ShapeValidator,
   StaticAssetGuard) corroborate or reject the hypothesis.
3. **Score** — verified findings receive a confidence score (0..1).
4. **Gate** — only confirmed findings with confidence ≥ 0.6 enter the main
   report body. Lower-confidence findings go to a separate appendix.

## Confidence scoring guide

| Source                          | Confidence |
|---------------------------------|------------|
| OOB callback received (future)  | 1.0        |
| Sensitive data extracted        | 1.0        |
| Strong marker present (passwd)  | 1.0        |
| Differential + shape validation | 0.8 - 0.9  |
| Boolean SQLi confirmed          | 0.85       |
| Time-based with replay          | 0.75       |
| Indirect signal only            | 0.6        |
| No verification                 | 0.0 - 0.3  |

## Deferred work

### OOB (Out-Of-Band) callback infrastructure

Blind injection classes (blind SQLi, blind SSRF, blind XXE without echo)
cannot be confirmed beyond reasonable doubt without an OOB channel. The
target server is forced to make an outbound DNS/HTTP request to an
attacker-controlled domain; receipt of that callback is irrefutable proof.

Implementing this requires:
- An authoritative DNS server logging queries to *.frameseven-oob.example
- An HTTP listener with TLS
- Per-probe unique subdomain generation and correlation
- Async wait/timeout handling in scanners

Alternative: integrate with ProjectDiscovery's interactsh client.

**Until OOB lands, blind findings cap at confidence 0.75 and are flagged
with status=needs_review by default.**

### CI regression corpus

A labeled corpus of FP and TP fixtures (mock HTTP servers replaying
real-world scenarios that caused FPs) should run in CI on every change
to the detection or verification code. The build fails if precision drops
below the established floor.

Initial corpus to build from:
- Catch-all hosts: /.env returning homepage HTML
- IDOR on cache-busting params (?v=, ?width=)
- SPA index.html returned for /admin, /actuator, etc.
- Static asset endpoints versioned with hashes

This is deferred as a separate workstream.
