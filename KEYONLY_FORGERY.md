# A key-only universal forgery, and why each fix closes its own door

Reproduce with `make attack` (Target 3) or `tests/test_keyonly_attack.py`.

## Summary

Section IV-B of Qiao et al. documents a forgery that needs an attacker who is
either a malicious KGC or who has captured one honest signature. Neither is
necessary. An outsider who has seen **nothing but the target's public key** —
no certificate, no signature, no interaction with anyone — can forge a valid
Verma et al. signature on a message of their own choosing, for that specific
target.

In the standard taxonomy of Goldwasser, Micali and Rivest ("A Digital
Signature Scheme Secure Against Adaptive Chosen-Message Attacks," *SIAM J.
Computing* 17(2), 1988), attacks are classified by what the adversary is given
— a **key-only attack** sees nothing but the public key — and forgeries by
what results — a **universal forgery** is valid on an arbitrary,
verifier-chosen message. Key-only attack plus universal forgery is the
strongest possible combination: nothing about the attacker's access is
weaker, nothing about the result is more damaging.

## The mechanism

Verma's single-signer verification is

```
z*P == R + h0*P_TA + v*pk,     h0 = H0(id, pk),   v = H1(m, pk, id, Delta)
```

`R` appears with coefficient 1, and **neither `h0` nor `v` depends on `R`**.
Given the target's identity and public key — no discrete log needed — both
`h0` and `v` are computable from public information alone. Fix any `z` (say
0), and the equation becomes a single linear statement in the one remaining
unknown:

```
R := z*P - h0*P_TA - v*pk
```

Ordinary point arithmetic. No discrete log, no signature, no interaction.

This is the same principle by which a Schnorr signature breaks completely if
the challenge is `H(m)` instead of `H(R, m)`: omitting the commitment from the
hash leaves it a free variable a linear equation can be solved for. Every
standard treatment of Schnorr signatures hashes the commitment together with
the message for exactly this reason — confirmed independently in, e.g.,
University of Illinois CS/ECE 498AC3 (Khurana, Fall 2020, Lecture 13), which
gives the canonical construction as `c <- H(m, u_t)`.

## Why the repaired scheme resists it

```
z*P == T + u*R + u*h0*P_TA + v*pk
h0 = H0(id, pk, R),  u = H2(m, pk, R, id, T, Delta),  v = H1(m, pk, R, id, T, Delta)
```

`R` is now an argument to all three hashes, so `h0`, `u` and `v` cannot be
computed until `R` is fixed — but solving the linear equation for `R` requires
knowing them first. `attempt_keyonly_forge_fixed` runs this as a fixed-point
search — guess `R`, compute the hashes, solve for what `R` would then need to
be, check for a match — and every candidate across 16 rounds is distinct.
Forging reduces to finding a fixed point of a random oracle over a 2^256
space: exhaustive search, not algebra.

The symmetric direction is checked too: holding `R` fixed and solving for `T`
instead does not converge either, since `u` and `v` also depend on `T`.

## Which fix closes which door — verified, not assumed

The scheme applies two corrections at once (§V-A, and see `ablation.py`), so
"the attack fails" does not by itself say which one is responsible. Two
single-fix ablations answer it precisely:

| | `R` bound everywhere | `R` **not** bound |
|---|---|---|
| **`T` bound everywhere** | real scheme: neither door open | `ablation_r.py`: open via **R** |
| **`T` not bound** | `ablation.py`: open via **T** | Verma: open via **R** (no `T` exists) |

Every cell is executable code, not inference:

- **Real scheme** (`scheme.py`): `attempt_keyonly_forge_fixed` fails solving for
  either `R` or `T`.
- **`ablation_r.py`** (Fix #1 alone removed — `R` dropped from `H0`, `H1`, `H2`,
  `T` still bound): `forge_keyonly` solves for `R` and succeeds;
  `attempt_solve_for_t_ablation_r` confirms `T` stays protected.
- **`ablation.py`** (Fix #2 alone removed — `T` dropped from `H1`/`H2`, `R`
  still bound): `forge_keyonly_via_t` solves for `T` and succeeds;
  `attempt_solve_for_r_ablated` confirms `R` stays protected.
- **Verma**: `forge_verma_keyonly` solves for `R` (its only commitment) and
  succeeds.

**Each fix is independently responsible for closing its own free variable's
door, and does nothing to protect the other's.** This is a cleaner and more
general statement than the project's earlier finding that "Fix #2 alone
defeats the observed-signature rescaling attack" (`ablation.py`'s original
purpose) — that finding is still correct, but it now has a companion: Fix #2
*also* independently closes a **simpler** attack against the same ablation,
one that needs no observed signature at all. The rescaling forgery already in
`attack.py` was not the weakest attack available against that variant.

## What this does not change

The paper's own security theorem is not contradicted — the repaired scheme
resists this attack, matching what Lemma 2/3's EUF-CMA claims would already
imply if trusted, since a key-only attack is strictly weaker than the
chosen-message attack the proof covers. This is a construction that makes an
implicit consequence of the proof concrete and explicit, and it identifies a
second, independent way the *specific* mechanism (binding a fresh commitment
into the hash) is load-bearing — not a second scheme-breaking bug in the
repaired construction.

It does sharpen the paper's own stated design principle (quoted in
`attack.py`'s docstring, about binding the signing nonce `T`) into a more
general one: **any commitment that appears in a verification equation without
being bound into a hash is a free variable, and a free variable with a known
coefficient can be solved for.** The paper states this for `T` alone, in the
context of the one attack it found; the mechanism is identical for `R`, and
for either variable in isolation.

## Reproducing

```bash
.venv/bin/python -m cbas.sidebyside          # Target 3
.venv/bin/python -m pytest tests/test_keyonly_attack.py -v
```
