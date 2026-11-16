# Open analysis: nonce reuse, replay and forward security

The interim presentation listed "open analysis: nonce reuse on sensors, and the
paper's forward-security claim" as the fourth piece of work. This document
records the result. Code: [`nonce_reuse.py`](../src/cbas/nonce_reuse.py). Tests:
[`test_nonce_reuse.py`](../tests/test_nonce_reuse.py),
[`test_security_claims.py`](../tests/test_security_claims.py). Demo: `make nonce`.

Provenance tags: (A) the paper's claim, (C) our finding, (D) our implementation
choice, (E) supported by our experiments.

## 1. Key recovery from a reused nonce

The repaired scheme signs with

    z_i = t_i + c_i*u_i + sk_i*v_i,    T_i = t_i*P

where `t_i` is a fresh random nonce, `c_i` the certificate secret and `sk_i` the
user's secret key. `u_i` and `v_i` are hashes of public data, so anyone can
compute them. If a sensor's RNG repeats `t_i` (a stuck or re-seeded generator, a
cloned firmware or VM image), each signature it makes under that nonce is one
more linear equation in the same unknowns. The repeat is visible, because
`T_i` is part of every signature.

**How many signatures are needed (C, E).**

| Scheme and attacker | Unknowns | Signatures sharing a nonce |
|---|---|---|
| Verma et al., anyone | `sk`, and `r2 + c` acting as one value | 2 |
| Qiao et al., outsider | `t`, `c`, `sk` | **3** |
| Qiao et al., the KGC | `t`, `sk` (it issued `c`) | **2** |
| Qiao et al., hedged nonces | no nonce is shared | the attack does not start |

The difference between the two schemes comes from the repair itself. In
Verma's equation the certificate term `c` has coefficient 1, so it merges with
the nonce. In Qiao's, `c` is multiplied by the per-message hash `u_i`, which
makes it a separate unknown. An outsider with only two signatures is left with
one equation in two unknowns, so every guess of `sk` has a matching `c`
(`test_two_signatures_leave_an_outsider_a_discrete_log`). Exactly one guess
also satisfies `sk*P == pk`, but finding it by checking guesses is exhaustive
search: as hard as computing a discrete logarithm. In that sense two
signatures are not enough.

**What the attacker gets (E).** All of the signer's secrets. The recovered `sk`
is checked against `pk`, and the recovered `c` against the certificate equation.
The attacker can then sign any message with a fresh nonce, and that signature
passes both single and aggregate verification alongside honest ones.

**Why the KGC case matters (C).** Certificate-based signatures exist so that the
KGC never holds a user's secret key. The paper's whole adversary `F2` is a
malicious KGC that must not be able to sign. With two repeated nonces, the KGC
gets `sk` anyway.

**What is not new.** This is the standard nonce-reuse attack on Schnorr-type
signatures. The 2/3/2 count and the observation that the KGC needs one fewer
signature are our working-out for this scheme, not a new technique.

**The defence (D, E).** `sign_hedged` derives the nonce as

    t_i = H(sk_i, c_i, m_i, pk_i, R_i, id_i, D, rng output)

following the EdDSA and RFC 6979 idea, with the RNG output mixed in. Different
messages get different nonces even when the RNG is stuck. The signing equation
and signature format are unchanged, so existing verifiers accept hedged
signatures and mixed batches without modification. The paper specifies
`t_i <-R Z_p*` and says nothing about how sensors generate it.

## 2. Section V-C, property 2: "Resist replay attacks"

**The paper (A):** "The signature algorithm of our CBAS scheme is probabilistic,
so the different random values will be used every time the algorithm is run,
and the different signature will be obtained even the same message takes as
the input."

**What we found (C, E).** Signing is indeed probabilistic. It does not follow
that replay is resisted. A replay attack re-sends an old, valid
(message, signature) pair, and that pair still verifies. It also verifies
inside a new aggregate, even when the same signature appears twice in one
batch. The paper sets `Δ` once in Setup and never says it changes. If a
deployment did rotate `Δ` per epoch, old signatures would stop verifying in the
new epoch (`test_cross_epoch_signature_is_rejected`), but replay inside an epoch
would still work. Resisting replay needs freshness that the verifier checks,
such as a sequence number or timestamp inside the message, or rejecting a
repeated `T_i`. The scheme as specified provides none of these.

## 3. Section V-C, property 4: "Perfect forward security"

**The paper (A):** "In our scheme, no one can obtain the random value that used
to created the signature, hence, our proposal provides perfect forward
security." This is the whole argument. No definition or proof is given.

**What we found (C, E).**

1. *The term does not fit.* "Perfect forward secrecy" is a key-exchange
   property. For signatures, forward security (Bellare and Miner, CRYPTO 1999)
   means time is divided into periods and the secret key is updated each
   period, so a key stolen in period j cannot sign for any earlier period. The
   paper itself cites a scheme of that kind: [24], Li et al., "A forward-secure
   certificate-based signature scheme", Comput. J. 2015.
2. *Nothing in this scheme updates a key.* `sk_i` and `Cert_i` are fixed for
   life, and none of the six algorithms takes a time period. A key stolen today
   signs for every period, past and future. In the test, the keys are recovered
   while the system is in "epoch-1". The attacker then signs a back-dated
   epoch-0 reading, and it verifies and aggregates next to a genuine epoch-0
   signature (`test_a_key_stolen_later_signs_for_an_earlier_period`).
3. *The premise fails too.* "No one can obtain the random value" assumes a
   perfect RNG. With a repeated nonce, `t` is recovered exactly
   (`test_the_nonce_can_be_obtained_when_the_rng_repeats`). Nonce secrecy is
   needed for unforgeability; it does not give forward security.

**Conclusion (C).** The forward-security claim is not supported. Making it true
would need a different, key-evolving construction like [24], not a change of
wording.

## Scope

We did not audit the paper's EUF-CMA proof (Theorem 1). Nothing here breaks the
repaired scheme under its own model, which assumes honest randomness and does
not cover replay or forward security. These findings concern the model's
assumptions and the two properties claimed beyond it.
