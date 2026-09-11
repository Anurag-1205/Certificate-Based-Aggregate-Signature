# Verification of the cost-table discrepancy

This note backs the claim made in [README.md](README.md) that the computation-cost
rows Qiao et al. give for **their own** scheme in Tables II and III are too low.
Since that is a claim against a peer-reviewed IEEE paper, the evidence is set out
here in full, together with the objections considered and rejected.

## What is and is not being claimed

**Not claimed:** that the scheme is insecure, that the security proof is wrong, or
that the paper's central contribution fails. The paper's cryptanalysis of Verma et
al.'s CB-CAS is *independently corroborated* by Xiong et al., who reach the same
conclusion by a different route (see [Sources](#sources)). The construction and the
two-sided reduction are not at issue here.

**Claimed, narrowly:** the cost expressions attributed to the new scheme in Table II
and Table III are arithmetically inconsistent with the scheme's own algorithm
definitions, given in the same paper. The rows are byte-identical to the rows given
for Verma et al.'s scheme, and are correct for *Verma's* equations but not for these.

This is an arithmetic claim about the paper's own equations under the paper's own
stated definitions, so it is checkable without appeal to convention.

## 1. Primary evidence: the paper's own text

Section V-A, verbatim.

**Sign, step (b):**

> Compute `v_i = H1(m_i||pk_i||R_i||id_i||T_i||D)` **and** `u_i = H2(m_i||pk_i||R_i||id_i||T_i||D)`

Two hash invocations, written explicitly. Table II charges `Sign` **one** `Th`.

**Verify, step (a):**

> For i, from 1 to n, compute `h_i0 = H0(id_i||pk_i||R_i)`, `v_i = H1(...)` **and** `u_i = H2(...)`

Three hash invocations per signer, inside an explicit loop over `n`. Table III
charges `2nTh`.

**Verify, step (b):**

> `zP = sum(T_i) + sum(u_i R_i) + (sum u_i h_i0) P_TA + sum(v_i pk_i)`

**AggSign:**

> a) Compute `z = sum z_i`.  b) Output `delta = (T, z)` where `T = (T_1, ..., T_n)`.

No group operation appears. Table III charges `(n-1)Ta`.

## 2. The arithmetic

Table II defines the symbols: *"let `Ta` be the addition over group, `Te` the
multiplication over group, `Tb` the pairing operation and `Th` the hash computation."*

Counting the verification equation under those definitions:

| Term | `Te` | `Ta` |
|---|---|---|
| `zP` | 1 | — |
| `sum(T_i)` | 0 | `n-1` |
| `sum(u_i R_i)` | `n` | `n-1` |
| `(sum u_i h_i0) P_TA` | 1 | — |
| `sum(v_i pk_i)` | `n` | `n-1` |
| combining the four top-level terms | — | 3 |
| **total** | **`2n+2`** | **`3n`** |

Hashes: `h_i0`, `v_i`, `u_i` per signer = **`3n`**.

The same count applied to **Verma et al.'s** equation, `zP = R + (sum h_i0) P_TA +
sum(v_i pk_i)`, gives `(n+2)Te + (n+1)Ta + 2nTh` -- **exactly the published row**.
Verma's `AggSign` likewise measures exactly `(n-1)Ta`, as published, since that
scheme genuinely sums `R_i` in the group. The method reproduces Verma's rows and
fails to reproduce this scheme's, which locates the error in the row rather than
in the method. This is asserted by
`tests/test_verma.py::test_verma_aggverify_cost_matches_its_published_row`.

For completeness, one Verma row in **Table II** is also slightly loose: `Sign`
computes `R_i = R1_i + r2_i*P`, which is `1Te + 1Ta + 1Th`, while the table gives
`1Te + 1Th`. The omitted operation is a single point addition, and it does not
affect the argument here -- the Table III rows that carry the analysis are exact.

## 3. Internal corroboration within the same paper

The paper's treatment of **Scheme [6]** (Verma et al.'s PFCBAS) uses the counting
method above, and contradicts its own rows for the new scheme:

| | Scheme [6] as published | New scheme as published | New scheme, counted |
|---|---|---|---|
| `Sign` (two hashes) | `1Te + 2Th` | `1Te + 1Th` | `1Te + 2Th` |
| `Verify` (single) | `4Te + 3Th` | `3Te + 2Ta + 2Th` | `4Te + 3Ta + 3Th` |
| `AggVerify` | `(2n+2)Te + (3n-1)Ta + 3nTh` | `(n+2)Te + (n+1)Ta + 2nTh` | `(2n+2)Te + 3nTa + 3nTh` |

Scheme [6] is charged `2Th` for a `Sign` with two hashes; the authors' own `Sign`,
which also has two hashes, is charged `1Th`. Scheme [6]'s aggregate row has the
same shape (`(2n+2)Te`, `3nTh`) that counting produces for the new scheme. The
paper therefore applies one method to a competitor and a different one to itself.

## 4. Objections considered

**(a) `h_i0` is message-independent and could be cached.** True -- it depends only on
`(id_i, pk_i, R_i)`, all static -- so a verifier serving a fixed fleet could drop to
`2nTh`, matching the published row. But Verma's `h_i0 = H0(id_i||pk_i)` is equally
static, so the same optimisation takes Verma to `nTh`. Under *no* caching the two
schemes are `3n` and `2n`; under caching they are `2n` and `n`. They differ by
exactly `n` either way. Since the paper assigns Verma `2nTh`, it is using the
no-caching model -- under which this scheme costs `3nTh`.
Test: `test_hash_claim_survives_the_caching_objection`.

**(b) `sum(u_i R_i)` could be folded away algebraically.** Since `c_i P = R_i +
h_i0 P_TA`, we have `sum(u_i R_i) + (sum u_i h_i0) P_TA == (sum u_i c_i) P`, a single
scalar multiplication. The identity is real and the test confirms it holds -- but
`c_i` is the signer's *secret* certificate, so a verifier cannot use it. The `n`
scalar multiplications stand. Test: `test_te_claim_cannot_be_rescued_by_algebraic_rewriting`.

**(c) Multi-scalar multiplication could reduce the count.** Straus-Shamir or
Pippenger genuinely compute `sum(s_i P_i)` for less than `n` independent scalar
multiplications. But those are *optimisations*, and would not yield `(n+2)Te`
either -- the resulting expression is not linear in `n` in that way. Table III is
plainly a naive operation count, since it also reports `Ta` growing linearly.

**(d) Miscounting on our side.** The counts are produced by instrumenting every
group operation and hash at a single chokepoint
([counter.py](src/cbas/backend/counter.py)) rather than by hand, and the same
instrument reproduces Verma's published row exactly.

## 5. The numerical consequence

Evaluated with the paper's own Table IV costs (`Te = 0.112`, `Ta = 0.005`,
`Th = 0.004` ms) at `n = 100`:

- claimed formula: **12.729 ms** -- exactly the bar published in Fig. 4, confirming
  that figure was generated from Table III and inherits the same error
- actual count: **25.324 ms**, a factor of **1.99**

Locked in by `test_n100_matches_the_published_figure4_bar`.

## 6. A correction in the paper's favour

`AggSign` performs `n-1` *scalar* additions in `Z_p` and **zero** group operations;
Table III charges it `(n-1)Ta`, i.e. group additions. That row **overstates** this
scheme's cost. Verma et al. genuinely compute `R = sum R_i` in the group, which is
again where the row appears to have come from.

Reporting this alongside the understatements is what makes the result a correction
rather than an attack.

## Reproducing

```bash
make selftest                      # group backend algebra, 31 checks
.venv/bin/python -m pytest tests/test_opcount.py -v
.venv/bin/python -m cbas.demo      # measured vs. claimed, side by side
```

## Sources

- Z. Qiao et al., "An Efficient Certificate-Based Aggregate Signature Scheme With
  Provable Security for Industrial Internet of Things," *IEEE Systems Journal*,
  17(1):72-82, 2023. doi:10.1109/JSYST.2022.3188012 -- the paper under analysis.
- G. K. Verma, B. B. Singh, N. Kumar, V. Chamola, "CB-CAS: Certificate-Based
  Efficient Signature Scheme With Compact Aggregation for IIoT Environment,"
  *IEEE Internet of Things Journal*, 7(4):2563-2572, 2020 -- scheme [11], whose
  rows match the counting method.
- G. K. Verma et al., "PFCBAS: Pairing Free and Provable Certificate-Based Aggregate
  Signature Scheme for the e-Healthcare Monitoring System," *IEEE Systems Journal*,
  14(2):1704-1715, 2020 -- scheme [6], counted by the paper in a way that
  contradicts its own rows. <https://ieeexplore.ieee.org/document/8788464/>
- H. Xiong, Y. Hou, X. Huang, S. Kumari, "Certificate-Based Parallel Key-Insulated
  Aggregate Signature Against Fully Chosen-Key Attacks for IIoT," IACR ePrint
  2020/1027 -- independently concludes Verma et al.'s CB-CAS is forgeable by a
  malicious KGC, corroborating this paper's security contribution.
  <https://eprint.iacr.org/2020/1027.pdf>
- "A Lightweight Certificate-Based Aggregate Signature Scheme Providing Key
  Insulation," *CMC*, 69(2) -- same sub-literature, same symbol convention
  (`Tsm` scalar multiplication, `Tsa` point addition, `H` hash).
  <https://www.techscience.com/cmc/v69n2/43896/html>
- D. Hankerson, A. Menezes, S. Vanstone, *Guide to Elliptic Curve Cryptography*,
  Springer, 2004 -- standard reference for scalar multiplication and multi-scalar
  multiplication cost.
