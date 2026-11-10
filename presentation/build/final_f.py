"""Appendix: divider and backup slides B1-B14 (only if asked)."""
import theme as T
from final_common import C, DEMO, N, card, tag_pill
from lib import box, grid, image, tb, terminal


def build(d):
    ko, nr, op, ag = C["keyonly"], C["nonce"], C["optimisation"], C["aggregator"]
    items = ["B1  The complete Verma scheme", "B2  The complete Qiao scheme", "B3  Key-only forgery: the algebra",
             "B4  The two ablations", "B5  The 2 × 2 as tests", "B6  Nonce reuse: the algebra", "B7  The hedged nonce",
             "B8  Forward security, defined", "B9  Optimisation in detail", "B10 Finding a bad signature",
             "B11 The interim's operation counts", "B12 The P-256 timing model", "B13 Demo fallbacks", "B14 Tests and commands"]

    # ------------------------------------------------------------------ divider
    s = d.dark(bg="#34414F", notes=N("""
        BACKUP SLIDES. Only if a question calls for them; do not present them as part of the talk. Each has its own notes.
        WHICH ONE: schemes B1-B2; key-only algebra B3; ablations B4-B5; nonce algebra B6; hedged nonce B7; forward security B8; optimisation B9; fault localisation B10; interim counts B11; P-256 timing B12; demo fallbacks B13; tests and commands B14.
    """))
    tb(s, 0.8, 0.9, 9, 0.35, "BACKUP · ONLY IF ASKED", size=14, color="#B7C3D0", bold=True, spc=140, check=False)
    tb(s, 0.8, 1.35, 11, 1.0, "Appendix", size=48, color="#FFFFFF", bold=True, font=T.F_MATH)
    for i, t_ in enumerate(items):
        col, row = divmod(i, 7)
        tb(s, 0.8 + col * 6.1, 2.6 + row * 0.58, 5.8, 0.5, t_, size=19, color="#E4EAF0")

    def bk(label, eyebrow, title, tags, notes):
        return d.slide(f"Backup · {eyebrow}", f"{label} · {title}", tags=tags, appendix=label, title_size=28, notes=N(notes))

    # ------------------------------------------------------------------ B1 Verma
    s = bk("B1", "Verma et al.", "The complete Verma scheme", ["PAPER"], """
        The scheme as Qiao et al. review it in their section IV-A; our implementation follows this description (src/cbas/verma.py). We did not cross-check Verma et al.'s original paper.
        For the key-only forgery, note that R_i is part of each signature (fresh r_2i every time) and is in neither H_0 nor H_1.
    """)
    rows = [[{"text": "ALGORITHM"}, {"text": "DEFINITION"}],
            [{"text": "Setup", "bold": True}, "$s ←_{R} Z^{*}_{p}$,  $s^{k}_{TA} = s$,  $P^{k}_{TA} = sP$\n$Params = (G, p, P, H_{0}, H_{1}, P^{k}_{TA}, Δ)$"],
            [{"text": "KeyGen", "bold": True}, "$s_{i} ←_{R} Z^{*}_{p}$,  $sk_{i} = s_{i}$,  $pk_{i} = s_{i}P$"],
            [{"text": "CertGen", "bold": True}, "$r_{1i} ←_{R} Z^{*}_{p}$,  $R_{1i} = r_{1i}P$,  $c_{i} = r_{1i} + s^{k}_{TA}H_{0}(id_{i}‖pk_{i})$\n$Cert_{i} = (R_{1i}, c_{i})$,  checked by $c_{i}P = R_{1i} + H_{0}(id_{i}‖pk_{i})P^{k}_{TA}$"],
            [{"text": "Sign", "bold": True}, "$r_{2i} ←_{R} Z^{*}_{p}$,  $R_{i} = R_{1i} + r_{2i}P$,  $v_{i} = H_{1}(m_{i}‖pk_{i}‖id_{i}‖Δ)$\n$z_{i} = r_{2i} + c_{i} + sk_{i}v_{i}$,  $δ_{i} = (R_{i}, z_{i})$"],
            [{"text": "AggSign", "bold": True}, "$R = ΣR_{i}$,  $z = Σz_{i}$,  $δ = (R, z)$"],
            [{"text": "AggVerify", "bold": True}, "$h^{i}_{0} = H_{0}(id_{i}‖pk_{i})$,  $v_{i} = H_{1}(m_{i}‖pk_{i}‖id_{i}‖Δ)$\naccept iff  $zP = R + (Σh^{i}_{0})P^{k}_{TA} + Σv_{i}pk_{i}$"]]
    grid(s, 0.6, 1.6, [1.75, 10.38], [0.4, 0.85, 0.5, 0.9, 0.9, 0.5, 0.9], rows, size=16.5, hdr_size=11.5)
    tb(s, 0.6, 6.62, 12.1, 0.3, "Source: Qiao et al., §IV-A. Code: verma.py. “Very” is the paper's name for AggVerify.", size=12.5, color=T.MUTED)

    # ------------------------------------------------------------------ B2 Qiao
    s = bk("B2", "Qiao et al.", "The complete Qiao scheme", ["PAPER"], """
        The repaired scheme from the paper's section V-A; our implementation is src/cbas/scheme.py, a direct transliteration.
        Two printed typos are corrected in our code: KeyGen prints pk_i = s_i (we use s_i P); the certificate check prints R_1i (we use R_i).
        Hash instantiation (ours): SHA-512 over a length-prefixed encoding, one domain label per hash, reduced mod p.
    """)
    rows = [[{"text": "ALGORITHM"}, {"text": "DEFINITION"}],
            [{"text": "Setup", "bold": True}, "$s ←_{R} Z^{*}_{p}$,  $s^{k}_{TA} = s$,  $P^{k}_{TA} = sP$\n$Params = (G, p, P, H_{0}, H_{1}, H_{2}, P^{k}_{TA}, Δ)$"],
            [{"text": "KeyGen", "bold": True}, "$s_{i} ←_{R} Z^{*}_{p}$,  $sk_{i} = s_{i}$,  $pk_{i} = s_{i}P$"],
            [{"text": "CertGen", "bold": True}, "$r_{i} ←_{R} Z^{*}_{p}$,  $R_{i} = r_{i}P$,  $c_{i} = r_{i} + s^{k}_{TA}H_{0}(id_{i}‖pk_{i}‖R_{i})$\n$Cert_{i} = (c_{i}, R_{i})$,  $R_{i}$ public;  check $c_{i}P = R_{i} + H_{0}(id_{i}‖pk_{i}‖R_{i})P^{k}_{TA}$"],
            [{"text": "Sign", "bold": True}, "$t_{i} ←_{R} Z^{*}_{p}$,  $T_{i} = t_{i}P$,   $v_{i} = H_{1}(m_{i}‖pk_{i}‖R_{i}‖id_{i}‖[[grn|T_{i}]]‖Δ)$\n$u_{i} = H_{2}(m_{i}‖pk_{i}‖R_{i}‖id_{i}‖[[grn|T_{i}]]‖Δ)$,   $z_{i} = t_{i} + c_{i}u_{i} + sk_{i}v_{i}$,   $δ_{i} = (T_{i}, z_{i})$"],
            [{"text": "AggSign", "bold": True}, "$z = Σz_{i}$,  $δ = (T, z)$ with $T = (T_{1}, …, T_{n})$"],
            [{"text": "AggVerify", "bold": True}, "$h^{i}_{0} = H_{0}(id_{i}‖pk_{i}‖R_{i})$,  $v_{i}$, $u_{i}$ recomputed as in Sign\naccept iff  $zP = ΣT_{i} + Σu_{i}R_{i} + (Σu_{i}h^{i}_{0})P^{k}_{TA} + Σv_{i}pk_{i}$"]]
    grid(s, 0.6, 1.6, [1.75, 10.38], [0.4, 0.8, 0.48, 0.85, 0.85, 0.48, 0.85], rows, size=16, hdr_size=11.5)
    tb(s, 0.6, 6.4, 12.1, 0.55, "Printed typos corrected in our code: KeyGen prints $pk_{i} = s_{i}$ (we use $s_{i}P$); the certificate check prints $R_{1i}$ (we use $R_{i}$).",
       size=12, color=T.MUTED, lsp=0.95)

    # ------------------------------------------------------------------ B3 key-only algebra
    s = bk("B3", "Key-only forgery", "The algebra, and why the repair turns it into a search", ["OUR FINDING"], """
        Left: the forgery on Verma's scheme in full. Any z works; z = 0 is what the code uses. The forged pair satisfies the check by construction, so it verifies for any message.
        Right: the same attempt against Qiao's scheme. Fix z and T, guess R, compute the three hashes from the guess, solve for the R the equation would need, and compare. Each round gives a new candidate. A success would be a fixed point of the hash functions; finding one is exhaustive search over the group, not algebra.
        Code: src/cbas/keyonly_attack.py (forge_verma_keyonly, attempt_keyonly_forge_fixed). Tests: tests/test_keyonly_attack.py.
    """)
    tb(s, 0.6, 1.62, 6, 0.3, "VERMA: SOLVE FOR R", size=12, color=T.BAD, bold=True, spc=100, check=False)
    tb(s, 0.6, 1.95, 5.9, 3.9, [
        {"text": "check:  $zP = R + h_{0}P_{TA} + v·pk$", "after": 8},
        {"text": "$h_{0} = H_{0}(id‖pk)$,  $v = H_{1}(m‖pk‖id‖Δ)$", "after": 8},
        {"text": "choose $z$ (say 0), then", "after": 4},
        {"text": "$R := zP − h_{0}P_{TA} − v·pk$", "after": 8, "bold": True},
        {"text": "substitute: $R + h_{0}P_{TA} + v·pk = zP$  ✓", "after": 8},
        {"text": "No secret, no signature, no discrete logarithm.", "color": T.MUTED}], size=18)
    tb(s, 6.9, 1.62, 6, 0.3, "QIAO: THE SAME STEP IS CIRCULAR", size=12, color=T.GOOD, bold=True, spc=100, check=False)
    tb(s, 6.9, 1.95, 5.85, 3.9, [
        {"text": "check:  $zP = T + uR + u·h_{0}P_{TA} + v·pk$", "after": 8},
        {"text": "$h_{0}$, $u$, $v$ all hash $R$ (and $u$, $v$ hash $T$)", "after": 8},
        {"text": "guess $R_{k}$; compute $h_{0}$, $u$, $v$ from it;", "after": 4},
        {"text": "$R_{k+1} := u^{−1}(zP − T − u·h_{0}P_{TA} − v·pk)$", "after": 8, "bold": True},
        {"text": "success needs $R_{k+1} = R_{k}$: a fixed point of a hash", "after": 8},
        {"text": f"Measured: {ko['qiao_distinct_min']} distinct rounds per trial, {ko['qiao_forged']} / {ko['trials']} forgeries.", "color": T.MUTED}], size=17)

    # ------------------------------------------------------------------ B4 the two ablations
    s = bk("B4", "Ablations", "What each ablation removes, and nothing else", ["IMPLEMENTATION"], """
        Both ablations are controlled experiments, not schemes anyone should use. Each removes exactly one binding and reuses everything else from the real scheme.
        ablation.py (from the interim) drops T_i from H_1 and H_2. ablation_r.py drops R_i from H_0, H_1 and H_2 and keeps T_i. Both remain working schemes: honest signatures verify and other messages are rejected; tests check this and that only the intended input is gone.
        The R-removed variant is forged by solving for R, but in Qiao's scheme R_i is the certificate's public point, so the verifier must accept an attacker-chosen R_i: public-key replacement, F_1's power in the paper's model. Under the real R_i the forgery fails in every trial.
    """)
    rows = [[{"text": ""}, {"text": "$H_{0}$"}, {"text": "$H_{1}$, $H_{2}$"}, {"text": "FORGED BY"}],
            [{"text": "Qiao, real scheme", "bold": True}, "$id‖pk‖R$", "$m‖pk‖R‖id‖T‖Δ$", {"text": "nothing we tried", "color": T.GOOD, "bold": True}],
            [{"text": "ablation.py", "bold": True}, "$id‖pk‖R$", "$m‖pk‖R‖id‖Δ$   (no $T$)", {"text": f"solving for $T$: {ko['t_cell']} / {ko['trials']}", "color": T.BAD, "bold": True}],
            [{"text": "ablation_r.py", "bold": True}, "$id‖pk$   (no $R$)", "$m‖pk‖id‖T‖Δ$   (no $R$)", {"text": f"solving for $R$: {ko['r_cell']} / {ko['trials']}*", "color": T.BAD, "bold": True}],
            [{"text": "Verma", "bold": True}, "$id‖pk$", "$m‖pk‖id‖Δ$", {"text": f"solving for $R$: {ko['verma_forged']} / {ko['trials']}", "color": T.BAD, "bold": True}]]
    grid(s, 0.6, 1.7, [2.6, 2.4, 3.9, 3.23], [0.45, 0.6, 0.6, 0.6, 0.6], rows, size=16, hdr_size=12)
    tb(s, 0.6, 4.75, 12.1, 1.2, [
        {"text": f"* needs an attacker-chosen $R_{{i}}$ (public-key replacement): under the real certificate $R_{{i}}$ it fails {ko['r_cell_needs_replaced_R']} / {ko['trials']}.", "after": 6},
        {"text": "Both ablations stay working schemes: honest signatures verify, other messages are rejected (tested)."}],
       size=15, color=T.MUTED, bullets=True)

    # ------------------------------------------------------------------ B5 2x2 as tests
    s = bk("B5", "If asked for proof", "The 2 × 2 as tests", ["EXPERIMENT"], """
        Captured output of pytest tests/test_keyonly_attack.py -k ablation -vv, both backends. Use -vv because the project's pytest configuration adds -q.
        The first four test pairs are the four claims behind the 2 by 2; the last two check that ablation_r.py is a working scheme and changes only the R binding.
    """)
    image(s, DEMO / "final_demo1_matrix.png", 0.9, 1.7, w=11.5)

    # ------------------------------------------------------------------ B6 nonce algebra
    s = bk("B6", "Nonce reuse", "The algebra of key recovery", ["OUR FINDING"], """
        Three signatures on different messages with the same nonce t: z_j = t + c u_j + sk v_j for j = 1, 2, 3. Subtract the first from the others to remove t: two equations in c and sk. Cramer's rule solves them; then t follows from any one signature. The code checks sk P = pk and the certificate equation before returning, so it never returns a wrong answer.
        With two signatures there is one equation in c and sk. Every guess of sk fits some c; exactly one guess also satisfies sk P = pk, and finding it by checking guesses is as hard as a discrete logarithm.
        The KGC knows c (it issued the certificate), so its single equation has one unknown.
        Verma: z = r_2 + c + sk v. With the nonce repeated, z_1 - z_2 = sk (v_1 - v_2), so sk follows; r_2 + c then acts as one known value, enough to sign anything with the same R.
        Code: src/cbas/nonce_reuse.py. Tests: tests/test_nonce_reuse.py.
    """)
    tb(s, 0.6, 1.65, 6, 0.3, "OUTSIDER, THREE SIGNATURES", size=12, color=T.MUTED, bold=True, spc=100, check=False)
    tb(s, 0.6, 1.98, 6.2, 3.9, [
        {"text": "$z_{j} = t + c·u_{j} + sk·v_{j}$,   $j = 1, 2, 3$", "after": 8},
        {"text": "$d_{1} = z_{1} − z_{2} = c·a_{1} + sk·b_{1}$", "after": 2},
        {"text": "$d_{2} = z_{1} − z_{3} = c·a_{2} + sk·b_{2}$", "after": 8},
        {"text": "$c = (d_{1}b_{2} − d_{2}b_{1}) / (a_{1}b_{2} − a_{2}b_{1})$", "after": 2},
        {"text": "$sk = (a_{1}d_{2} − a_{2}d_{1}) / (a_{1}b_{2} − a_{2}b_{1})$", "after": 8},
        {"text": "with $a = u$-differences, $b = v$-differences; then $t = z_{1} − c·u_{1} − sk·v_{1}$", "size": 14.5, "color": T.MUTED}],
       size=17)
    tb(s, 7.1, 1.65, 6, 0.3, "WITH ONLY TWO", size=12, color=T.MUTED, bold=True, spc=100, check=False)
    tb(s, 7.1, 1.98, 5.6, 1.7, [
        {"text": "Outsider: $d_{1} = c·a_{1} + sk·b_{1}$, one equation, two unknowns. Picking the right $sk$ is a discrete logarithm.", "after": 8},
        {"text": "KGC: it knows $c$, so $sk = (d_{1} − c·a_{1}) / b_{1}$."}], size=15.5, lsp=0.97)
    tb(s, 7.1, 3.95, 6, 0.3, "VERMA", size=12, color=T.MUTED, bold=True, spc=100, check=False)
    tb(s, 7.1, 4.28, 5.6, 1.6, "$z_{1} − z_{2} = sk·(v_{1} − v_{2})$, so $sk$ follows from two; $r_{2} + c$ is then one known value.",
       size=15.5, lsp=0.97)

    # ------------------------------------------------------------------ B7 hedged nonce
    s = bk("B7", "The fix", "The hedged nonce, in detail", ["IMPLEMENTATION", "EXPERIMENT"], f"""
        sign_hedged in src/cbas/nonce_reuse.py. The nonce is SHA-512 over a domain-separated, length-prefixed encoding of sk, c, the message, pk, R, the identity, Delta and a fresh RNG output, reduced mod p.
        Why the secrets: without them the nonce would be computable by anyone. Why the message: so a stuck RNG still gives different nonces for different messages. Why the RNG output: hedging; a purely deterministic nonce is vulnerable to fault attacks that cause two different signatures on the same message, and mixing in randomness keeps that from being a single-point failure.
        Same message twice under a stuck RNG gives the same signature: harmless, it reveals nothing new.
        Results: distinct nonces {nr['hedged_distinct']} / {nr['trials']}, verify unchanged {nr['hedged_verify']} / {nr['trials']}, attack refused {nr['hedged_refused']} / {nr['trials']}; mixed batches of hedged and ordinary signatures aggregate and verify (test).
    """)
    tb(s, 0.6, 1.7, 12.1, 0.9, "$t_{i} = H_{nonce}(sk_{i}, c_{i}, m_{i}, pk_{i}, R_{i}, id_{i}, Δ, {{fresh rng output}})$", size=22)
    rows = [[{"text": "INPUT"}, {"text": "WHY IT IS THERE"}],
            [{"text": "$sk_{i}$, $c_{i}$", "bold": True}, "the nonce must be secret: nobody without the keys can compute it"],
            [{"text": "$m_{i}$", "bold": True}, "different messages get different nonces, even if the RNG is stuck"],
            [{"text": "$pk_{i}$, $R_{i}$, $id_{i}$, $Δ$", "bold": True}, "binds the nonce to this signer and this system"],
            [{"text": "fresh RNG output", "bold": True}, "hedging: a working RNG still adds randomness against fault attacks"]]
    grid(s, 0.6, 2.6, [3.2, 8.93], [0.42, 0.55, 0.55, 0.55, 0.55], rows, size=16, hdr_size=11.5)
    tb(s, 0.6, 5.5, 12.1, 0.6, f"Stuck RNG: distinct nonces {nr['hedged_distinct']} / {nr['trials']}; verifies with the unchanged verifier {nr['hedged_verify']} / {nr['trials']}; attack refused {nr['hedged_refused']} / {nr['trials']}.",
       size=15, color=T.MUTED)

    # ------------------------------------------------------------------ B8 forward security
    s = bk("B8", "Forward security", "What forward security means for signatures", ["PAPER"], """
        Bellare and Miner, "A Forward-Secure Digital Signature Scheme", CRYPTO 1999 (building on Anderson's 1997 remark). The public key stays fixed; the secret key evolves through periods by a one-way update, and the old key is erased. A signature names its period. Stealing the key of period j allows signing only for periods j and later.
        Qiao et al.'s scheme has none of these parts: no periods, no update algorithm, no period in the signature. The paper's own reference 24 (Li et al., Computer Journal 2015) is titled a forward-secure certificate-based signature scheme; we have not read it, so we cite only its title.
        'Perfect forward secrecy' is the key-exchange property that session keys stay safe after a long-term key leaks; it does not apply to a signature scheme.
    """)
    rows = [[{"text": "INGREDIENT"}, {"text": "FORWARD-SECURE SIGNATURE"}, {"text": "QIAO ET AL."}],
            [{"text": "Time periods", "bold": True}, "yes, named in each signature", {"text": "none", "color": T.BAD, "bold": True}],
            [{"text": "Key update", "bold": True}, "one-way, old key erased", {"text": "none: $sk_{i}$, $Cert_{i}$ fixed", "color": T.BAD, "bold": True}],
            [{"text": "Key stolen in period $j$", "bold": True}, "signs only for $j$ and later", {"text": "signs for any period", "color": T.BAD, "bold": True}]]
    grid(s, 0.6, 1.7, [3.2, 4.6, 4.33], [0.45, 0.6, 0.6, 0.6], rows, size=16.5, hdr_size=11.5)
    tb(s, 0.6, 4.3, 12.1, 1.7, [
        {"text": "Bellare and Miner, CRYPTO 1999. The paper's own ref. [24] (Li et al., Comput. J. 2015) is titled “A forward-secure certificate-based signature scheme”.", "after": 6},
        {"text": "“Perfect forward secrecy” is a key-exchange property; it does not describe a signature scheme."}],
       size=15, color=T.MUTED, bullets=True)

    # ------------------------------------------------------------------ B9 optimisation detail
    p, r = op["p256"], op["ristretto255"]
    s = bk("B9", "Optimisation", "Per-signer cost at each stage, both libraries", ["EXPERIMENT"], f"""
        Slopes of a linear fit of aggregate verification time over n = 50 to 500 (microseconds per signer), from the recorded runs bench/results/optimization_*.json ({p['timestamp'][:10]}). Over four runs on the current code: P-256 ratio 2.37 to 2.46 as specified and 2.95 to 3.07 optimised; Ristretto255 2.12 to 2.13 and 2.23 to 2.24.
        Ristretto255 via libsodium has no native multi-scalar routine, so the multi-scalar path falls back to evaluating terms one by one: no gain. An earlier version of that fallback was slower than naive; it was fixed by adding scalar-one terms directly.
        Every fast path is checked against the reference implementation on both backends, for valid and tampered inputs (tests/test_optimized.py).
    """)
    rows = [[{"text": "µs PER SIGNER"}, {"text": "AS SPECIFIED"}, {"text": "+ MSM"}, {"text": "+ ROSTER"}, {"text": "RATIO"}]]
    for lib_name, dd in (("P-256", p), ("Ristretto255", r)):
        for scheme, key in (("Qiao", "cbas"), ("Verma", "verma")):
            sl = dd["slopes"][key]
            rows.append([{"text": f"{lib_name} · {scheme}", "bold": True}, f"{sl['naive']:.1f}", f"{sl['msm']:.1f}", f"{sl['prepared']:.1f}",
                         (f"{dd['ratio_naive']:.2f} → {dd['ratio_optimised']:.2f}" if key == "cbas" else "")])
    grid(s, 0.6, 1.7, [3.0, 2.2, 2.0, 2.2, 2.73], [0.45, 0.55, 0.55, 0.55, 0.55], rows, size=16.5, hdr_size=11.5)
    tb(s, 0.6, 4.75, 12.1, 1.3, [
        {"text": f"MSM terms at $n = 500$: Qiao {p['msm_terms']['cbas']} ($3n + 1$), Verma {p['msm_terms']['verma']} ($n + 2$): ratio 2.99.", "after": 6},
        {"text": "Ristretto255 has no native multi-scalar routine, so that step gains nothing there."}],
       size=15, color=T.MUTED, bullets=True)

    # ------------------------------------------------------------------ B10 localisation
    s = bk("B10", "Aggregator", "Finding a bad signature without checking every one", ["IMPLEMENTATION", "EXPERIMENT"], f"""
        locate_faults in src/cbas/aggregator.py: verify a range as one aggregate; if it fails, split it in half and recurse into both halves. A clean range of any size costs one aggregate verification, so f faults among n cost on the order of f log n verifications, not n.
        Measured: one bad signature among {ag['n_locate']} found with {ag['locate_verifications']} verifications (a test asserts fewer than {ag['n_locate']}).
        Sub-batching, for an aggregator too weak to verify at all: split into batches of k so a fault loses only its batch. AGGREGATOR.md gives the optimum k by fault rate under a measured cost model.
    """)
    terminal(s, 0.6, 1.7, 5.95, 2.2, ["check(range):", "  if aggregate(range) verifies:", "      return            # clean",
                                      "  if len(range) == 1:", "      report bad        # found",
                                      "  check(left half); check(right half)"], size=14)
    box(s, 6.83, 1.7, 5.9, 2.2, fill=T.PANEL, line=None, radius=0.1)
    tb(s, 7.08, 1.82, 5.45, 2.0, [
        {"text": "Cost", "bold": True, "size": 17, "after": 6},
        {"text": "A clean range costs one aggregate check, whatever its size: about $f × log_{2}n$ checks for $f$ faults.", "size": 15.5, "after": 6},
        {"text": f"Measured: 1 bad in {ag['n_locate']} → {ag['locate_verifications']} checks.", "size": 15.5, "bold": True}], lsp=0.97)
    tb(s, 0.6, 4.75, 12.1, 1.2, "If the aggregator cannot verify at all, smaller sub-batches bound the loss; AGGREGATOR.md gives the best batch size per fault rate.",
       size=15, color=T.MUTED)

    # ------------------------------------------------------------------ B11 interim counts
    s = bk("B11", "From the interim", "The complete operation-count table", ["PAPER", "OUR AUDIT"], """
        Printed rows against counted rows, from the interim. Counts come from the instrumented backend and are identical on both libraries. Verma's counted rows match the printed rows except Sign, which omits one point addition (negligible).
        Qiao's AggSign is zero group operations: n - 1 scalar additions; the printed (n - 1) T_a overstates it, in the paper's favour.
        Regression-tested in tests/test_opcount.py and tests/test_verma.py.
    """)
    q = [[{"text": "QIAO ET AL."}, {"text": "PAPER"}, {"text": "COUNTED"}],
         [{"text": "Sign", "bold": True}, "$1T_{e} + 1T_{h}$", {"text": "$1T_{e} + 2T_{h}$", "color": T.BAD, "bold": True}],
         [{"text": "Verify", "bold": True}, "$3T_{e} + 2T_{a} + 2T_{h}$", {"text": "$4T_{e} + 3T_{a} + 3T_{h}$", "color": T.BAD, "bold": True}],
         [{"text": "AggSign", "bold": True}, "$(n−1)T_{a}$", {"text": "0 group ops", "color": T.GOOD, "bold": True}],
         [{"text": "AggVerify", "bold": True}, "$(n+2)T_{e} + (n+1)T_{a} + 2nT_{h}$", {"text": "$(2n+2)T_{e} + 3nT_{a} + 3nT_{h}$", "color": T.BAD, "bold": True}]]
    grid(s, 0.6, 1.7, [1.6, 4.9, 5.63], [0.4, 0.5, 0.5, 0.5, 0.5], q, size=16, hdr_size=11.5)
    v = [[{"text": "VERMA ET AL."}, {"text": "PAPER"}, {"text": "COUNTED"}],
         [{"text": "Sign", "bold": True}, "$1T_{e} + 1T_{h}$", "$1T_{e} + 1T_{a} + 1T_{h}$"],
         [{"text": "Verify, AggSign, AggVerify", "bold": True}, "as printed", {"text": "same ✓", "color": T.GOOD, "bold": True}]]
    grid(s, 0.6, 4.4, [3.6, 4.0, 4.53], [0.4, 0.5, 0.5], v, size=16, hdr_size=11.5)

    # ------------------------------------------------------------------ B12 P-256 timing model
    s = bk("B12", "Timing model", "Why P-256 timing exceeded the operation counts", ["EXPERIMENT", "OUR AUDIT"], """
        At the interim, the P-256 per-signer ratio measured about 20 percent above the ratio predicted from operation counts priced with a bare hash. Each hash call also encodes its point arguments. Qiao's verification encodes 8 points per signer (pk and R in H_0; pk, R and T in each of H_1 and H_2), Verma's 2; tests/test_opcount.py counts them. On OpenSSL an encoding costs a modular inversion; on libsodium a Ristretto255 point is stored as its encoding, so encoding is nearly free.
        bench/hashcost.py times the real hash calls and predicts 2.363 to 2.371 (three repeats) against a measured 2.366; on Ristretto255 the prediction is unchanged at 2.14. Timing values are from 10 November on the Ryzen 5 7520U; they are not asserted by the audit script because they are timings.
    """)
    rows = [[{"text": "PER-SIGNER RATIO, QIAO ÷ VERMA"}, {"text": "BARE-HASH MODEL"}, {"text": "REAL HASH CALLS"}, {"text": "MEASURED"}],
            [{"text": "P-256 · OpenSSL", "bold": True}, "1.985 – 1.986", {"text": "2.363 – 2.371", "bold": True, "color": T.GOOD}, "2.366"],
            [{"text": "Ristretto255 · libsodium", "bold": True}, "2.143", "2.139 – 2.143", "2.153"]]
    grid(s, 0.6, 1.7, [3.8, 2.7, 2.8, 2.83], [0.45, 0.55, 0.55], rows, size=16.5, hdr_size=11.5)
    tb(s, 0.6, 3.6, 12.1, 2.3, [
        {"text": "Point encodings per signer during verification: Qiao 8, Verma 2 (counted by a test).", "after": 6},
        {"text": "Encoding is a modular inversion on OpenSSL's P-256, and almost free on libsodium's Ristretto255.", "after": 6},
        {"text": "Source: bench/hashcost.py, three repeats, Ryzen 5 7520U (timings, so not asserted by the audit script)."}],
       size=15.5, bullets=True)

    # ------------------------------------------------------------------ B13 demo fallbacks
    s = bk("B13", "If the terminal fails", "Demo fallbacks: captured output", ["EXPERIMENT"], """
        The real output of make attack (Target 3) and make nonce (steps 1 to 3), captured by presentation/build/make_demo_fallback_final.py, which runs the commands and renders their stdout unedited.
        Say: 'this is the output of the same command, captured earlier.' The values T = ... differ from run to run because every run draws fresh keys; the True/False lines are what matter.
        Slides 10 and 22 already carry the same captures; this slide is only needed if the audience wants them larger.
    """)
    image(s, DEMO / "final_demo1_keyonly.png", 0.6, 1.65, w=5.6)
    image(s, DEMO / "final_demo2_attack.png", 6.45, 1.65, w=6.28)
    tb(s, 0.6, 3.55, 5.6, 0.3, "Demo 1 · make attack, Target 3", size=13, color=T.MUTED)
    tb(s, 6.45, 4.95, 6.28, 0.3, "Demo 2 · make nonce, steps 1–3 (step 4 is on slide 23)", size=13, color=T.MUTED)

    # ------------------------------------------------------------------ B14 tests and commands
    ts = C["tests"]
    s = bk("B14", "Reproducibility", "Tests and commands", ["IMPLEMENTATION"], f"""
        {ts['total']} tests: {ts['per_backend']} run once per group library ({2 * ts['per_backend']}) and {ts['independent']} need no group (fitting and aggregator-model maths). The self-test ({ts['selftest']} checks) has no dependency on pytest.
        Every number in this deck is recomputed and asserted by presentation/audit/verify_claims_final.py, which writes presentation/data/claims_final.json; the slides read that file.
    """)
    terminal(s, 0.6, 1.7, 12.13, 4.3, [
        "\\$ make selftest     # group algebra, both libraries",
        f"\\$ make test         # {ts['total']} tests: {ts['per_backend']} × 2 libraries + {ts['independent']} without a group",
        "\\$ make attack       # Demo 1: the paper's attack and the key-only forgery",
        "\\$ make nonce        # Demo 2: nonce reuse and the hedged-nonce fix",
        "\\$ make optimize     # Part III        \\$ make dos      # Part IV",
        "\\$ make hashcost     # the P-256 timing model (backup B12)",
        "\\$ .venv/bin/python presentation/audit/verify_claims_final.py",
        "                    # recomputes and asserts every number in this deck"], size=15.5)
