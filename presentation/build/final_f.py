"""Appendix: divider and backup slides B1-B16 (only if asked)."""
import theme as T
from final_common import C, DEMO, N, card, tag_pill
from lib import box, grid, image, tb, terminal


def build(d):
    ko, nr, op, ag = C["keyonly"], C["nonce"], C["optimisation"], C["aggregator"]
    items = ["B1  The complete Verma scheme", "B2  The complete Qiao scheme", "B3  Key-only forgery: the algebra",
             "B4  The two ablations", "B5  The 2 × 2 as tests", "B6  Nonce reuse: the algebra", "B7  The hedged nonce",
             "B8  Forward security, defined", "B9  Optimisation in detail", "B10 Finding a bad signature",
             "B11 The interim's operation counts", "B12 The P-256 timing model", "B13 Demo fallbacks", "B14 Tests and commands",
             "B15 The paper's attack, step by step", "B16 References"]

    # ------------------------------------------------------------------ divider
    s = d.dark(bg="#34414F", notes=N("""
        BACKUP SLIDES. Only if a question calls for them; do not present them as part of the talk. Each has its own notes.
        WHICH ONE: schemes B1-B2; key-only algebra B3; ablations B4-B5; nonce algebra B6; hedged nonce B7; forward security B8; optimisation B9; the paper's attack step by step B15; references B16; fault localisation B10; interim counts B11; P-256 timing B12; demo fallbacks B13; tests and commands B14.
    """))
    tb(s, 0.8, 0.9, 9, 0.35, "BACKUP · ONLY IF ASKED", size=14, color="#B7C3D0", bold=True, spc=140, check=False)
    tb(s, 0.8, 1.35, 11, 1.0, "Appendix", size=48, color="#FFFFFF", bold=True, font=T.F_MATH)
    for i, t_ in enumerate(items):
        col, row = divmod(i, 8)
        tb(s, 0.8 + col * 6.1, 2.45 + row * 0.53, 5.8, 0.48, t_, size=18, color="#E4EAF0")

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
        Slopes of a linear fit of aggregate verification time over n = 50 to 500 (microseconds per signer), from the recorded runs bench/results/optimization_*.json ({p['timestamp'][:10]}). Over {p['runs']} runs on the best-effort verifiers (bench/results/optimization_runs.json): P-256 ratio {p['range']['ratio_naive'][0]:.2f} to {p['range']['ratio_naive'][1]:.2f} as specified and {p['range']['ratio_optimised'][0]:.2f} to {p['range']['ratio_optimised'][1]:.2f} optimised; Ristretto255 {r['range']['ratio_naive'][0]:.2f} to {r['range']['ratio_naive'][1]:.2f} and {r['range']['ratio_optimised'][0]:.2f} to {r['range']['ratio_optimised'][1]:.2f}.
        Best-effort shape: coefficient-1 sums (the T_i, Verma's aggregate R) are plain additions, and the roster caches C_i = R_i + h_0 P_TA for Qiao. An earlier verifier fed the T_i into the multi-scalar call as 3n+1 terms and reported a ratio of about 3.0; a test now pins the best-effort shape.
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
        {"text": f"MSM terms at $n = 500$: Qiao {p['msm_terms']['cbas']} ($2n$: $u_{{i}}C_{{i}}$, $v_{{i}}pk_{{i}}$), Verma {p['msm_terms']['verma']} ($n + 1$); coefficient-1 sums are plain additions.", "after": 6},
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

    # ------------------------------------------------------------------ B15 the paper's attack in full
    s = bk("B15", "The paper's attack", "The malicious-KGC forgery on Verma, step by step", ["PAPER", "REPRODUCED"], """
        Steps (a) to (d) and the check are the paper's section IV-B, which we reproduced (attack.py, forge_verma). The attacker is the paper's F_2, a malicious KGC: it issued the certificate (R_1i, c_i), and it has seen one valid signature (R_i, z_i) on m_i. It never learns sk_i or the nonce r_2i.
        The one-line form on the right, with lambda = v'/v_i, is our rewriting: once the certificate is removed, (z_i - c_i)P = (R_i - R_1i) + v_i pk_i, and multiplying both sides by lambda turns the coefficient v_i into v'.
        It works only because v_i = H_1(m_i || pk_i || id_i || Delta) does not depend on the nonce. The repair hashes T_i into v_i and u_i, so the new coefficient cannot be computed before the new commitment, which is defined in terms of it: circular.
        The function takes no secret key as an argument; a test checks its signature. Results: slide 5.
    """)
    tb(s, 0.6, 1.62, 6.9, 0.3, "STEPS (A)–(D), PAPER §IV-B", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    tb(s, 0.6, 1.95, 6.95, 4.3, [
        {"text": "(a)  $r_{2i}P = R_{i} − R_{1i}$,    $r_{2i} + sk_{i}v_{i} = z_{i} − c_{i}$", "after": 9},
        {"text": "(b)  $α = (1/v_{i})(z_{i} − c_{i}) = r_{2i}/v_{i} + sk_{i}$", "after": 2},
        {"text": "      $A = (1/v_{i})(R_{i} − R_{1i}) = (r_{2i}/v_{i})P$", "after": 9},
        {"text": "(c)  $v′ = H_{1}(m′‖pk_{i}‖id_{i}‖Δ)$", "after": 2},
        {"text": "      $R′ = R_{1i} + v′A = R_{1i} + (v′r_{2i}/v_{i})P$", "after": 2},
        {"text": "      $z′ = v′α + c_{i} = v′r_{2i}/v_{i} + c_{i} + sk_{i}v′$", "after": 9},
        {"text": "(d)  output $δ′ = (R′, z′)$"}], size=17.5)
    tb(s, 7.9, 1.62, 4.8, 0.3, "IT VERIFIES", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    tb(s, 7.9, 1.95, 4.85, 2.2, [
        {"text": "$z′P = (v′r_{2i}/v_{i})P + c_{i}P + sk_{i}v′P$", "after": 4},
        {"text": "$= (v′r_{2i}/v_{i})P + R_{1i} + H_{0}(id_{i}‖pk_{i})P_{TA} + v′pk_{i}$", "after": 4},
        {"text": "$= R′ + H_{0}(id_{i}‖pk_{i})P_{TA} + v′pk_{i}$"}], size=14.5, lsp=0.97)
    box(s, 7.9, 4.0, 4.83, 1.25, fill=T.BAD_T, line=T.BAD, lw=1.5, radius=0.08)
    tb(s, 8.05, 4.05, 4.55, 1.15, [{"text": "The same attack in one line, $λ = v′/v_{i}$  (our rewriting)", "bold": True, "size": 13, "after": 3},
                                   {"text": "$R′ = R_{1i} + λ(R_{i} − R_{1i})$", "size": 16, "after": 1},
                                   {"text": "$z′ = c_{i} + λ(z_{i} − c_{i})$", "size": 16}], lsp=0.97)
    rows = [[{"text": "PAPER STEP"}, {"text": "attack.py · forge_verma"}],
            ["(a) $v_{i}$ and $1/v_{i}$", "lines 73–74"], ["(b) $α$, $A$", "lines 77–78"], ["(c) $v′$, $R′$, $z′$", "lines 81–83"]]
    grid(s, 0.6, 5.0, [2.7, 2.6], [0.35, 0.36, 0.36, 0.36], rows, size=13.5, hdr_size=11)
    tb(s, 7.9, 5.4, 4.8, 0.6, "It needs only that $v_{i}$ ignores the nonce. The function takes no secret key; a test checks that.",
       size=13, color=T.MUTED, lsp=0.95)

    # ------------------------------------------------------------------ B16 references
    s = bk("B16", "References", "References", [], """
        Every source cited on the slides. [1] is the paper under study; [2] is the scheme it breaks and repairs. [3] gives the attack and forgery vocabulary used in Part II (key-only, universal). [4] is the Schnorr signature, whose commitment-in-the-hash rule explains the key-only forgery. [5] defines forward security for signatures (Part V). [6] and [7] are the deterministic and hedged nonce derivations behind our fix. Reference [8] is cited by its title only (it is the paper's own reference 24); we have not read it. Software versions are in the repository README.
    """)
    refs = [
        "[1]  Z. Qiao, Q. Yang, Y. Zhou, B. Yang, Z. Xia, M. Zhang, T. Wang. An Efficient Certificate-Based Aggregate Signature Scheme With Provable Security for Industrial Internet of Things. IEEE Systems Journal 17(1):72–82, 2023. doi:10.1109/JSYST.2022.3188012",
        "[2]  G. K. Verma, B. B. Singh, N. Kumar, V. Chamola. CB-CAS: Certificate-Based Efficient Signature Scheme With Compact Aggregation for Industrial Internet of Things Environment. IEEE Internet of Things Journal 7(4):2563–2572, 2020",
        "[3]  S. Goldwasser, S. Micali, R. L. Rivest. A Digital Signature Scheme Secure Against Adaptive Chosen-Message Attacks. SIAM J. Computing 17(2):281–308, 1988",
        "[4]  C. P. Schnorr. Efficient Signature Generation by Smart Cards. J. Cryptology 4(3):161–174, 1991",
        "[5]  M. Bellare, S. K. Miner. A Forward-Secure Digital Signature Scheme. CRYPTO 1999, LNCS 1666, 431–448",
        "[6]  T. Pornin. Deterministic Usage of the DSA and ECDSA. RFC 6979, 2013",
        "[7]  S. Josefsson, I. Liusvaara. Edwards-Curve Digital Signature Algorithm (EdDSA). RFC 8032, 2017",
        "[8]  J. Li, H. Teng, X. Huang, Y. Zhang, J. Zhou. A Forward-Secure Certificate-Based Signature Scheme. The Computer Journal 58(4):853–866, 2015 (cited by title)",
    ]
    tb(s, 0.6, 1.6, 12.1, 4.9, [{"text": r_, "after": 7} for r_ in refs], size=13.5, lsp=0.95)
    tb(s, 0.6, 6.55, 12.1, 0.3, "Implementation: Ristretto255 via libsodium, NIST P-256 via OpenSSL; code, tests and recorded results in the project repository.",
       size=12, color=T.MUTED)

