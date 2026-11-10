"""Part V: open analysis - nonce reuse, replay, forward security (slides 20-25)."""
import theme as T
from final_common import C, DEMO, N, card, num_badge, quote, tag_pill, verdict
from lib import box, chip, cue, grid, image, tb, takeaway, terminal


def build(d):
    nr = C["nonce"]
    t = nr["trials"]
    vc = C["vc"]

    # ------------------------------------------------------------------ 20. the question
    s = d.slide("Part V · Open analysis: nonce reuse", "What if a sensor's random-number generator repeats?",
                tags=["PAPER", "OUR FINDING"], notes=N("""
        SAY: Every signature uses a fresh random nonce t_i. The paper simply writes t_i chosen at random and says nothing about how a sensor gets randomness. Sensors are exactly where randomness fails: a generator stuck after a reboot, a firmware image cloned with its seed, too little entropy at boot.
        THE EQUATION: z_i = t_i + c_i u_i + sk_i v_i. Anyone can compute u_i and v_i, they are hashes of public data. The unknowns are t_i, the certificate secret c_i and the secret key sk_i. If t_i repeats, every signature under it is one more linear equation in the same three unknowns.
        The repeat is easy to spot: T_i = t_i P is in every signature, so a repeated nonce shows up as a repeated T_i.
        TIME: 45 seconds.
        NEXT: how many such signatures are enough.
    """))
    box(s, 0.6, 1.75, 12.13, 1.25, fill=T.WHITE, line=T.INK, lw=1.5, radius=0.1)
    tb(s, 0.85, 1.82, 5, 0.3, "QIAO'S SIGNING EQUATION", size=12, color=T.MUTED, bold=True, spc=100, check=False)
    tb(s, 0.85, 2.12, 11.7, 0.8, "$z_{i} = [[red|t_{i}]] + [[red|c_{i}]]·u_{i} + [[red|sk_{i}]]·v_{i}$      $u_{i}$, $v_{i}$: hashes of public data   ·   red: secret",
       size=22)
    card(s, 0.6, 3.25, 5.9, 2.8, "Why a nonce can repeat on a sensor",
         ["a generator stuck or re-seeded after a reboot", "a firmware or VM image cloned with its seed",
          "too little entropy at boot"], hsize=17, bsize=16, gap=6)
    card(s, 6.83, 3.25, 5.9, 2.8, "What a repeat gives an attacker",
         ["each signature under the same $t_{i}$ is one more linear equation in the same unknowns",
          "and it is visible: the same $T_{i}$ appears in each signature"], tag="OUR FINDING", hsize=17, bsize=16, gap=6)
    takeaway(s, "The paper only says “$t_{i}$ is chosen at random”. On sensors, that is the weak point.")

    # ------------------------------------------------------------------ 21. how many signatures
    s = d.slide("Part V · Nonce reuse", "How many signatures with one nonce give away the keys?",
                tags=["OUR FINDING", "EXPERIMENT"], notes=N(f"""
        SAY: Verma's scheme first: its certificate term has coefficient one, so the nonce and the certificate merge into one unknown, and two signatures give the secret key. Qiao's repair multiplies the certificate by the per-message hash u_i, so the certificate is a separate unknown: an outsider needs three signatures, and then recovers t, c and sk by solving three linear equations. With only two, every guess of sk fits some c; picking the right one is a discrete logarithm.
        THE KGC: it issued the certificate, so it already knows c. Two signatures give it sk, the very key certificate-based signatures promise it never learns.
        RESULTS: outsider with three: {nr['outsider3']} of {t} recover both secrets, the forgery verifies {nr['forge_ok']} of {t} and passes aggregate verification {nr['forge_agg_ok']} of {t}. KGC with two: {nr['kgc2']} of {t}. Verma with two: {nr['verma2']} of {t}.
        PROVENANCE: nonce reuse against Schnorr-type signatures is a standard attack. What is ours is working it out for this scheme: the three-versus-two count and the KGC case.
        TIME: 1 minute.
        NEXT: we run it.
    """))
    rows = [[{"text": "SCHEME AND ATTACKER"}, {"text": "UNKNOWNS"}, {"text": "SIGNATURES NEEDED"}, {"text": "RESULT"}],
            [{"text": "Verma, anyone", "bold": True}, "$sk_{i}$ and $r_{2i} + c_{i}$ (merged)", {"text": "2", "bold": True, "size": 20, "align": "c"},
             {"text": f"forges {nr['verma2']} / {t}", "color": T.BAD, "bold": True}],
            [{"text": "Qiao, outsider", "bold": True}, "$t_{i}$, $c_{i}$, $sk_{i}$", {"text": "3", "bold": True, "size": 20, "align": "c"},
             {"text": f"keys recovered {nr['outsider3']} / {t}", "color": T.BAD, "bold": True}],
            [{"text": "Qiao, the KGC", "bold": True}, "$t_{i}$, $sk_{i}$ (it knows $c_{i}$)", {"text": "2", "bold": True, "size": 20, "align": "c"},
             {"text": f"$sk_{{i}}$ recovered {nr['kgc2']} / {t}", "color": T.BAD, "bold": True}]]
    grid(s, 0.6, 1.75, [3.1, 3.9, 2.4, 2.73], [0.45, 0.6, 0.6, 0.6], rows, size=16.5, hdr_size=11.5)
    box(s, 0.6, 4.25, 5.9, 1.8, fill=T.PANEL, line=None, radius=0.1)
    tb(s, 0.85, 4.35, 5.45, 1.6, [
        {"text": "Why Qiao needs one more", "bold": True, "size": 16, "after": 5},
        {"text": "$c_{i}$ is multiplied by the per-message $u_{i}$, so it is a separate unknown. With two signatures, every guess of $sk_{i}$ fits some $c_{i}$.", "size": 15}],
       lsp=0.97)
    box(s, 6.83, 4.25, 5.9, 1.8, fill=T.BAD_T, line=T.BAD, lw=1.5, radius=0.1)
    tb(s, 7.08, 4.35, 5.45, 1.6, [
        {"text": "The KGC case breaks the scheme's promise", "bold": True, "size": 16, "after": 5, "color": T.BAD},
        {"text": "Certificate-based signatures exist so that the KGC never learns $sk_{i}$. Two repeated nonces hand it over.", "size": 15}],
       lsp=0.97)
    takeaway(s, "Three signatures with one nonce give an outsider every secret; the KGC needs only two.", color=T.BAD)

    # ------------------------------------------------------------------ 22. demo 2
    s = d.slide("Part V · Demo 2", "Demo 2: a stuck RNG gives away a sensor's keys", tags=["EXPERIMENT"], notes=N("""
        RUN: make nonce. About one second.
        POINT AT: Step 1: three readings, the same T in each, and every signature verifies, so nothing looks wrong. Step 2: recovered sk matches pk: True; recovered c passes the certificate check: True; the attacker's own message valve=OPEN verifies: KEYS STOLEN, and it passes aggregate verification next to an honest signature. Step 3: the KGC needs only two.
        FALLBACK: the panel on this slide is the captured output of the same command. Backup B13 has it larger.
        TIME: 1 minute 30 seconds including the demo.
        NEXT: the fix, which is step 4 of the same demo.
    """))
    terminal(s, 0.6, 1.75, 4.0, 0.75, ["\\$ make nonce"], size=22)
    tb(s, 0.6, 2.75, 4.0, 0.3, "WHAT TO POINT AT", size=12, color=T.MUTED, bold=True, spc=100, check=False)
    pts = ["Same $T$ three times; all verify", "Recovered $sk$ and $c$ check out", "`valve=OPEN` verifies: keys stolen",
           "The KGC needs only two"]
    for i, p in enumerate(pts):
        num_badge(s, 0.6, 3.15 + i * 0.66, i + 1)
        tb(s, 1.15, 3.12 + i * 0.66, 3.45, 0.5, p, size=15.5, anchor="m")
    image(s, DEMO / "final_demo2_attack.png", 4.9, 1.7, w=7.83)
    takeaway(s, "The server sees only valid signatures, yet an outsider now signs as this sensor.", color=T.BAD)

    # ------------------------------------------------------------------ 23. the fix
    s = d.slide("Part V · The fix", "The fix: derive the nonce from the keys and the message",
                tags=["IMPLEMENTATION", "EXPERIMENT"], notes=N(f"""
        SAY: The standard defence, used by EdDSA and RFC 6979: do not take the nonce straight from the generator. Hash the secret keys and the message, and mix in the generator's output: a hedged nonce. If the generator is stuck, different messages still get different nonces, because the message is an input. With a stuck generator, the same message signed twice gives the same signature, which reveals nothing new.
        NO CHANGE FOR VERIFIERS: the signing equation and the signature format are unchanged, so every existing verifier accepts hedged signatures, also mixed with ordinary ones in one aggregate.
        RESULT: with the RNG stuck, all three nonces distinct in {nr['hedged_distinct']} of {t}, signatures verify {nr['hedged_verify']} of {t}, and the attack refuses to start {nr['hedged_refused']} of {t}.
        PROVENANCE: the technique is standard; applying it to this scheme and checking it is ours. The paper specifies no nonce derivation.
        TIME: 45 seconds.
    """))
    box(s, 0.6, 1.75, 12.13, 1.0, fill=T.GOOD_T, line=T.GOOD, lw=1.5, radius=0.1)
    tb(s, 0.85, 1.8, 11.7, 0.9, "$t_{i} = H(sk_{i}, c_{i}, m_{i}, pk_{i}, R_{i}, id_{i}, Δ, {{rng output}})$      instead of      $t_{i} = {{rng output}}$",
       size=21, anchor="m")
    tb(s, 0.6, 3.0, 4.6, 2.5, [{"text": "Different messages get different nonces, even if the RNG is stuck", "after": 8},
                               {"text": "Same signature format: every verifier works unchanged", "after": 8},
                               {"text": "The standard defence (EdDSA, RFC 6979)"}], size=16.5, bullets=True)
    image(s, DEMO / "final_demo2_defence.png", 5.45, 2.95, w=7.28)
    tb(s, 5.45, 5.75, 7.28, 0.3, "Step 4 of the same demo, captured output.", size=12.5, color=T.MUTED)
    takeaway(s, "A hedged nonce closes the leak, and no verifier has to change.", color=T.GOOD)

    # ------------------------------------------------------------------ 24. replay
    s = d.slide("Part V · The paper's §V-C claims", "Claim: “resist replay attacks”", tags=["PAPER", "OUR FINDING"], notes=N("""
        SAY: The paper's argument is that signing is randomised, so signing the same message twice gives a different signature. True, and we checked it. But a replay attack does not sign anything: it re-sends an old, valid message and signature. That pair still verifies. It even verifies inside a new aggregate, and the same signature can appear twice in one batch.
        DELTA: the paper sets Delta once, in Setup, and never says it changes. If a deployment rotated Delta per epoch, old signatures would stop verifying in the next epoch, but replay inside an epoch would still work.
        WHAT IS NEEDED: freshness that the verifier checks: a sequence number or timestamp inside the message, or rejecting repeated T_i values.
        TIME: 45 seconds.
    """))
    quote(s, 0.6, 1.75, 12.13, 1.45, "The signature algorithm of our CBAS scheme is probabilistic, so the different random values will be used every time the algorithm is run, and the different signature will be obtained even the same message takes as the input.",
          "Qiao et al., §V-C, property 2, “Resist replay Attacks”")
    card(s, 0.6, 3.45, 5.9, 2.6, "What we tested", [f"An old signature verifies again ({vc['replay']} / {vc['trials']} libraries)",
                                                   f"…also twice inside one aggregate ({vc['replay_in_batch']} / {vc['trials']})",
                                                   "$Δ$ is fixed in Setup, so nothing marks a signature as old"],
         tag="EXPERIMENT", hsize=17, bsize=15.5, gap=5)
    card(s, 6.83, 3.45, 5.9, 1.75, "What replay resistance needs", ["Freshness the verifier checks: a sequence number or timestamp in the message, or rejecting a repeated $T_{i}$"],
         hsize=17, bsize=15.5, gap=5)
    verdict(s, 6.83, 5.42, 5.9, "Claim does not hold as argued")
    takeaway(s, "Randomised signing is not replay protection: an old valid signature is still valid.", color=T.BAD)

    # ------------------------------------------------------------------ 25. forward security
    s = d.slide("Part V · The paper's §V-C claims", "Claim: “perfect forward security”", tags=["PAPER", "OUR FINDING"], notes=N("""
        SAY: This is the paper's entire argument, one sentence, with no definition and no proof. For signatures, forward security has a standard meaning (Bellare and Miner, CRYPTO 1999): time is split into periods, the secret key is updated every period, and a key stolen in one period cannot sign for an earlier one. 'Perfect forward secrecy' is a key-exchange term.
        THE SCHEME: sk_i and the certificate are fixed for life, and none of the six algorithms takes a time period. So a key stolen today signs for every period. Our test: keys recovered in epoch 1, through the nonce reuse of the previous slides, sign a back-dated epoch-0 reading, and it verifies. And the premise, 'no one can obtain the random value', is exactly what nonce reuse breaks.
        THE PAPER ITSELF: cites a scheme titled 'A forward-secure certificate-based signature scheme', its reference 24 (Li et al. 2015), so the notion was available to the authors. We cite only its title; we have not read it.
        TIME: 45 seconds.
        IF ASKED 'could the claim be rescued?': only with a different, key-evolving construction like reference 24; not with a change of wording.
        NEXT: Part VI, how we know all this.
    """))
    quote(s, 0.6, 1.75, 12.13, 1.2, "In our scheme, no one can obtain the random value that used to created the signature, hence, our proposal provides perfect forward security.",
          "Qiao et al., §V-C, property 4 (the whole argument)")
    card(s, 0.6, 3.2, 3.9, 2.85, "The standard meaning", ["Keys are updated every time period; a key stolen later cannot sign for earlier periods.",
                                                         "Bellare and Miner, CRYPTO 1999"], hsize=17, bsize=15, gap=5)
    card(s, 4.72, 3.2, 3.9, 2.85, "This scheme", ["$sk_{i}$ and $Cert_{i}$ never change; no algorithm takes a time period.",
                                                 "The paper cites one by title: ref. [24], “A forward-secure certificate-based signature scheme”"], hsize=17, bsize=15, gap=5)
    card(s, 8.83, 3.2, 3.9, 2.85, "What we tested", [f"Keys stolen in epoch 1 sign a back-dated epoch-0 reading that verifies ({vc['backdated']} / {vc['trials']}).",
                                                    "And nonce reuse breaks the premise."],
         tag="EXPERIMENT", hsize=17, bsize=15, gap=5)
    takeaway(s, "No key ever changes, so nothing is forward-secure. The claim is not supported.", color=T.BAD)
