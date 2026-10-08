"""Reusable diagrams: the swimlane protocol (generic and concrete), the attack event diagram, the step rail."""
import theme as T
from lib import arrow, box, chip, line, lock, party, pill, tb, text_width

LANES = [  # key, label, sub, y0, height
    ("kgc", "KGC", "trusted authority", 2.42, 1.3),
    ("sen", "Sensor $i$", "× n devices", 3.72, 1.3),
    ("agg", "Aggregator", "holds no secret", 5.02, 0.85),
    ("ver", "Cloud / Verifier", "checks the aggregate", 5.87, 0.95),
]
X0, CW = 2.0, (12.73 - 2.0) / 6


def cx(k):
    return X0 + k * CW


def secret_chip(s, x, y, w, text, kind, size=12.5):
    from lib import PARTY
    chip(s, x, y, w, 0.27, text, kind, size=size, dash=True, align="l", pad=0.3)
    lock(s, x + 0.06, y + 0.015, 0.23, PARTY[kind][0])


def protocol(s, concrete):
    """Swimlane protocol diagram. concrete=False: object names only; concrete=True: Qiao et al.'s objects."""
    # phase header
    groups = [(0, 1, "configuration"), (1, 3, "per sensor, once: keys and certificate"),
              (3, 4, "signing, per reading"), (4, 5, "aggregation"), (5, 6, "verification")]
    for a, b, t in groups:
        box(s, cx(a) + 0.02, 1.62, (b - a) * CW - 0.04, 0.33, fill=T.PANEL, line=None, radius=0.04, text=t, size=12.5,
            color=T.MUTED, check=False)
    for k, name in enumerate(["① Setup", "② KeyGen", "③ CertGen", "④ Sign", "⑤ AggSign", "⑥ AggVerify"]):
        tb(s, cx(k), 1.98, CW, 0.4, name, size=15, bold=True, align="c", anchor="m", check=False)
    # lanes
    from lib import PARTY
    for key, label, sub, y0, h in LANES:
        box(s, 0.6, y0 + 0.02, 12.13, h - 0.04, fill=PARTY[key][1], line=None, radius=0.06)
        tb(s, 0.72, y0 + 0.1, 1.3, 0.55, [{"text": label, "bold": True, "size": 14.5, "color": PARTY[key][0]},
                                           {"text": sub, "size": 11.5, "color": T.MUTED}], check=False)

    def alg(k, lane_y, name, kind, h=0.46):
        party(s, kind, cx(k) + 0.14, lane_y + 0.1, 1.5, h, text=name, size=16, bold=True, lw=1.75)

    alg(0, 2.42, "Setup", "kgc")
    alg(1, 3.72, "KeyGen", "sen")
    alg(2, 2.42, "CertGen", "kgc")
    alg(3, 3.72, "Sign", "sen")
    alg(4, 5.02, "AggSign", "agg", h=0.4)
    alg(5, 5.87, "AggVerify", "ver", h=0.46)

    def c2(k, lane_y, row, text, kind, secret=False):
        y = lane_y + 0.64 + row * 0.3
        if secret:
            secret_chip(s, cx(k) + 0.14, y, 1.5, text, kind)
        else:
            chip(s, cx(k) + 0.14, y, 1.5, 0.27, text, kind, size=12.5)

    if concrete:
        c2(0, 2.42, 0, "$s^{k}_{TA}$  secret", "kgc", True)
        c2(0, 2.42, 1, "Params  public", "kgc")
        c2(1, 3.72, 0, "$sk_{i}$  secret", "sen", True)
        c2(1, 3.72, 1, "$pk_{i}$  public", "sen")
        c2(2, 2.42, 0, "$c_{i}$  secret", "kgc", True)
        c2(2, 2.42, 1, "$R_{i}$  public", "kgc")
        c2(3, 3.72, 0, "$t_{i}$  secret", "sen", True)
        chip(s, cx(3) + 0.14, 3.72 + 0.94, 1.5, 0.27, "$δ_{i} = ([[grn|T_{i}]], z_{i})$", "sen", size=12.5)
        chip(s, cx(4) + 0.14, 5.02 + 0.54, 1.5, 0.27, "$δ = (T, z)$", "agg", size=12.5)
        chip(s, cx(5) + 0.14, 5.87 + 0.6, 0.72, 0.27, "1 valid", "good", size=12, bold=True, pad=0.02)
        chip(s, cx(5) + 0.92, 5.87 + 0.6, 0.72, 0.27, "0 reject", "bad", size=12, bold=True, pad=0.02)
    else:
        c2(0, 2.42, 0, "msk  secret", "kgc", True)
        c2(0, 2.42, 1, "Params  public", "kgc")
        c2(1, 3.72, 0, "$sk_{i}$  secret", "sen", True)
        c2(1, 3.72, 1, "$pk_{i}$  public", "sen")
        c2(2, 2.42, 0, "$Cert_{i}$", "kgc", True)
        chip(s, cx(3) + 0.14, 3.72 + 0.64, 1.5, 0.27, "$δ_{i}$", "sen", size=13)
        chip(s, cx(4) + 0.14, 5.02 + 0.54, 1.5, 0.27, "$δ$", "agg", size=13)
        chip(s, cx(5) + 0.14, 5.87 + 0.6, 0.72, 0.27, "1 valid", "good", size=12, bold=True, pad=0.02)
        chip(s, cx(5) + 0.92, 5.87 + 0.6, 0.72, 0.27, "0 reject", "bad", size=12, bold=True, pad=0.02)

    # Params published through the cloud
    arrow(s, [(cx(0) + 0.89, 3.6), (cx(0) + 0.89, 5.97)], T.KGC)
    tb(s, cx(0) + 1.0, 5.08, 1.6, 0.7, "Params published via the cloud server", size=12.5, color=T.MUTED, lsp=0.95)
    box(s, cx(0) + 0.14, 5.97, 1.5, 0.42, fill=T.WHITE, line=T.VER, lw=1.25, radius=0.06, text="stores Params", size=13)
    # pk_i to the KGC
    arrow(s, [(cx(1) + 0.89, 3.82), (cx(1) + 0.89, 2.75), (cx(2) + 0.14, 2.75)], T.SEN)
    tb(s, cx(1) - 0.05, 3.1, 0.9, 0.28, "$id_{i}, pk_{i}$", size=12.5, color=T.SEN, align="r", check=False)
    # certificate to the sensor (channel not specified)
    arrow(s, [(cx(2) + 1.64, 2.75), (cx(3) + 0.9, 2.75), (cx(3) + 0.9, 3.82)], T.KGC, dash=True)
    tb(s, cx(2) + 1.7, 2.45, 1.0, 0.27, "$Cert_{i}$", size=13, color=T.KGC, bold=True, check=False)
    tb(s, cx(3) + 1.0, 2.98, 1.6, 0.7, "delivery channel not specified", size=12.5, color=T.MUTED, lsp=0.95)
    # signatures to the aggregator
    arrow(s, [(cx(3) + 1.64, 4.05), (cx(4) + 0.89, 4.05), (cx(4) + 0.89, 5.12)], T.SEN)
    tb(s, cx(3) + 1.7, 3.76, 2.2, 0.27, "$m_{i}, δ_{i}$ from each sensor", size=12.5, color=T.SEN, check=False)
    # aggregate to the verifier
    arrow(s, [(cx(4) + 1.64, 5.3), (cx(5) + 0.89, 5.3), (cx(5) + 0.89, 5.97)], T.AGG)
    tb(s, cx(4) + 1.7, 5.03, 1.9, 0.27, "$δ, m_{1}, …, m_{n}$", size=12.5, color=T.AGG, check=False)
    # verifier needs public key material (acquisition not specified)
    pk_text = ("$id_{i}, pk_{i}, R_{i}$ of every signer" if concrete else "$pk_{i}$ of every signer")
    box(s, cx(1) + 0.14, 5.97, 4.7, 0.78, fill=T.WHITE, line=T.MUTED, lw=1.25, dash=True, radius=0.06,
        text=[{"text": pk_text, "size": 13.5}, {"text": "how the verifier obtains them is not specified", "size": 12.5, "color": T.MUTED}],
        align="l", pad=0.14)
    arrow(s, [(cx(1) + 4.84, 6.2), (cx(5) + 0.14, 6.2)], T.MUTED, dash=True)
    tb(s, cx(1) + 4.95, 5.92, 1.8, 0.26, "input to AggVerify", size=12.5, color=T.MUTED, check=False)


# --------------------------------------------------------------------------- attack event diagram
def _mix(s, x, y, w, left, sealed, right, size, lock_c=T.BAD):
    """left text + sealed chip + right text on one line; returns nothing."""
    f = 1.045
    wl = text_width(left, size) * f if left else 0.0
    ws = text_width(sealed, size) * f
    cx_ = x + wl
    chip(s, cx_, y, ws + 0.68, 0.3, sealed, "bad", size=size, dash=True, align="l", pad=0.32)
    lock(s, cx_ + 0.05, y + 0.04, 0.22, lock_c)
    if left:
        tb(s, x, y, wl + 0.05, 0.3, left, size=size, anchor="m", check=False)
    if right:
        tb(s, cx_ + ws + 0.74, y, 1.6, 0.3, right, size=size, anchor="m", check=False)


def attack_diagram(s):
    # legitimate sensor
    party(s, "sen", 0.6, 1.7, 2.2, 3.4, text=None, lw=1.5)
    tb(s, 0.72, 1.78, 2.0, 0.55, [{"text": "Legitimate sensor", "bold": True, "size": 14.5, "color": T.SEN},
                                   {"text": "$id_{i}$", "size": 13.5, "color": T.MUTED}], check=False)
    tb(s, 0.72, 2.5, 2.0, 0.3, "holds, never shares:", size=12.5, color=T.MUTED, check=False)
    chip(s, 0.72, 2.82, 1.96, 0.4, "$sk_{i}$", "sen", size=14, dash=True, align="l", pad=0.38)
    lock(s, 0.79, 2.88, 0.27, T.SEN)
    chip(s, 0.72, 3.3, 1.96, 0.4, "$r_{2i}$ fresh nonce", "sen", size=13, dash=True, align="l", pad=0.38)
    lock(s, 0.79, 3.36, 0.27, T.SEN)
    tb(s, 0.72, 3.88, 2.0, 0.3, "signs a reading $m_{i}$:", size=12.5, color=T.MUTED, check=False)
    chip(s, 0.72, 4.2, 1.96, 0.58, [{"text": "valid signature", "size": 12.5},
                                     {"text": "$δ_{i} = (R_{i}, z_{i})$", "size": 14}], "sen")
    tb(s, 0.72, 4.82, 2.0, 0.26, "captured by the KGC", size=11.5, color=T.MUTED, check=False)
    arrow(s, [(2.8, 4.49), (3.05, 4.49)], T.INK, lw=2.0)

    # malicious KGC
    box(s, 3.05, 1.7, 2.7, 4.5, fill=T.BAD_T, line=T.BAD, lw=1.75, radius=0.1)
    tb(s, 3.18, 1.76, 2.5, 0.55, [{"text": "Malicious KGC", "bold": True, "size": 15.5, "color": T.BAD},
                                   {"text": "the paper's attacker $F_{2}$", "size": 12, "color": T.MUTED}], check=False)
    box(s, 3.15, 2.4, 2.5, 1.8, fill=T.WHITE, line=T.RULE, radius=0.06)
    tb(s, 3.27, 2.45, 2.3, 0.25, "KNOWS", size=11.5, color=T.KGC, bold=True, spc=100, check=False)
    tb(s, 3.27, 2.7, 2.35, 1.45, [
        {"text": "✓  master secret $s$", "after": 3},
        {"text": "✓  $Cert_{i} = (R_{1i}, c_{i})$", "after": 3},
        {"text": "✓  public $id_{i}, pk_{i}, Δ$, $P^{k}_{TA}$", "after": 3},
        {"text": "✓  $m_{i}$ and $(R_{i}, z_{i})$"}], size=12.5)
    box(s, 3.15, 4.3, 2.5, 1.8, fill=T.BAD_T, line=T.BAD, lw=1.25, radius=0.06)
    tb(s, 3.27, 4.35, 2.3, 0.25, "DOES NOT KNOW", size=11.5, color=T.BAD, bold=True, spc=100, check=False)
    chip(s, 3.27, 4.66, 2.26, 0.4, "$sk_{i}$", "bad", size=14, dash=True, align="l", pad=0.38)
    lock(s, 3.34, 4.72, 0.27, T.BAD)
    chip(s, 3.27, 5.12, 2.26, 0.4, "$r_{2i}$", "bad", size=14, dash=True, align="l", pad=0.38)
    lock(s, 3.34, 5.18, 0.27, T.BAD)
    tb(s, 3.27, 5.62, 2.3, 0.42, "never learned, at any step", size=12.5, color=T.BAD, bold=True, check=False)
    arrow(s, [(5.75, 2.2), (5.97, 2.2)], T.BAD, lw=2.25)

    # five steps
    X, W = 5.97, 4.3
    sz = 13.5
    steps = [
        (1.7, 0.98, "① strip the certificate", [("p", "$r_{2i}P = R_{i} − R_{1i}$"), ("m", "", "$r_{2i} + sk_{i}v_{i}$", "$= z_{i} − c_{i}$")]),
        (2.74, 0.98, "② normalise by $v_{i}$", [("m", "$α = (z_{i} − c_{i})/v_{i} = $", "$r_{2i}/v_{i} + sk_{i}$", ""), ("p", "$A = (R_{i} − R_{1i})/v_{i}$")]),
        (3.78, 0.62, "③ new message $m′_{i}$", [("p", "$v′_{i} = H_{1}(m′_{i}, …)$   no $R′_{i}$ needed")]),
        (4.44, 0.62, "④ build the commitment", [("p", "$R′_{i} = R_{1i} + v′_{i}·A$")]),
        (5.1, 0.62, "⑤ build the response", [("p", "$z′_{i} = v′_{i}·α + c_{i}$")]),
    ]
    for y, h, title, rows in steps:
        box(s, X, y, W, h, fill=T.WHITE, line=T.INK, lw=1.25, radius=0.06)
        tb(s, X + 0.12, y + 0.04, W - 0.2, 0.26, title, size=13, bold=True, check=False)
        yy = y + 0.33
        for r in rows:
            if r[0] == "p":
                tb(s, X + 0.14, yy, W - 0.26, 0.3, r[1], size=sz, color=T.MUTED, check=False)
            else:
                _mix(s, X + 0.14, yy, W - 0.26, r[1], r[2], r[3], sz)
            yy += 0.31
    box(s, X, 5.78, W, 0.42, fill=T.BAD_T, line=T.BAD, lw=1.75, radius=0.08, text="forged $δ′_{i} = (R′_{i}, z′_{i})$ on $m′_{i}$",
        size=14.5, bold=True, color=T.BAD)
    arrow(s, [(X + W, 5.99), (10.6 + 1.06, 5.99), (10.6 + 1.06, 4.75)], T.BAD, lw=2.25)

    # verifier
    party(s, "ver", 10.6, 2.2, 2.13, 2.55, lw=1.5)
    tb(s, 10.72, 2.26, 1.9, 0.3, "Verifier", size=15, bold=True, color=T.VER, check=False)
    tb(s, 10.72, 2.62, 1.95, 1.4, [{"text": "checks", "color": T.MUTED, "size": 12}, {"text": "$z′_{i}P = R′_{i}$"},
                                    {"text": "$+ H_{0}(id_{i}‖pk_{i})P^{k}_{TA}$"}, {"text": "$+ v′_{i}pk_{i}$"}], size=12.5, check=False)
    tb(s, 10.72, 3.85, 1.95, 0.4, "ACCEPTED", size=21, bold=True, color=T.BAD, check=False)
    tb(s, 10.72, 4.22, 1.95, 0.5, "also inside an aggregate", size=11.5, color=T.BAD, check=False)
    # banner
    box(s, 0.6, 6.3, 12.13, 0.62, fill=T.BAD_T, line=T.BAD, lw=1.75, radius=0.08)
    tb(s, 0.8, 6.3, 11.8, 0.62, [{"text": "The attacker never learns $r_{2i}$ or $sk_{i}$: it rescales the sealed combination.",
                                   "bold": True, "size": 19, "color": T.BAD}], anchor="m", check=False)


# --------------------------------------------------------------------------- step rail
RAIL = ["① strip the certificate", "② normalise by $v_{i}$", "③ choose $m′_{i}$, get $v′_{i}$", "④ build $R′_{i}$",
        "⑤ build $z′_{i}$"]


def rail(s, active):
    tb(s, 0.6, 1.72, 3.2, 0.3, "THE ATTACK, IN FIVE STEPS", size=11.5, color=T.MUTED, bold=True, spc=100, check=False)
    for i, t in enumerate(RAIL):
        y = 2.1 + i * 0.78
        on = i in active
        box(s, 0.6, y, 3.2, 0.62, fill=(T.BAD_T if on else T.PANEL), line=(T.BAD if on else None), lw=2.0, radius=0.08,
            text=t, size=15.5, bold=on, color=(T.BAD if on else T.MUTED), align="l", pad=0.18)
        if i < 4:
            arrow(s, [(2.2, y + 0.62), (2.2, y + 0.78)], T.RULE, lw=1.5)
