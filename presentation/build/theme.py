"""Design tokens shared by the figure generator and the deck builder.

One identity per party, everywhere:
    KGC          violet      Sensor      blue       Aggregator  amber
    Verifier     slate       Attack      red        Repair / T_i binding   green
"""

W_IN, H_IN = 13.333, 7.5

INK = "#14202E"
MUTED = "#5B6675"
RULE = "#D3D9E1"
PANEL = "#F2F5F8"
WHITE = "#FFFFFF"

KGC, KGC_T = "#6B3FA0", "#EFE8F8"
SEN, SEN_T = "#1D5EA8", "#E4EEF9"
AGG, AGG_T = "#B26A00", "#FBF0DC"
VER, VER_T = "#455A6E", "#E6EBF0"
BAD, BAD_T = "#B3261E", "#FCE9E7"
GOOD, GOOD_T = "#1E7B4F", "#E2F3EA"

TERM_BG = "#101923"       # terminal panels
TERM_FG = "#DDE5EE"

# provenance tags: (label, colour)
TAGS = {
    "PAPER": "#52606F",
    "REPRODUCED": "#0E7C86",
    "IMPLEMENTATION": "#7A6F63",
    "EXPERIMENT": "#4B4BB8",
    "OUR AUDIT": "#A21F6B",
}

F_BODY = "Calibri"
F_MATH = "Cambria"
F_MONO = "Courier New"

# type scale (pt)
T_TITLE = 30
T_BODY = 20
T_SMALL = 16
T_CAP = 13
T_EQ = 28
