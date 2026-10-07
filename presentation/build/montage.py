"""Stack rendered slide PNGs into review sheets: montage.py first last [out]"""
import glob, sys
from PIL import Image
a, b = int(sys.argv[1]), int(sys.argv[2])
fs = sorted(glob.glob("/home/anurag/Documents/RIS/Project/presentation/render/s-*.png"))[a-1:b]
ims = [Image.open(f).convert("RGB") for f in fs]
w, h = ims[0].size
m = Image.new("RGB", (w, h * len(ims)), "white")
for i, im in enumerate(ims):
    m.paste(im, (0, i * h))
out = sys.argv[3] if len(sys.argv) > 3 else "/tmp/claude-1000/-home-anurag-Documents-RIS-Project/42d010ad-5dc4-4315-b8d2-d3da99a530b3/scratchpad/sheet.png"
m.save(out); print(out, m.size)
