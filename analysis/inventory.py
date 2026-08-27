import os, re, collections
d = os.path.expanduser("~/manet-beacon-trust/results")
files = [f for f in os.listdir(d) if f.endswith(".csv")]
pat = collections.Counter()
for f in files:
    p = re.sub(r"seed\d+", "seedN", f)
    p = re.sub(r"run\d+", "runN", p)
    pat[p] += 1
print(f"{len(files)} csv files in results/\n")
for p, n in sorted(pat.items()):
    print(f"{n:4d}  {p}")
kinds = {"beacon_rx","behaviour","throughput","recovery","flow","pdr"}
print("\nsuffixes present:", sorted({f.rsplit("-",1)[-1][:-4] for f in files}))
