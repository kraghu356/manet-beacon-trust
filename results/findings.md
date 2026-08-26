# Measured results (Aug 26)

Config: 25 nodes, 500x500m, 30dBm, rssiNoise=4dB, 10 flows @ 12pkt/s, 400s

## Coverage (5 seeds, detection of attacker)
behaviour-only: A1 0/5, A2 5/5
localization-only: A1 5/5, A2 0/5
fused: A1 5/5, A2 5/5

## Arms C/D/E on A2 (5 seeds, mean)
C no isolation:  PDR 0.696, drops 1583
D isolate-on-suspicion: PDR 0.698, drops 27
E confirm-then-isolate: PDR 0.674, drops 113

## Null results
Fusion gives no detection advantage over best single branch.
Fusion FP advantage reverses with clear_persistence (4: fused worse; 12: fused better).
Isolation has no measurable PDR effect (A1 mean -0.017, CI straddles zero).
