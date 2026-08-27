# Measured results (Aug 26)

Config: 25 nodes, 500x500m, 30dBm, rssiNoise=4dB, 10 flows @ 12pkt/s, 400s

## Coverage (5 seeds)
behaviour-only: A1 0/5, A2 5/5
localization-only: A1 5/5, A2 0/5
fused: A1 5/5, A2 5/5

## Arms on A2 (5 seeds, mean)
C none: PDR 0.696 drops 1583
D suspicion: PDR 0.698 drops 27
E confirm: PDR 0.674 drops 113

## Nulls
No fusion detection advantage.
Fusion FP advantage reverses with clear_persistence.
Isolation: no measurable PDR effect.
Arm D matches or beats arm E everywhere tested.

## Clean-network false isolation (5 seeds, no attacker, 400s)
D isolates 3/3 honest nodes in 5/5 seeds, never releases: 15/15 node-seeds.
E isolates 1/15 node-seeds (seed1 node1, t=110, released t=355).
Isolation-seconds on honest nodes: D mean 1054, E mean 49 (21.5x reduction).
No isolate-release churn in E; the schedules are correct, not buggy.
Fused detector false-confirmed once on a clean network (seed1 node1, t=110).
