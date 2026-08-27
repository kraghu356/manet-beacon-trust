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

## Aggregation ablation (Aug 27, 20 detection runs, fused mode)
G1 direct-only, G2 direct+indirect, G3 all three: identical confirmations.
  A1 6/15, A2 5/15, A3 6/15, none 1/15 in every configuration.
Components are live and differ: on A2-seed1, direct-only mean trust 0.7148 (50 confirmed),
  indirect-only 0.7548 (70 confirmed). Differences never cross the persistence gate.
History cannot be ablated alone: it seeds from other components, so w_history=1.0
  with others zero yields NaN trust by construction. Not a valid ablation cell.
Conclusion: B+L fusion does the work; the aggregation layer is inert at this scale.

## Recovery baseline
settle_s=20.0 required; the default 5.0 put baseline inside the throughput ramp.
With the fix, none gives recovery_ratio 0.971 +/- 0.093, A3 0.926 +/- 0.144.
throughput_debt_kbit is not trustworthy yet: nonzero on clean runs (12184 kbit),
  because the 20-30s baseline window is too short. Exclude from tables pending a rerun.

## A1 has no packet-level footprint
A1 and none recovery curves are byte-identical (cmp confirms, all seeds).
A1 is pure false-location: attacker forwards honestly. Report A1 against localization
  error, not PDR. Yesterday's isolation-PDR null on A1 measured an effect that cannot exist.
