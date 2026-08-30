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

## EMBN-MANET (Kuriakose, Joshi, Bairwa; Ad Hoc Networks 140:103063, 2023)
Read from SSRN preprint 4148530 on Aug 27.
Evidence: RSSI + trilateration only, k-polytopes centroids. No behavioural component.
Attack model: beacon spoofs false location coordinates. NO forwarding attack considered.
  => A2 and A3 are outside their threat model, not failures of their method.
Response: reputation value assigned; beacon excluded from LOCALIZATION COORDINATION.
  => NOT packet-forwarding blacklisting. Arm D is NOT EMBN. Relabel arm D as
  'immediate isolation on suspicion', a policy of our own design.
Accuracy: 100% when fewer than 4 malicious beacons per neighbourhood, >85% above four.
  The abstract's flat 90% is the less precise figure; cite the conditional one.
Their stated limitation: static beacon nodes only; mobile beacons named as future work.
  Our beacons are mobile. Clean differentiator, in their own framing.
Fair comparison axis: detection coverage (our E2 models their evidence class; E2 = 0/5 on A2).

## Arm comparison under attack (Aug 27, 45 runs, A1/A2/A3 x C/D/E x 5 seeds)
Detection identical across arms within each attack (fp 0.20/0.00/0.25), as expected:
  arms differ only in post-verdict policy, so any arm difference is isolation policy alone.
D isolates at ~20s mean, BEFORE the attack starts at 30s, in all three attacks.
  D's fast recovery_time (4.5-6.2s) is therefore an artifact of isolating pre-attack.
E isolates at 45s (A1, A3) and 54s (A2), zero variance: confirmation is deterministic.
throughput_debt shows no consistent ordering across attacks and CIs exceed differences.
  Combined with nonzero debt on clean runs, this metric is not usable. Excluded.
Conclusion: no throughput advantage for either arm survives its CI.
  Objective 4 rests on false-isolation cost (clean network: D 15/15, E 1/15), not throughput.

## A3 is not a fusion-only region (Aug 27)
At half intensity on both axes, all three modes detect the attacker 5/5:
  behaviour 11111, localization 11111, fused 11111.
Fusion adds nothing on A3. The coverage claim rests on A1/A2 blindness (structural),
  not on sensitivity to weak signals. Sensitivity advantage tested and not found.

## A1 offset is diagonal and clamped (Aug 28)
mbtr-sim.cc:276-277 adds the same offset d to BOTH x and y, then clamps to the field.
Nominal d=300m therefore gives displacement d*sqrt(2)=424m before clamping,
and 267m measured mean after clamping (p95 299m, median 271m).
Effective attack strength depends on the beacon's position in the field.
Table 4 must say: per-axis offset 300m, applied diagonally, clamped; measured mean 267m.
Sweep x-axis must be plotted against MEASURED displacement, not nominal f.

## Paper 3 baseline (Aug 29)
manet-gen: 80211b DsssRate11Mbps, plExp=2.5, txPower=23dBm, 10 flows @ 4pkt/s, 512B
100 nodes @ 1500x1500m: PDR 0.824, hops 2.18, delay 43ms
50 nodes @ 1060x1060m:  PDR 0.824, hops 2.50
802.11g breaks AODV multi-hop entirely: hops=1.0 in every config tested.
Distance-based flow pairing FAILED: positions are zero at app-setup time.
150 nodes still single-hop; unresolved, affects scalability test only.
