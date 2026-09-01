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

## Paper 3 baseline (Aug 29)
manet-gen: 80211b DsssRate11Mbps, plExp=2.5, txPower=23dBm, 10 flows @ 4pkt/s, 512B
100 nodes @ 1500x1500m: PDR 0.824, hops 2.18, delay 43ms
50 nodes @ 1060x1060m:  PDR 0.824, hops 2.50
802.11g breaks AODV multi-hop: hops=1.0 in every configuration tested.
Distance-based flow pairing failed: node positions are zero at app-setup time.
150 nodes still single-hop; affects scalability test only, not the main experiment.

## Paper 3: black hole implemented and verified (Aug 29)
src/aodvatk = private AODV clone; forged RREP in RecvRequest + drop in Forwarding().
Attributes: EnableBlackHole (bool), DropProb (0-1; 1.0=BHA, 0.3-0.8=GHA).
100 nodes, 1500x1500m, 80211b, plExp 2.5, txPower 23dBm, 10 flows @ 4pkt/s:
  0 malicious:  PDR 0.824  hops 2.18
  5 malicious:  PDR 0.532  hops 1.28
  10 malicious: PDR 0.568  hops 1.19
Hop count drop confirms the forge: attackers advertise 1-hop routes to everything.
Module rename gotchas: NS_LOG_COMPONENT_DEFINE names and the helper class
  (AodvHelper -> AodvAtkHelper) both collide with stock aodv if not renamed.

## Paper 3: black hole verified (Aug 29)
src/aodvatk = private AODV clone. Forged RREP in RecvRequest, drop in Forwarding().
Attributes: EnableBlackHole, DropProb (1.0=BHA, 0.3-0.8=GHA).
100 nodes, 1500x1500m, 80211b, plExp 2.5, txP 23dBm, 10 flows @ 4pkt/s:
  0 malicious:  PDR 0.824 hops 2.18
  5 malicious:  PDR 0.532 hops 1.28
  10 malicious: PDR 0.568 hops 1.19
Hop drop 2.18->1.28 confirms the forge is working.
Rename gotchas: NS_LOG_COMPONENT_DEFINE strings and AodvHelper class name
  both collide with stock aodv.

## Paper 3: black hole verified (Aug 29)
src/aodvatk = private AODV clone. Forged RREP in RecvRequest, drop in Forwarding().
Attributes: EnableBlackHole, DropProb (1.0=BHA, 0.3-0.8=GHA).
100 nodes, 1500x1500m, 80211b, plExp 2.5, txP 23dBm, 10 flows @ 4pkt/s:
  0 malicious:  PDR 0.824 hops 2.18
  5 malicious:  PDR 0.532 hops 1.28
  10 malicious: PDR 0.568 hops 1.19
Hop drop 2.18->1.28 confirms the forge works.
Rename gotchas: NS_LOG_COMPONENT_DEFINE strings and the AodvHelper class name
  both collide with stock aodv and must be renamed.

## Paper 3: black hole verified (Aug 29)
src/aodvatk = private AODV clone. Forged RREP in RecvRequest, drop in Forwarding().
100 nodes, 1500x1500m, 80211b, plExp 2.5, txP 23dBm: 0 mal PDR 0.824 hops 2.18,
  5 mal PDR 0.532 hops 1.28, 10 mal PDR 0.568 hops 1.19.

## Paper 3: BHA and GHA verified (Aug 29)
src/aodvatk: forged RREP in RecvRequest, probabilistic drop in Forwarding().
100 nodes, 1500x1500m, 80211b, plExp 2.5, txP 23dBm, 5 malicious:
  dropProb 0.0: PDR 0.867 (forge alone does no damage; attackers relay honestly)
  dropProb 0.5: PDR 0.826, 2561/5094 dropped (50.3%, matches target)
  dropProb 1.0: PDR 0.532, 5583/5583 dropped
Non-linear: 50% drop costs 4 PDR points, 100% costs 33. AODV keeps a lossy
  route alive but tears down a dead one, triggering rediscovery.
=> GHA is near-invisible in network PDR but obvious in per-node forwarding
  ratio. Confirms per-node-window is the right dataset unit.

## Paper 3: BHA/GHA verified, parallel confirmed (Aug 29)
src/aodvatk: forged RREP in RecvRequest, probabilistic drop in Forwarding().
5 malicious of 100, dropProb 0.0/0.5/1.0 -> PDR 0.867/0.826/0.532.
Drop rate exact: 2561/5094 at p=0.5. Forge alone does no damage.
Seed variance is large: same config gave PDR 0.532/0.672/0.692 across 3 seeds.
parallel -j3 on the raw binary: 2.4x speedup, ~95s per 300s run.
Campaign estimate: 120 runs at 900s ~= 3.3 h with -j3.

## Paper 3: feature extractor working (Aug 29)
Per-node per-10s-window CSV: fwd_seen, fwd_ok, fwd_drop, no_route, fwd_ratio,
  rreq_recv, speed, is_malicious, label. All nodes run aodvatk (honest with
  EnableBlackHole=false) so counters are collected uniformly.
fwd_ratio = fwd_ok / (fwd_ok + fwd_drop): excludes no-route failures, which are
  routing conditions rather than misbehaviour. Honest nodes now read exactly 1.000.
Forge and drop split into separate attributes (ForgeRrep, DropProb).
  BHA (forge, p=1.0):        attacker ratio 0.000, F1 1.000
  GHA hijacking (forge,0.5): attacker ratio 0.141, F1 0.985 -- forge causes
    20.7 no-route events/window, so the attack is detected via route failure.
  GHA pure (no forge, 0.5):  attacker ratio 0.517, F1 0.981 -- honest detection.
Note: fwd_drop and fwd_ok leak the label for BHA (definitionally 0). Exclude
  from the feature set; fwd_ratio alone gives F1 0.95, without it 0.70.
Single-run CV: leaks across windows. Real evaluation needs run-level splits.

## Paper 3: sinkhole (Aug 29)
Sinkhole = forge RREPs, drop nothing (--forge=1 --dropProb=0.0).
attacker fwd_ratio 1.000 (identical to honest); detected via no_route 33.1 vs 1.1
and fwd_seen 38.7 vs 13.6. F1 0.886.
=> Distinct signature from BHA/GHA: the sinkhole advertises routes it cannot
   serve, so it fails to forward rather than refusing to. Three attacks now
   have three different feature signatures, which is what the multi-class
   problem needs.

## Paper 3: flooding attack (Aug 29)
FloodRate attribute: bogus RREQs/s to random unreachable 10.1.1.x addresses.
rreq_recv does NOT discriminate (1479 vs 1439): a broadcast storm is heard by
  everyone, so the feature cannot separate source from bystander. F1 0.678.
rreq_sent does: 48.4/window vs 0.00. F1 0.989.
CAUTION: rreq_sent currently counts only flood RREQs, so honest nodes read
  exactly 0 -- label leakage. Hook SendRequest() to count all originated RREQs.
Four attacks, four distinct signatures:
  BHA fwd_ratio 0.000 | GHA 0.517 | Sinkhole no_route 33.1 | Flood rreq_sent 48.4

## Paper 3: flooding attack (Aug 29)
FloodRate attribute: bogus RREQs/s to random unreachable 10.1.1.x addresses.
rreq_recv does NOT discriminate (1479 vs 1439): a broadcast storm is heard by
  everyone, so it cannot separate source from bystander. F1 0.678.
rreq_sent does: 48.4/window vs 0.00. F1 0.989.
CAUTION: rreq_sent counted only flood RREQs, so honest nodes read exactly 0.
  Label leakage, same class of defect as fwd_drop. Fix pending: hook
  SendRequest() to count all originated RREQs.
Four attacks, four distinct signatures:
  BHA fwd_ratio 0.000 | GHA 0.517 | Sinkhole no_route 33.1 | Flood rreq_sent 48.4
Remaining: wormhole, time-varying GHA, run-level splitting, campaign.

## Paper 3: flooding, leak fixed (Aug 29)
rreq_sent now hooks SendRequest(), counting ALL originated RREQs.
Honest nodes: 1.52/window (real AODV discovery). Attackers: 307.6.
F1 0.9946, up from 0.9886 with the leaky version.
307.6 vs a floodRate of 5/s: AODV retries each bogus RREQ with expanding TTL.
Four attacks, four leak-free signatures:
  BHA  fwd_ratio 0.000 vs 1.000  F1 1.00
  GHA  fwd_ratio 0.517 vs 1.000  F1 0.98
  Sink no_route  33.1  vs 1.1    F1 0.89
  Flood rreq_sent 307.6 vs 1.52  F1 0.99

## Paper 3: wormhole implemented, all five attacks done (Aug 29)
WormPartner attribute + registry; RREQ heard by one endpoint replayed by the
other with no hop increment. Recursion guard needed; replay must use the
receiving node's OWN interface address or GetNetDevice segfaults.
Effect: hops 2.18 -> 1.67, PDR 0.841 (unharmed). Endpoints forward honestly.
Detection with behavioural features only: F1 0.611.
  fwd_ratio 1.0 both classes; no_route LOWER for attackers; rreq_sent ~equal.
  Only weak signal is fwd_seen 40.6 vs 24.6 (traffic converges on the tunnel).
=> Behavioural features cannot detect a topological attack. This is the
   justification for neighbour-distance / neighbour-churn features and for
   the graph component of the teacher.
Difficulty spread: BHA 1.00, Flood 0.99, GHA 0.98, Sink 0.89, Worm 0.61.

## Paper 3: run-level split validated (Aug 29)
10 grey-hole runs, train seeds 1-7 (4801 rows), test 8-10 (3066 rows).
No window from a test run appears in training (spec section 22).
Macro F1 0.9805 vs 0.981 single-run CV: NO meaningful leakage.
  precision 1.000, recall 0.928 on the malicious class.
  0 false positives across 2927 honest windows; 10 of 139 attacker windows missed.
Misses are likely windows where a p=0.5 grey hole forwarded most traffic by
  chance. Temporal features (EWMA of fwd_ratio) should recover them.

## Paper 3: multi-class baseline (Aug 29)
Six classes, random forest, 5-fold CV. Macro F1 0.898, accuracy 0.992.
  Flooding 0.990 | BHA 0.981 | Normal 0.996 | GHA 0.933 | Sink 0.777 | Worm 0.709
Sinkhole and wormhole are mutually confused: both show high no_route (33 vs 40)
  with normal fwd_ratio. A per-node classifier cannot separate them.
  => this is the concrete gap the graph model must close. The distinction is
  structural: sinkhole attracts unservable routes; wormhole creates a fake
  adjacency between two specific nodes.
Severe imbalance: 7314 Normal vs 47 GHA windows. Motivates focal loss.
