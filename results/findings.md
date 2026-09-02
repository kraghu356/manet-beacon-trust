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

## Paper 3: multi-class baseline (Aug 29)
Six classes, random forest, 5-fold CV. Macro F1 0.898, accuracy 0.992.
  Flooding 0.990 | BHA 0.981 | Normal 0.996 | GHA 0.933 | Sink 0.777 | Worm 0.709
Sinkhole and wormhole are mutually confused: both show high no_route (33 vs 40)
  with normal fwd_ratio. A per-node classifier cannot separate them.
  => the concrete gap a graph model must close. The distinction is structural:
  sinkhole attracts unservable routes; wormhole creates a fake adjacency
  between two specific nodes.
Severe imbalance: 7314 Normal vs 47 GHA windows. Motivates focal loss.

## Paper 3: multi-class baseline (Aug 29)
Six classes, random forest, 5-fold CV. Macro F1 0.898, accuracy 0.992.
  Flooding 0.990 | BHA 0.981 | Normal 0.996 | GHA 0.933 | Sink 0.777 | Worm 0.709
Sinkhole and wormhole are mutually confused: both show high no_route with
  normal fwd_ratio. A per-node classifier cannot separate them.
  => the concrete gap a graph model must close.
Imbalance: 7314 Normal vs 47 GHA windows. Motivates focal loss.

## Paper 3: temporal features (Aug 29)
EWMA(alpha=0.3) of fwd_ratio, no_route, nb_max_dist, rreq_sent, plus slope.
Binary grey hole, run-level split: F1 0.9805 -> 0.9981.
Multi-class macro F1 0.898 -> 0.924. Per class:
  Flood 0.990 | BHA 0.975 | GHA 0.957 | Normal 0.998 | Sink 0.823 | Worm 0.800
GOTCHA: EWMA must be grouped by (run, node_id). Grouping by (class, node_id)
  pools honest nodes from different runs and destroyed flooding precision
  (1.000 -> 0.581).
Sink/Worm remain the hard pair (recall 0.78 / 0.68): both show high no_route
  with normal fwd_ratio. Temporal smoothing does not separate them, which
  confirms the distinction is structural and motivates the graph model.

## Paper 3: full dataset and classical baseline (Aug 30)
120 runs, 20 seeds x 6 conditions, 347900 rows, 157945 with forwarding activity.
Imbalance after filtering: normal 150250, sink 2490, bha 2030, flood 1439,
  gha 1227, worm 509. Worst ratio 295:1.
Split by seed: train 1-12, val 13-16, test 17-20. No run in two partitions.
Random forest, 300 trees, balanced class weights, 13 features incl. 4 EWMA:
  macro F1 0.918, accuracy 0.993
  normal 0.997 | bha 0.996 | gha 0.990 | flood 0.983 | sink 0.872 | worm 0.672
Holds from 5 runs (0.924) to 20 runs (0.918): features generalise across topology.
Residual error is entirely sink/worm, which trade errors with each other.
  sink precision 0.810 recall 0.944; worm precision 0.653 recall 0.694.
=> Any model must beat 0.918, and can only do so by exploiting structure.

## Paper 3: GRU sequence model (Aug 30)
2-layer GRU, hidden 64, masked mean pooling, class-weighted CE, 30 epochs.
Node-level predictions broadcast to windows so the comparison matches the
  random forest exactly: same 34676 test windows, same seed split.
  macro F1 0.918 (RF) -> 0.983 (GRU)
  worm 0.672 -> 1.000 | sink 0.872 -> 0.928 | flood 0.983 -> 1.000
  gha 0.990 -> 0.975 (slight loss)
=> The sink/worm error was TEMPORAL, not structural. nb_max_dist spikes only
   when the tunnel endpoints are far apart; a per-window classifier sees an
   intermittent signal, a sequence model sees the pattern.
=> The earlier justification for a graph model does not hold. A GATv2 must
   now beat 0.983 and would be a stronger model, not a necessary one.
CAUTION: node-level report showed worm 1.000 on only 7 sequences. The
  per-window broadcast (111 rows) is the trustworthy number.

## Paper 3: GRU sequence model (Aug 30)
2-layer GRU, hidden 64, masked mean pooling, class-weighted CE, 30 epochs.
Node predictions broadcast to windows: same 34676 test windows as the RF.
  macro F1 0.918 (RF) -> 0.983 (GRU)
  worm 0.672 -> 1.000 | sink 0.872 -> 0.928 | flood 0.983 -> 1.000
=> The sink/worm error was TEMPORAL, not structural. A GATv2 must now beat
   0.983 and would be a stronger model, not a necessary one.

## Paper 3: detection latency curve (Aug 30)
GRU macro-F1 against observation window (node-level, 2300 test sequences):
   5 windows ( 50s): F1 0.660  precision 0.615  recall 0.922
  10 windows (100s): F1 0.802  precision 0.765  recall 0.945
  15 windows (150s): F1 0.841  precision 0.792  recall 0.987
  20 windows (200s): F1 0.900  precision 0.836  recall 0.989
  29 windows (290s): F1 0.949  precision 0.928  recall 0.982
Recall is high from the start; PRECISION is what improves with observation.
=> Attackers are spotted quickly; distinguishing them from honest nodes is
   what takes time. Mirrors Paper 2's false-isolation cost result.
Flooding stays at F1 1.000 even at 10 windows; sink/worm need the full run.

## Paper 3: per-attack detection latency (Aug 30)
GRU F1 by attack and observation window (node-level, small support):
  attack   50s    100s   200s   290s
  flood   1.000  1.000  1.000  1.000   (immediate: 307 RREQ/window)
  bha     0.889  0.919  0.833  0.974   (fast: fwd_ratio -> 0 at once)
  gha     0.345  0.865  0.857  0.923   (needs packets for the ratio to settle)
  sink    0.435  0.541  0.784  0.800   (route failures accumulate slowly)
  worm    0.326  0.500  0.933  1.000   (only visible when endpoints drift apart)
=> Attacks that change behaviour instantly are caught instantly; attacks with
   statistical or intermittent signatures need observation time.
CAVEATS: worm has only 7 test sequences. bha is non-monotonic (0.833 at 20
  windows) which is likely training noise; rerun over seeds before publishing.

## Paper 3: zero-day / open-set failure (Aug 30)
Trained on 4 attacks + normal, wormhole held out entirely (no train or val).
All 7 held-out wormhole nodes classified NORMAL with confidence 1.000.
Mean max-softmax by true class: worm 1.000, sink 1.000, flood 1.000,
  bha 0.989, gha 0.982, normal 0.967 -- the UNSEEN class is the most confident.
Thresholding max-softmax: 0/7 wormholes flagged unknown at 0.9, 0.95 or 0.99,
  while 213-400 of 2293 known-class nodes were falsely flagged.
=> Max-softmax gives no novelty signal; the network is overconfident OOD.
=> Failure direction is toward 'normal', not toward a similar attack. A novel
   attack passes silently with no anomaly reported.
=> Motivates an explicit open-set mechanism (energy score, Mahalanobis,
   reconstruction error) rather than confidence gating on softmax.
CAVEAT: only 7 wormhole test sequences.

## Paper 3: post-hoc OOD scoring also fails (Aug 30)
Energy score and max-softmax on the 4-attack model, wormhole held out:
  AUROC unseen-vs-seen: energy 0.277, max-softmax 0.323 -- both BELOW chance.
Mean energy: flood -8.68, sink -7.80, gha -7.76, bha -7.75, worm -6.53,
  normal -5.89. The unseen attack sits nearer NORMAL than the known attacks.
=> A discriminative model learns what attacks look like; an unseen attack
   that matches none of them falls into the normal region. No post-hoc score
   can recover this -- the representation does not encode it as unusual.
=> Points to a normality model (autoencoder / one-class on normal traffic)
   rather than confidence gating on a classifier.
CAVEAT: 7 wormhole sequences, single training run. Repeat across seeds.

## Paper 3: normality model for open-set (Aug 30)
GRU autoencoder trained on NORMAL traffic only (1122 sequences, no attacks).
Reconstruction-error AUROC vs normal:
  flood 1.000 | sink 0.991 | worm 0.906 | bha 0.648 | gha 0.396
Wormhole 0.906 from a model that never saw any attack, vs 0.277 for the
  energy score on the discriminative model. The signature IS anomalous;
  a classifier trained on other attacks had no reason to encode it.
COMPLEMENTARY: the attacks the classifier handles best (bha, gha) are the
  ones the autoencoder handles worst, and vice versa. Suggests classifier
  for known attacks + normality model for novel ones.
CAVEAT: recon error spans 5.1 to 82906, dominated by unbounded rreq_sent.
  Re-check AUROCs after log-transforming that feature.

## Paper 3: open-set with log-scaled features (Aug 30)
log1p on unbounded count features before scaling. AUROC vs normal:
  flood 1.000 | sink 1.000 | worm 0.996 | bha 0.723 | gha 0.442
Wormhole 0.906 -> 0.996. Recon errors now 6-218, not 5-82906: a learned
  representation rather than one runaway feature.
Zero-day wormhole AUROC 0.996 from a model that saw NO attacks.
COMPLEMENTARITY (measured):
  autoencoder wins on flood/sink/worm - attacks that ADD activity
  classifier wins on bha/gha (0.996/0.990) - attacks that SUPPRESS it
=> Architecture: classifier for suppression attacks, normality model for
   additive and novel ones. Neither alone covers all five.

## Paper 3: open-set with log-scaled features (Aug 30)
log1p on unbounded counts before scaling. AUROC vs normal:
  flood 1.000 | sink 1.000 | worm 0.996 | bha 0.723 | gha 0.442
Zero-day wormhole AUROC 0.996 from a model that saw NO attacks.
COMPLEMENTARITY: autoencoder wins on flood/sink/worm (attacks that ADD
  activity); classifier wins on bha/gha 0.996/0.990 (attacks that SUPPRESS).

## Paper 3: zero-day AUROC across 3 training seeds (Aug 30)
GRU autoencoder on normal traffic only, log1p on unbounded counts.
  flood 1.000 +/- 0.000 | sink 1.000 +/- 0.000 | worm 0.996 +/- 0.000
  bha   0.713 +/- 0.025 | gha  0.444 +/- 0.004
Wormhole 0.996 with zero variance over independent training runs.
GHA consistently BELOW chance (0.444, sd 0.004): a node forwarding half its
  packets reconstructs better than average normal traffic. Systematic, not noise.
CAVEATS: variance is over training seeds, not data. Same 2300 test sequences,
  worm still only 7 of them. Full leave-one-attack-out (5 models) still to do.

## Paper 3: full leave-one-attack-out (Aug 30)
Five classifiers, each blind to one attack. Softmax AUROC for unseen-vs-seen:
  gha 0.926 (called bha 18/19) | sink 0.613 (normal 20/20)
  worm 0.420 (normal 7/7) | bha 0.290 (called gha 20/20) | flood 0.230 (normal 19/19)
Classifier macro-F1 on KNOWN classes stays 0.823-0.988 throughout: the blind
  spot is invisible in reported metrics.
Two failure modes: bha<->gha are mistaken for each other (benign, node still
  isolated); flood/sink/worm collapse UNANIMOUSLY to 'normal' (no alarm).
GHA is the only usable AUROC because BHA remains in training as a near neighbour.
=> Discriminative IDS silently passes novel attacks unless a close relative is
   in the training set.
=> The autoencoder catches exactly the three that collapse to normal:
   flood 1.000, sink 1.000, worm 0.996. The two models are complementary by
   construction, not coincidence.

## Paper 3: hybrid operating point (Aug 30)
AE gate threshold = 95th pct of validation-normal reconstruction error (21.92).
Novel attacks caught as unknown, at 5.4% false-unknown on honest nodes:
  flood 19/19 | sink 20/20 | worm 7/7 | bha 0/20 | gha 0/19
Exactly complementary to the classifier (bha 0.996, gha 0.990; flood/sink/worm
  collapse to 'normal').
Mechanism, not coincidence: suppression attacks reconstruct well because a
  quiet node resembles a normal one; additive attacks reconstruct badly.
=> Hybrid covers all five. Cost is 5.4% of honest nodes flagged for review,
   the same availability trade-off Paper 2 quantified as Phi.

## Paper 3: 4-fold data cross-validation of the AE (Aug 30)
Rotating held-out seeds, not just training seeds. AUROC vs normal:
  flood 0.996 +/- 0.005 | sink 0.996 +/- 0.004 | worm 0.963 +/- 0.054
  bha   0.811 +/- 0.053 | gha  0.374 +/- 0.046
Wormhole per fold: 0.996, 0.987, 1.000, 0.870. The single-split 0.996 was the
  optimistic end; 0.963 +/- 0.054 is the honest figure (7-8 test sequences/fold).
GHA below chance in ALL folds (0.317-0.442): a half-forwarding node
  reconstructs better than average normal traffic. Systematic property of the
  attack, and the clearest justification for the hybrid.

## Paper 3: 4-fold CV of the GRU classifier (Aug 30)
macro F1 0.894 +/- 0.053 across rotating held-out seeds.
  folds: 0.952, 0.941, 0.843, 0.840 -- seeds 17-20 was the BEST split.
  bha 0.987+/-0.013 | normal 0.989+/-0.011 | flood 0.976+/-0.017
  sink 0.946+/-0.066 | worm 0.773+/-0.164 | gha 0.693+/-0.279
CORRECTION: the single-split 0.983 with worm 1.000 was optimistic. Across
  folds the GRU does NOT reliably solve wormhole (0.773, sd 0.164).
Hybrid case is stronger, not weaker: AE gets worm 0.963+/-0.054 (better mean,
  one third the variance) and fails on gha; classifier is the reverse.
Variance driven by small support: 7-8 worm and 19-20 gha sequences per fold.
