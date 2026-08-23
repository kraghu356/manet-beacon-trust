/*
 * mbtr-sim.cc — Multi-evidence Beacon Trust and Recovery, evidence-generation stage.
 *
 * Covers plan Steps 5 (clean baseline), 6 (false-location beacon) and 7
 * (behavioural evidence). Produces the raw feature columns fixed in
 * docs/03-architecture.md. It does NOT compute trust or make decisions — that is
 * Step 8 onward and lives outside the simulator so the model can be iterated
 * without re-running NS-3.
 *
 * Build: symlink into an NS-3 tree's scratch/ (see scripts/setup_ns3.sh).
 *
 * Attack selection:
 *   --attack=none  clean baseline
 *   --attack=A1    false-location beacon, honest forwarding
 *   --attack=A2    honest position, grey-hole forwarding
 *   --attack=A3    hybrid, both at half intensity
 *
 * Outputs (into --outDir):
 *   ground_truth.csv   labels; never an input to the model
 *   beacon_rx.csv      one row per beacon reception (localization evidence)
 *   behaviour.csv      one row per node per window (behavioural evidence)
 *   flows.csv          per-flow PDR / throughput / delay
 *   summary.csv        network-level aggregates
 */

#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/energy-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/traffic-control-module.h"
#include "ns3/wifi-module.h"

#include "mbtr-isolation.h"

#include <fstream>
#include <set>
#include <iomanip>
#include <map>
#include <sstream>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("MbtrSim");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

struct Config
{
    uint32_t nNodes = 20;
    uint32_t nBeacons = 3;    // beacons are node ids 0 .. nBeacons-1
    uint32_t attacker = 2;    // must be < nBeacons
    std::string attack = "none";
    double offsetM = 300.0;   // A1 magnitude
    double dropProb = 0.6;    // A2 magnitude
    double attackStart = 30.0;
    double simTime = 200.0;
    double areaX = 1000.0;
    double areaY = 1000.0;
    double minSpeed = 1.0;
    double maxSpeed = 5.0;
    double pause = 2.0;
    uint32_t nFlows = 4;
    uint32_t pktSize = 512;
    double pktRate = 4.0;     // packets per second per flow
    double beaconInterval = 1.0;
    double window = 10.0;     // observation window
    double windowStep = 5.0;  // 50% overlap
    double txPowerDbm = 16.0206;
    double pathLossExp = 3.0;
    double refLossDb = 46.6777; // loss at 1 m, LogDistance default
    uint32_t seed = 1;
    uint32_t run = 1;
    std::string outDir = "results";
    std::string isolationSchedule = "";  // empty = no isolation (Steps 5-7 only)
    double binS = 1.0;                   // recovery-curve resolution
};

static Config g_cfg;

// Effective attack parameters after intensity scaling for A3.
static double
EffectiveOffset()
{
    if (g_cfg.attack == "A1")
        return g_cfg.offsetM;
    if (g_cfg.attack == "A3")
        return g_cfg.offsetM * 0.5;
    return 0.0;
}

static double
EffectiveDropProb()
{
    if (g_cfg.attack == "A2")
        return g_cfg.dropProb;
    if (g_cfg.attack == "A3")
        return g_cfg.dropProb * 0.5;
    return 0.0;
}

static bool
AttackActive()
{
    return g_cfg.attack != "none";
}

// ---------------------------------------------------------------------------
// Global evidence tables
// ---------------------------------------------------------------------------

struct RssiSample
{
    double timeS = -1.0;
    double rssiDbm = 0.0;
};

// (receiving node id, transmitting node id) -> most recent RSSI
static std::map<std::pair<uint32_t, uint32_t>, RssiSample> g_rssi;
static std::map<Mac48Address, uint32_t> g_macToNode;
static std::map<Ipv4Address, uint32_t> g_ipToNode;

// Per-node behavioural counters, cumulative.
struct NodeCounters
{
    uint64_t transitRx = 0;   // packets offered to this node for forwarding
    uint64_t forwarded = 0;   // packets actually forwarded
    uint64_t maliciousDrop = 0;
    uint64_t ipDrop = 0;      // drops for ordinary reasons (queue, TTL, no route)
    double delaySumS = 0.0;   // relay latency accumulator
    uint64_t delaySamples = 0;
};

static std::vector<NodeCounters> g_counters;
static std::vector<NodeCounters> g_countersPrev;

// Packet uid -> time the node accepted it for forwarding, for relay latency.
static std::map<std::pair<uint32_t, uint64_t>, double> g_transitEntryTime;

static std::vector<uint64_t> g_rxBytesBin;  // delivered bytes per time bin
static std::vector<uint64_t> g_rxPktsBin;

static std::ofstream g_beaconRx;
static std::ofstream g_behaviour;

// ---------------------------------------------------------------------------
// Distance estimation from RSSI (inverse log-distance path loss)
// ---------------------------------------------------------------------------

static double
EstimateDistance(double rssiDbm)
{
    // Pr(d) = Pt - refLoss - 10 n log10(d / 1m)
    double exponentArg = (g_cfg.txPowerDbm - g_cfg.refLossDb - rssiDbm) /
                         (10.0 * g_cfg.pathLossExp);
    return std::pow(10.0, exponentArg);
}

// ---------------------------------------------------------------------------
// Beacon payload
// ---------------------------------------------------------------------------

struct BeaconPayload
{
    uint32_t beaconId;
    uint32_t seq;
    double claimedX;
    double claimedY;
    double txTimeS;
};

// ---------------------------------------------------------------------------
// BeaconApp — periodic position advertisement. Lies iff this node is the
// attacker and the active scenario includes a location component.
// ---------------------------------------------------------------------------

class BeaconApp : public Application
{
  public:
    static TypeId GetTypeId();
    void Setup(uint32_t beaconId, bool liesAboutPosition, double offsetM);

  private:
    void StartApplication() override;
    void StopApplication() override;
    void Send();

    Ptr<Socket> m_socket;
    EventId m_event;
    uint32_t m_beaconId = 0;
    uint32_t m_seq = 0;
    bool m_lies = false;
    double m_offset = 0.0;
};

TypeId
BeaconApp::GetTypeId()
{
    static TypeId tid =
        TypeId("BeaconApp").SetParent<Application>().AddConstructor<BeaconApp>();
    return tid;
}

void
BeaconApp::Setup(uint32_t beaconId, bool liesAboutPosition, double offsetM)
{
    m_beaconId = beaconId;
    m_lies = liesAboutPosition;
    m_offset = offsetM;
}

void
BeaconApp::StartApplication()
{
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_socket->SetAllowBroadcast(true);
    m_socket->Bind();
    m_socket->Connect(InetSocketAddress(Ipv4Address("255.255.255.255"), 9999));
    m_event = Simulator::Schedule(Seconds(0.1), &BeaconApp::Send, this);
}

void
BeaconApp::StopApplication()
{
    Simulator::Cancel(m_event);
    if (m_socket)
    {
        m_socket->Close();
    }
}

void
BeaconApp::Send()
{
    Ptr<MobilityModel> mob = GetNode()->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();

    BeaconPayload p;
    p.beaconId = m_beaconId;
    p.seq = m_seq++;
    p.claimedX = pos.x;
    p.claimedY = pos.y;
    p.txTimeS = Simulator::Now().GetSeconds();

    // The lie only takes effect once the attack window opens; before that the
    // attacker is indistinguishable from an honest beacon, which is what gives
    // the trust model a clean history to build on.
    if (m_lies && Simulator::Now().GetSeconds() >= g_cfg.attackStart)
    {
        // Fixed displacement along the diagonal, clamped to the field.
        double d = m_offset / std::sqrt(2.0);
        p.claimedX = std::min(g_cfg.areaX, std::max(0.0, pos.x + d));
        p.claimedY = std::min(g_cfg.areaY, std::max(0.0, pos.y + d));
    }

    Ptr<Packet> packet = Create<Packet>(reinterpret_cast<uint8_t*>(&p), sizeof(p));
    m_socket->Send(packet);

    m_event = Simulator::Schedule(Seconds(g_cfg.beaconInterval), &BeaconApp::Send, this);
}

// ---------------------------------------------------------------------------
// BeaconMonitor — runs on every node. Logs one localization-evidence row per
// beacon reception.
// ---------------------------------------------------------------------------

class BeaconMonitor : public Application
{
  public:
    static TypeId GetTypeId();

  private:
    void StartApplication() override;
    void StopApplication() override;
    void HandleRead(Ptr<Socket> socket);

    Ptr<Socket> m_socket;
};

TypeId
BeaconMonitor::GetTypeId()
{
    static TypeId tid =
        TypeId("BeaconMonitor").SetParent<Application>().AddConstructor<BeaconMonitor>();
    return tid;
}

void
BeaconMonitor::StartApplication()
{
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9999));
    m_socket->SetRecvCallback(MakeCallback(&BeaconMonitor::HandleRead, this));
}

void
BeaconMonitor::StopApplication()
{
    if (m_socket)
    {
        m_socket->Close();
    }
}

void
BeaconMonitor::HandleRead(Ptr<Socket> socket)
{
    Address from;
    Ptr<Packet> packet;
    while ((packet = socket->RecvFrom(from)))
    {
        if (packet->GetSize() < sizeof(BeaconPayload))
        {
            continue;
        }

        BeaconPayload p;
        packet->CopyData(reinterpret_cast<uint8_t*>(&p), sizeof(p));

        uint32_t rxId = GetNode()->GetId();
        Ipv4Address src = InetSocketAddress::ConvertFrom(from).GetIpv4();
        if (g_ipToNode.find(src) == g_ipToNode.end())
        {
            continue;
        }
        uint32_t txId = g_ipToNode[src];

        // Do not measure a node against itself.
        if (txId == rxId)
        {
            continue;
        }

        auto it = g_rssi.find({rxId, txId});
        if (it == g_rssi.end())
        {
            continue; // no physical-layer sample; drop the row rather than guess
        }
        double rssi = it->second.rssiDbm;

        Vector rxPos = GetNode()->GetObject<MobilityModel>()->GetPosition();
        Vector txPos = NodeList::GetNode(txId)->GetObject<MobilityModel>()->GetPosition();

        double estD = EstimateDistance(rssi);
        double claimedD = std::sqrt(std::pow(p.claimedX - rxPos.x, 2) +
                                    std::pow(p.claimedY - rxPos.y, 2));
        double trueD = std::sqrt(std::pow(txPos.x - rxPos.x, 2) +
                                 std::pow(txPos.y - rxPos.y, 2));

        bool isAttacker = AttackActive() && txId == g_cfg.attacker &&
                          Simulator::Now().GetSeconds() >= g_cfg.attackStart;

        g_beaconRx << std::fixed << std::setprecision(4)
                   << Simulator::Now().GetSeconds() << ',' << rxId << ',' << txId << ','
                   << p.seq << ',' << p.claimedX << ',' << p.claimedY << ',' << txPos.x
                   << ',' << txPos.y << ',' << rxPos.x << ',' << rxPos.y << ',' << rssi
                   << ',' << estD << ',' << claimedD << ',' << trueD << ','
                   << std::fabs(estD - claimedD) << ',' << (isAttacker ? 1 : 0) << '\n';
    }
}

// ---------------------------------------------------------------------------
// TransitControlRouting — installed on EVERY node at higher priority than AODV.
//
// With dropProb = 0 it is a pure observer: it counts packets offered for
// forwarding and declines them so AODV handles the actual routing. With
// dropProb > 0 it silently discards a fraction of transit traffic, which is the
// grey-hole. Locally originated and locally destined traffic is never touched,
// so the attacker's own flows and the AODV control plane behave normally and it
// keeps winning routes.
// ---------------------------------------------------------------------------

class TransitControlRouting : public Ipv4RoutingProtocol
{
  public:
    static TypeId GetTypeId();
    TransitControlRouting();

    void SetDropProbability(double p);
    void SetNodeId(uint32_t id);

    Ptr<Ipv4Route> RouteOutput(Ptr<Packet> p,
                               const Ipv4Header& header,
                               Ptr<NetDevice> oif,
                               Socket::SocketErrno& sockerr) override;
    bool RouteInput(Ptr<const Packet> p,
                    const Ipv4Header& header,
                    Ptr<const NetDevice> idev,
                    const UnicastForwardCallback& ucb,
                    const MulticastForwardCallback& mcb,
                    const LocalDeliverCallback& lcb,
                    const ErrorCallback& ecb) override;
    void NotifyInterfaceUp(uint32_t) override {}
    void NotifyInterfaceDown(uint32_t) override {}
    void NotifyAddAddress(uint32_t, Ipv4InterfaceAddress) override {}
    void NotifyRemoveAddress(uint32_t, Ipv4InterfaceAddress) override {}
    void SetIpv4(Ptr<Ipv4> ipv4) override;
    void PrintRoutingTable(Ptr<OutputStreamWrapper>, Time::Unit) const override {}

  private:
    Ptr<Ipv4> m_ipv4;
    Ptr<UniformRandomVariable> m_rand;
    double m_dropProb = 0.0;
    uint32_t m_nodeId = 0;
};

TypeId
TransitControlRouting::GetTypeId()
{
    static TypeId tid = TypeId("TransitControlRouting")
                            .SetParent<Ipv4RoutingProtocol>()
                            .AddConstructor<TransitControlRouting>();
    return tid;
}

TransitControlRouting::TransitControlRouting()
{
    m_rand = CreateObject<UniformRandomVariable>();
}

void
TransitControlRouting::SetDropProbability(double p)
{
    m_dropProb = p;
}

void
TransitControlRouting::SetNodeId(uint32_t id)
{
    m_nodeId = id;
}

void
TransitControlRouting::SetIpv4(Ptr<Ipv4> ipv4)
{
    m_ipv4 = ipv4;
}

Ptr<Ipv4Route>
TransitControlRouting::RouteOutput(Ptr<Packet>,
                                   const Ipv4Header&,
                                   Ptr<NetDevice>,
                                   Socket::SocketErrno&)
{
    // Never route locally originated traffic; defer to AODV.
    return nullptr;
}

bool
TransitControlRouting::RouteInput(Ptr<const Packet> p,
                                  const Ipv4Header& header,
                                  Ptr<const NetDevice> idev,
                                  const UnicastForwardCallback& ucb,
                                  const MulticastForwardCallback& mcb,
                                  const LocalDeliverCallback& lcb,
                                  const ErrorCallback& ecb)
{
    if (!m_ipv4)
    {
        return false;
    }

    Ipv4Address dst = header.GetDestination();
    int32_t iif = m_ipv4->GetInterfaceForDevice(idev);

    // Local delivery, broadcast and multicast are none of our business.
    if (dst.IsBroadcast() || dst.IsMulticast() || iif < 0 ||
        m_ipv4->IsDestinationAddress(dst, iif))
    {
        return false;
    }

    // From here on the packet is transiting this node.
    g_counters[m_nodeId].transitRx++;
    g_transitEntryTime[{m_nodeId, p->GetUid()}] = Simulator::Now().GetSeconds();

    bool attackWindow = Simulator::Now().GetSeconds() >= g_cfg.attackStart;
    if (m_dropProb > 0.0 && attackWindow && m_rand->GetValue() < m_dropProb)
    {
        g_counters[m_nodeId].maliciousDrop++;
        return true; // consumed and discarded, no callback fired
    }

    return false; // let AODV forward it
}

// ---------------------------------------------------------------------------
// Trace sinks
// ---------------------------------------------------------------------------

static void
PhyMonitorRx(uint32_t rxNodeId,
             Ptr<const Packet> packet,
             uint16_t /*channelFreqMhz*/,
             WifiTxVector /*txVector*/,
             MpduInfo /*aMpdu*/,
             SignalNoiseDbm signalNoise,
             uint16_t /*staId*/)
{
    // The monitor sniff carries the full frame, so the MAC header identifies the
    // transmitter. Keying on MAC rather than packet UID survives fragmentation
    // and aggregation, which UID matching does not.
    Ptr<Packet> copy = packet->Copy();
    WifiMacHeader hdr;
    if (copy->PeekHeader(hdr) == 0)
    {
        return;
    }
    Mac48Address tx = hdr.GetAddr2();
    auto it = g_macToNode.find(tx);
    if (it == g_macToNode.end())
    {
        return;
    }
    g_rssi[{rxNodeId, it->second}] = {Simulator::Now().GetSeconds(), signalNoise.signal};
}

static void
SinkRxTrace(Ptr<const Packet> p, const Address&)
{
    size_t bin = static_cast<size_t>(Simulator::Now().GetSeconds() / g_cfg.binS);
    if (bin < g_rxBytesBin.size())
    {
        g_rxBytesBin[bin] += p->GetSize();
        g_rxPktsBin[bin] += 1;
    }
}

static void
UnicastForwardTrace(uint32_t nodeId,
                    const Ipv4Header&,
                    Ptr<const Packet> p,
                    uint32_t)
{
    g_counters[nodeId].forwarded++;

    auto key = std::make_pair(nodeId, p->GetUid());
    auto it = g_transitEntryTime.find(key);
    if (it != g_transitEntryTime.end())
    {
        g_counters[nodeId].delaySumS += Simulator::Now().GetSeconds() - it->second;
        g_counters[nodeId].delaySamples++;
        g_transitEntryTime.erase(it);
    }
}

static void
Ipv4DropTrace(uint32_t nodeId,
              const Ipv4Header&,
              Ptr<const Packet>,
              Ipv4L3Protocol::DropReason,
              Ptr<Ipv4>,
              uint32_t)
{
    g_counters[nodeId].ipDrop++;
}

// ---------------------------------------------------------------------------
// Windowed behavioural sampling
// ---------------------------------------------------------------------------

static void
SampleWindow()
{
    double now = Simulator::Now().GetSeconds();

    for (uint32_t i = 0; i < g_cfg.nNodes; ++i)
    {
        const NodeCounters& c = g_counters[i];
        const NodeCounters& prev = g_countersPrev[i];

        uint64_t dTransit = c.transitRx - prev.transitRx;
        uint64_t dFwd = c.forwarded - prev.forwarded;
        uint64_t dMal = c.maliciousDrop - prev.maliciousDrop;
        uint64_t dIpDrop = c.ipDrop - prev.ipDrop;
        double dDelaySum = c.delaySumS - prev.delaySumS;
        uint64_t dDelayN = c.delaySamples - prev.delaySamples;

        // F_i and D_i are computed independently; they are not complements,
        // because packets can also be lost to collision or buffer overflow.
        double fRatio = dTransit ? static_cast<double>(dFwd) / dTransit : -1.0;
        double dRatio = dTransit ? static_cast<double>(dTransit - dFwd) / dTransit : -1.0;
        double meanDelay = dDelayN ? dDelaySum / dDelayN : -1.0;

        bool isBeacon = i < g_cfg.nBeacons;
        bool isAttacker = AttackActive() && i == g_cfg.attacker && now >= g_cfg.attackStart;

        g_behaviour << std::fixed << std::setprecision(6) << now << ',' << i << ','
                    << (isBeacon ? 1 : 0) << ',' << dTransit << ',' << dFwd << ','
                    << dMal << ',' << dIpDrop << ',' << fRatio << ',' << dRatio << ','
                    << meanDelay << ',' << (isAttacker ? 1 : 0) << '\n';
    }

    g_countersPrev = g_counters;

    if (now + g_cfg.windowStep < g_cfg.simTime)
    {
        Simulator::Schedule(Seconds(g_cfg.windowStep), &SampleWindow);
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int
main(int argc, char* argv[])
{
    CommandLine cmd(__FILE__);
    cmd.AddValue("nNodes", "Total nodes", g_cfg.nNodes);
    cmd.AddValue("nBeacons", "Beacon nodes (ids 0..n-1)", g_cfg.nBeacons);
    cmd.AddValue("attacker", "Attacker node id, must be a beacon", g_cfg.attacker);
    cmd.AddValue("attack", "none | A1 | A2 | A3", g_cfg.attack);
    cmd.AddValue("offset", "A1 location offset in metres", g_cfg.offsetM);
    cmd.AddValue("dropProb", "A2 grey-hole drop probability", g_cfg.dropProb);
    cmd.AddValue("attackStart", "Attack activation time (s)", g_cfg.attackStart);
    cmd.AddValue("simTime", "Simulation duration (s)", g_cfg.simTime);
    cmd.AddValue("nFlows", "Number of CBR flows", g_cfg.nFlows);
    cmd.AddValue("seed", "RNG seed", g_cfg.seed);
    cmd.AddValue("run", "RNG run number", g_cfg.run);
    cmd.AddValue("outDir", "Output directory", g_cfg.outDir);
    cmd.AddValue("isolation",
                 "CSV of isolation events (time_s,observer,target,action); "
                 "empty disables isolation",
                 g_cfg.isolationSchedule);
    cmd.Parse(argc, argv);

    if (g_cfg.attack != "none" && g_cfg.attack != "A1" && g_cfg.attack != "A2" &&
        g_cfg.attack != "A3")
    {
        NS_FATAL_ERROR("Unknown attack: " << g_cfg.attack);
    }
    if (AttackActive() && g_cfg.attacker >= g_cfg.nBeacons)
    {
        NS_FATAL_ERROR("Attacker " << g_cfg.attacker << " is not a beacon node");
    }

    RngSeedManager::SetSeed(g_cfg.seed);
    RngSeedManager::SetRun(g_cfg.run);

    std::string tag = g_cfg.attack + "-seed" + std::to_string(g_cfg.seed) + "-run" +
                      std::to_string(g_cfg.run);

    // --- nodes -------------------------------------------------------------
    NodeContainer nodes;
    nodes.Create(g_cfg.nNodes);
    g_counters.resize(g_cfg.nNodes);
    g_countersPrev.resize(g_cfg.nNodes);

    // --- mobility: Random Waypoint -----------------------------------------
    MobilityHelper mobility;
    Ptr<PositionAllocator> posAlloc =
        CreateObjectWithAttributes<RandomRectanglePositionAllocator>(
            "X",
            StringValue("ns3::UniformRandomVariable[Min=0.0|Max=" +
                        std::to_string(g_cfg.areaX) + "]"),
            "Y",
            StringValue("ns3::UniformRandomVariable[Min=0.0|Max=" +
                        std::to_string(g_cfg.areaY) + "]"));

    mobility.SetPositionAllocator(posAlloc);
    mobility.SetMobilityModel(
        "ns3::RandomWaypointMobilityModel",
        "Speed",
        StringValue("ns3::UniformRandomVariable[Min=" + std::to_string(g_cfg.minSpeed) +
                    "|Max=" + std::to_string(g_cfg.maxSpeed) + "]"),
        "Pause",
        StringValue("ns3::ConstantRandomVariable[Constant=" +
                    std::to_string(g_cfg.pause) + "]"),
        "PositionAllocator",
        PointerValue(posAlloc));
    mobility.Install(nodes);

    // --- wifi 802.11b ad hoc ------------------------------------------------
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",
                                 StringValue("DsssRate11Mbps"),
                                 "ControlMode",
                                 StringValue("DsssRate1Mbps"));

    YansWifiChannelHelper channel;
    channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss("ns3::LogDistancePropagationLossModel",
                               "Exponent",
                               DoubleValue(g_cfg.pathLossExp),
                               "ReferenceLoss",
                               DoubleValue(g_cfg.refLossDb));

    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());
    phy.Set("TxPowerStart", DoubleValue(g_cfg.txPowerDbm));
    phy.Set("TxPowerEnd", DoubleValue(g_cfg.txPowerDbm));

    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

    for (uint32_t i = 0; i < devices.GetN(); ++i)
    {
        Ptr<WifiNetDevice> wd = DynamicCast<WifiNetDevice>(devices.Get(i));
        Mac48Address mac = Mac48Address::ConvertFrom(wd->GetAddress());
        g_macToNode[mac] = nodes.Get(i)->GetId();
        IsolationRegistry::Get().RegisterNodeMac(nodes.Get(i)->GetId(), mac);
    }

    // --- isolation enforcement layer ---------------------------------------
    // Installed unconditionally, including on clean runs. With an empty
    // blacklist the qdisc is a plain FIFO, so its queueing behaviour is present
    // in the baseline too. Installing it only for isolation runs would confound
    // the recovery measurement with a change in queue discipline.
    TrafficControlHelper tch;
    tch.SetRootQueueDisc("BlacklistQueueDisc");
    QueueDiscContainer qdiscs = tch.Install(devices);
    for (uint32_t i = 0; i < qdiscs.GetN(); ++i)
    {
        Ptr<BlacklistQueueDisc> bq = DynamicCast<BlacklistQueueDisc>(qdiscs.Get(i));
        if (bq)
        {
            bq->SetNodeId(nodes.Get(i)->GetId());
        }
    }

    // --- routing: TransitControlRouting over AODV --------------------------
    AodvHelper aodv;
    InternetStackHelper stack;
    stack.SetRoutingHelper(aodv);
    stack.Install(nodes);

    Ipv4AddressHelper addr;
    addr.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = addr.Assign(devices);

    for (uint32_t i = 0; i < g_cfg.nNodes; ++i)
    {
        g_ipToNode[ifaces.GetAddress(i)] = nodes.Get(i)->GetId();
    }

    double attackerDrop = EffectiveDropProb();
    for (uint32_t i = 0; i < g_cfg.nNodes; ++i)
    {
        Ptr<Ipv4> ipv4 = nodes.Get(i)->GetObject<Ipv4>();
        Ptr<Ipv4ListRouting> list = DynamicCast<Ipv4ListRouting>(ipv4->GetRoutingProtocol());
        NS_ASSERT_MSG(list, "Expected Ipv4ListRouting");

        Ptr<TransitControlRouting> tcr = CreateObject<TransitControlRouting>();
        tcr->SetNodeId(i);
        tcr->SetIpv4(ipv4);
        if (AttackActive() && i == g_cfg.attacker)
        {
            tcr->SetDropProbability(attackerDrop);
        }
        list->AddRoutingProtocol(tcr, 100); // above AODV's default priority
    }

    // --- traffic: UDP CBR ---------------------------------------------------
    uint16_t port = 8080;
    ApplicationContainer sinks;
    ApplicationContainer sources;

    // Source/destination pairs drawn from non-beacon nodes so that traffic
    // endpoints are never the node under investigation.
    uint32_t firstData = g_cfg.nBeacons;
    uint32_t nData = g_cfg.nNodes - firstData;
    NS_ASSERT_MSG(nData >= 2 * g_cfg.nFlows, "Not enough non-beacon nodes for flows");

    for (uint32_t f = 0; f < g_cfg.nFlows; ++f)
    {
        uint32_t src = firstData + f;
        uint32_t dst = g_cfg.nNodes - 1 - f;

        PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                    InetSocketAddress(Ipv4Address::GetAny(), port + f));
        sinks.Add(sinkHelper.Install(nodes.Get(dst)));

        OnOffHelper onoff("ns3::UdpSocketFactory",
                          InetSocketAddress(ifaces.GetAddress(dst), port + f));
        onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        onoff.SetAttribute("PacketSize", UintegerValue(g_cfg.pktSize));
        onoff.SetAttribute(
            "DataRate",
            DataRateValue(DataRate(static_cast<uint64_t>(g_cfg.pktSize * 8 * g_cfg.pktRate))));
        sources.Add(onoff.Install(nodes.Get(src)));
    }

    sinks.Start(Seconds(0.0));
    sinks.Stop(Seconds(g_cfg.simTime));
    sources.Start(Seconds(10.0)); // after AODV has had a chance to settle
    sources.Stop(Seconds(g_cfg.simTime - 1.0));

    // --- beacons and monitors ----------------------------------------------
    bool lies = EffectiveOffset() > 0.0;
    for (uint32_t i = 0; i < g_cfg.nBeacons; ++i)
    {
        Ptr<BeaconApp> app = CreateObject<BeaconApp>();
        app->Setup(i, lies && AttackActive() && i == g_cfg.attacker, EffectiveOffset());
        nodes.Get(i)->AddApplication(app);
        app->SetStartTime(Seconds(1.0));
        app->SetStopTime(Seconds(g_cfg.simTime));
    }

    for (uint32_t i = 0; i < g_cfg.nNodes; ++i)
    {
        Ptr<BeaconMonitor> mon = CreateObject<BeaconMonitor>();
        nodes.Get(i)->AddApplication(mon);
        mon->SetStartTime(Seconds(0.5));
        mon->SetStopTime(Seconds(g_cfg.simTime));
    }

    // --- energy -------------------------------------------------------------
    // NOTE: NS-3 3.41+ moved these into the ns3::energy namespace. If the build
    // fails here, qualify with ns3::energy:: rather than deleting the block —
    // energy consumption is a required metric in Step 13.
    BasicEnergySourceHelper energySource;
    energySource.Set("BasicEnergySourceInitialEnergyJ", DoubleValue(100.0));
    EnergySourceContainer sources_e = energySource.Install(nodes);

    WifiRadioEnergyModelHelper radioEnergy;
    DeviceEnergyModelContainer deviceModels = radioEnergy.Install(devices, sources_e);

    // --- traces -------------------------------------------------------------
    for (uint32_t i = 0; i < g_cfg.nNodes; ++i)
    {
        std::ostringstream oss;
        oss << "/NodeList/" << i << "/DeviceList/0/$ns3::WifiNetDevice/Phy/MonitorSnifferRx";
        Config::ConnectWithoutContext(oss.str(), MakeBoundCallback(&PhyMonitorRx, i));

        std::ostringstream fwd;
        fwd << "/NodeList/" << i << "/$ns3::Ipv4L3Protocol/UnicastForward";
        Config::ConnectWithoutContext(fwd.str(), MakeBoundCallback(&UnicastForwardTrace, i));

        std::ostringstream drop;
        drop << "/NodeList/" << i << "/$ns3::Ipv4L3Protocol/Drop";
        Config::ConnectWithoutContext(drop.str(), MakeBoundCallback(&Ipv4DropTrace, i));
    }

    // --- output files -------------------------------------------------------
    std::string prefix = g_cfg.outDir + "/" + tag + "-";

    g_beaconRx.open(prefix + "beacon_rx.csv");
    g_beaconRx << "time_s,rx_node,beacon_id,seq,claimed_x,claimed_y,true_x,true_y,"
                  "rx_x,rx_y,rssi_dbm,est_dist_m,claimed_dist_m,true_dist_m,"
                  "residual_m,is_attacker\n";

    g_behaviour.open(prefix + "behaviour.csv");
    g_behaviour << "time_s,node,is_beacon,transit_rx,forwarded,malicious_drop,ip_drop,"
                   "fwd_ratio,drop_ratio,mean_relay_delay_s,is_attacker\n";

    std::ofstream gt(prefix + "ground_truth.csv");
    gt << "node_id,is_beacon,attack_type,attack_start_s,attack_stop_s,param_offset_m,"
          "param_drop_prob\n";
    for (uint32_t i = 0; i < g_cfg.nNodes; ++i)
    {
        bool isAtk = AttackActive() && i == g_cfg.attacker;
        gt << i << ',' << (i < g_cfg.nBeacons ? 1 : 0) << ','
           << (isAtk ? g_cfg.attack : "none") << ','
           << (isAtk ? g_cfg.attackStart : 0.0) << ','
           << (isAtk ? g_cfg.simTime : 0.0) << ','
           << (isAtk ? EffectiveOffset() : 0.0) << ','
           << (isAtk ? EffectiveDropProb() : 0.0) << '\n';
    }
    gt.close();

    // --- recovery instrumentation ------------------------------------------
    size_t nBins = static_cast<size_t>(g_cfg.simTime / g_cfg.binS) + 1;
    g_rxBytesBin.assign(nBins, 0);
    g_rxPktsBin.assign(nBins, 0);
    for (uint32_t i = 0; i < sinks.GetN(); ++i)
    {
        sinks.Get(i)->TraceConnectWithoutContext("Rx", MakeCallback(&SinkRxTrace));
    }

    // --- isolation schedule --------------------------------------------------
    std::vector<IsolationEvent> isoEvents;
    if (!g_cfg.isolationSchedule.empty())
    {
        isoEvents = LoadIsolationSchedule(g_cfg.isolationSchedule);
        if (isoEvents.empty())
        {
            NS_FATAL_ERROR("Isolation schedule " << g_cfg.isolationSchedule
                                                 << " is empty or unreadable");
        }
        for (const IsolationEvent& e : isoEvents)
        {
            Simulator::Schedule(Seconds(e.timeS),
                                &ApplyIsolationEvent,
                                e,
                                g_cfg.nNodes);
        }
    }

    Simulator::Schedule(Seconds(g_cfg.window), &SampleWindow);

    // --- flow monitor -------------------------------------------------------
    FlowMonitorHelper fmHelper;
    Ptr<FlowMonitor> monitor = fmHelper.InstallAll();

    Simulator::Stop(Seconds(g_cfg.simTime));
    Simulator::Run();

    // --- results ------------------------------------------------------------
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(fmHelper.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

    std::ofstream flows(prefix + "flows.csv");
    flows << "flow_id,src,dst,tx_packets,rx_packets,lost,pdr,throughput_kbps,"
             "mean_delay_ms,mean_jitter_ms\n";

    uint64_t totalTx = 0, totalRx = 0;
    double totalThroughput = 0.0, delayWeighted = 0.0;

    for (const auto& kv : stats)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(kv.first);
        if (t.destinationPort < 8080 || t.destinationPort >= 8080 + g_cfg.nFlows)
        {
            continue; // beacon and control traffic excluded from data-plane stats
        }

        const FlowMonitor::FlowStats& s = kv.second;
        double pdr = s.txPackets ? static_cast<double>(s.rxPackets) / s.txPackets : 0.0;
        double durS = (s.timeLastRxPacket - s.timeFirstTxPacket).GetSeconds();
        double thr = durS > 0 ? s.rxBytes * 8.0 / durS / 1000.0 : 0.0;
        double meanDelay = s.rxPackets ? s.delaySum.GetMilliSeconds() /
                                             static_cast<double>(s.rxPackets)
                                       : 0.0;
        double meanJitter = s.rxPackets > 1 ? s.jitterSum.GetMilliSeconds() /
                                                  static_cast<double>(s.rxPackets - 1)
                                            : 0.0;

        flows << kv.first << ',' << t.sourceAddress << ',' << t.destinationAddress << ','
              << s.txPackets << ',' << s.rxPackets << ',' << s.lostPackets << ','
              << pdr << ',' << thr << ',' << meanDelay << ',' << meanJitter << '\n';

        totalTx += s.txPackets;
        totalRx += s.rxPackets;
        totalThroughput += thr;
        delayWeighted += meanDelay * s.rxPackets;
    }
    flows.close();

    std::ofstream recovery(prefix + "recovery.csv");
    recovery << "bin_start_s,rx_packets,rx_bytes,throughput_kbps\n";
    for (size_t b = 0; b < g_rxBytesBin.size(); ++b)
    {
        recovery << std::fixed << std::setprecision(3) << b * g_cfg.binS << ','
                 << g_rxPktsBin[b] << ',' << g_rxBytesBin[b] << ','
                 << (g_rxBytesBin[b] * 8.0 / g_cfg.binS / 1000.0) << '\n';
    }
    recovery.close();

    double remainingEnergy = 0.0;
    for (uint32_t i = 0; i < sources_e.GetN(); ++i)
    {
        Ptr<BasicEnergySource> src = DynamicCast<BasicEnergySource>(sources_e.Get(i));
        remainingEnergy += src->GetRemainingEnergy();
    }
    double energyUsed = 100.0 * g_cfg.nNodes - remainingEnergy;

    uint64_t totalMalDrop = 0;
    for (uint32_t i = 0; i < g_cfg.nNodes; ++i)
    {
        totalMalDrop += g_counters[i].maliciousDrop;
    }

    std::ofstream summary(prefix + "summary.csv");
    summary << "attack,seed,run,pdr,throughput_kbps,mean_delay_ms,total_tx,total_rx,"
               "malicious_drops,energy_used_j,isolations,blocked_frames\n";
    summary << g_cfg.attack << ',' << g_cfg.seed << ',' << g_cfg.run << ','
            << (totalTx ? static_cast<double>(totalRx) / totalTx : 0.0) << ','
            << totalThroughput << ','
            << (totalRx ? delayWeighted / totalRx : 0.0) << ',' << totalTx << ','
            << totalRx << ',' << totalMalDrop << ',' << energyUsed << ','
            << IsolationRegistry::Get().IsolationCount() << ','
            << IsolationRegistry::Get().BlockedFrames() << '\n';
    summary.close();

    g_beaconRx.close();
    g_behaviour.close();

    std::cout << "[" << tag << "] PDR="
              << (totalTx ? static_cast<double>(totalRx) / totalTx : 0.0)
              << "  throughput=" << totalThroughput << " kbps"
              << "  malicious_drops=" << totalMalDrop << std::endl;

    Simulator::Destroy();
    return 0;
}
