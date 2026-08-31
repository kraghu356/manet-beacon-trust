#include "ns3/aodv-module.h"
#include "ns3/aodvatk-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include <fstream>
#include <iomanip>
#include <sys/stat.h>
using namespace ns3;
namespace ns3 { namespace aodvatk { uint64_t GetBhDrops(); uint64_t GetBhSeen(); } }
struct Cfg {
  uint32_t nNodes = 50;
  double areaX = 700.0, areaY = 700.0;
  double simTime = 300.0;
  double minSpeed = 1.0, maxSpeed = 5.0, pause = 2.0;
  uint32_t nFlows = 10;
  double pktRate = 4.0;
  uint32_t pktSize = 512;
  std::string standard = "80211g";
  std::string dataMode = "ErpOfdmRate54Mbps";
  double txPowerDbm = 20.0;
  double plExp = 3.0, refLoss = 46.6777;
  bool enableHello = false;
  double routeTimeout = 10.0;
  uint32_t nMalicious = 0;
  double dropProb = 1.0;
  uint32_t seed = 1;
  std::string outDir = "out";
};
static Cfg g;
int main(int argc, char* argv[]) {
  CommandLine cmd(__FILE__);
  cmd.AddValue("nNodes", "nodes", g.nNodes);
  cmd.AddValue("areaX", "field width", g.areaX);
  cmd.AddValue("areaY", "field height", g.areaY);
  cmd.AddValue("simTime", "duration", g.simTime);
  cmd.AddValue("minSpeed", "min speed", g.minSpeed);
  cmd.AddValue("maxSpeed", "max speed", g.maxSpeed);
  cmd.AddValue("pause", "pause time", g.pause);
  cmd.AddValue("nFlows", "flows", g.nFlows);
  cmd.AddValue("pktRate", "pkt/s per flow", g.pktRate);
  cmd.AddValue("pktSize", "payload bytes", g.pktSize);
  cmd.AddValue("standard", "80211b|80211g", g.standard);
  cmd.AddValue("dataMode", "phy rate", g.dataMode);
  cmd.AddValue("txPower", "dBm", g.txPowerDbm);
  cmd.AddValue("plExp", "path loss exponent", g.plExp);
  cmd.AddValue("refLoss", "ref loss dB", g.refLoss);
  cmd.AddValue("hello", "aodv hello", g.enableHello);
  cmd.AddValue("routeTimeout", "active route timeout s", g.routeTimeout);
  cmd.AddValue("nMalicious", "number of black hole nodes", g.nMalicious);
  cmd.AddValue("dropProb", "drop probability for malicious nodes", g.dropProb);
  cmd.AddValue("seed", "rng seed", g.seed);
  cmd.AddValue("outDir", "output dir", g.outDir);
  cmd.Parse(argc, argv);
  RngSeedManager::SetSeed(g.seed);
  RngSeedManager::SetRun(1);
  mkdir(g.outDir.c_str(), 0755);
  NodeContainer nodes;
  nodes.Create(g.nNodes);
  WifiHelper wifi;
  if (g.standard == "80211b") wifi.SetStandard(WIFI_STANDARD_80211b);
  else wifi.SetStandard(WIFI_STANDARD_80211g);
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                               "DataMode", StringValue(g.dataMode),
                               "ControlMode", StringValue("ErpOfdmRate6Mbps"));
  YansWifiChannelHelper ch;
  ch.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  ch.AddPropagationLoss("ns3::LogDistancePropagationLossModel",
                        "Exponent", DoubleValue(g.plExp),
                        "ReferenceLoss", DoubleValue(g.refLoss));
  YansWifiPhyHelper phy;
  phy.SetChannel(ch.Create());
  phy.Set("TxPowerStart", DoubleValue(g.txPowerDbm));
  phy.Set("TxPowerEnd", DoubleValue(g.txPowerDbm));
  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");
  NetDeviceContainer devices = wifi.Install(phy, mac, nodes);
  std::string xs = "ns3::UniformRandomVariable[Min=0.0|Max=" + std::to_string(g.areaX) + "]";
  std::string ys = "ns3::UniformRandomVariable[Min=0.0|Max=" + std::to_string(g.areaY) + "]";
  Ptr<RandomRectanglePositionAllocator> pa =
      CreateObject<RandomRectanglePositionAllocator>();
  pa->SetAttribute("X", StringValue(xs));
  pa->SetAttribute("Y", StringValue(ys));
  MobilityHelper mob;
  mob.SetPositionAllocator(pa);
  mob.SetMobilityModel("ns3::RandomWaypointMobilityModel",
      "Speed", StringValue("ns3::UniformRandomVariable[Min=" +
                std::to_string(g.minSpeed) + "|Max=" + std::to_string(g.maxSpeed) + "]"),
      "Pause", StringValue("ns3::ConstantRandomVariable[Constant=" +
                std::to_string(g.pause) + "]"),
      "PositionAllocator", PointerValue(pa));
  mob.Install(nodes);
  AodvHelper aodv;
  aodv.Set("EnableHello", BooleanValue(g.enableHello));
  aodv.Set("ActiveRouteTimeout", TimeValue(Seconds(g.routeTimeout)));
  // Malicious nodes are the LAST nMalicious ids, so honest node indices are
  // stable across runs with different attacker counts.
  AodvAtkHelper atk;
  atk.Set("EnableHello", BooleanValue(g.enableHello));
  atk.Set("ActiveRouteTimeout", TimeValue(Seconds(g.routeTimeout)));
  atk.Set("EnableBlackHole", BooleanValue(true));
  atk.Set("DropProb", DoubleValue(g.dropProb));
  NodeContainer honest, malicious;
  for (uint32_t i = 0; i < g.nNodes; ++i) {
    if (i >= g.nNodes - g.nMalicious) malicious.Add(nodes.Get(i));
    else honest.Add(nodes.Get(i));
  }
  InternetStackHelper internet;
  internet.SetRoutingHelper(aodv);
  internet.Install(honest);
  if (g.nMalicious > 0) {
    InternetStackHelper atkStack;
    atkStack.SetRoutingHelper(atk);
    atkStack.Install(malicious);
  }
  Ipv4AddressHelper addr;
  addr.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer ifs = addr.Assign(devices);
  uint16_t port = 9;
  Ptr<UniformRandomVariable> rv = CreateObject<UniformRandomVariable>();
  uint32_t half = g.nNodes / 2;
  for (uint32_t f = 0; f < g.nFlows; ++f) {
    uint32_t src = f % half;
    uint32_t dst = half + (f % half);
    PacketSinkHelper sink("ns3::UdpSocketFactory",
        InetSocketAddress(Ipv4Address::GetAny(), port + f));
    ApplicationContainer sa = sink.Install(nodes.Get(dst));
    sa.Start(Seconds(0.0)); sa.Stop(Seconds(g.simTime));
    OnOffHelper on("ns3::UdpSocketFactory",
        InetSocketAddress(ifs.GetAddress(dst), port + f));
    on.SetConstantRate(DataRate((uint64_t)(g.pktRate * g.pktSize * 8)), g.pktSize);
    ApplicationContainer app = on.Install(nodes.Get(src));
    app.Start(Seconds(1.0 + rv->GetValue(0.0, 5.0)));
    app.Stop(Seconds(g.simTime));
  }
  FlowMonitorHelper fmh;
  Ptr<FlowMonitor> mon = fmh.InstallAll();
  Simulator::Stop(Seconds(g.simTime));
  Simulator::Run();
  mon->CheckForLostPackets();
  FlowMonitor::FlowStatsContainer st = mon->GetFlowStats();
  uint64_t tx = 0, rx = 0; double dsum = 0.0; uint64_t rxd = 0;
  uint64_t fwd = 0;
  for (auto& kv : st) {
    tx += kv.second.txPackets; rx += kv.second.rxPackets;
    dsum += kv.second.delaySum.GetSeconds(); rxd += kv.second.rxPackets;
    fwd += kv.second.timesForwarded;
  }
  double pdr = tx ? (double)rx / tx : 0.0;
  double delay = rxd ? (dsum / rxd) * 1000.0 : 0.0;
  double hops = rx ? (double)fwd / rx + 1.0 : 0.0;
  std::ofstream o(g.outDir + "/summary.csv");
  o << "nodes,areaX,areaY,sim_time,seed,standard,hello,route_timeout,"
       "n_flows,pkt_rate,tx,rx,pdr,delay_ms,mean_hops\n";
  o << g.nNodes << "," << g.areaX << "," << g.areaY << "," << g.simTime << ","
    << g.seed << "," << g.standard << "," << (g.enableHello?1:0) << ","
    << g.routeTimeout << "," << g.nFlows << "," << g.pktRate << ","
    << tx << "," << rx << "," << std::fixed << std::setprecision(6) << pdr
    << "," << delay << "," << hops << "\n";
  o.close();
  std::cout << "  bhSeen=" << aodvatk::GetBhSeen() << " bhDrops=" << aodvatk::GetBhDrops() << std::endl;
  std::cout << "[n=" << g.nNodes << " " << g.standard << " hello="
            << (g.enableHello?1:0) << "] PDR=" << std::fixed
            << std::setprecision(4) << pdr << "  delay=" << std::setprecision(1)
            << delay << "ms  hops=" << std::setprecision(2) << hops
            << "  tx=" << tx << " rx=" << rx << std::endl;
  Simulator::Destroy();
  return 0;
}
