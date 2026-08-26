/*
 * mbtr-isolation.h — Steps 10 and 11: isolation and secure route recovery.
 *
 * DESIGN NOTE, because this is the part a reviewer will interrogate.
 *
 * Isolation is enforced at the traffic-control layer, not inside AODV. A
 * BlacklistQueueDisc sits as the root qdisc on every node and discards any
 * outgoing frame whose next-hop MAC address is blacklisted. This is the one
 * place in the NS-3 stack where the next hop is known and the packet can still
 * be stopped, which is exactly what next-hop exclusion needs.
 *
 * Three consequences follow, and all three are wanted:
 *
 *  1. Data traffic stops being relayed through the isolated node.
 *  2. Unicast AODV control traffic to it stops too, so it can no longer answer
 *     into a route. Control-plane isolation comes free, without forking AODV.
 *  3. The link appears to fail to AODV's own link-failure detection, which
 *     raises RERR and triggers rediscovery unprompted. Route recovery is
 *     therefore *AODV's native mechanism operating under an exclusion
 *     constraint*, not a bespoke recovery protocol. That is a weaker claim than
 *     "we designed a recovery algorithm", and it is the honest one. What Step 11
 *     contributes is the exclusion constraint and the measurement of what it
 *     costs, not a new routing protocol.
 *
 * What this does NOT do: it does not stop the isolated node's own broadcasts
 * from being *received*. A blacklisted node can still be heard. Full ingress
 * filtering would need a receive-side hook that NS-3 does not expose cleanly.
 * State this limitation in the paper rather than implying total silencing.
 *
 * VERDICTS ARE REPLAYED, NOT COMPUTED HERE. Isolation times come from a CSV
 * produced by the Python pipeline (Steps 8-9). Keeping detection out of the
 * simulator has two benefits: the C++ and Python trust models cannot silently
 * diverge, and recovery cost can be measured independently of detection
 * accuracy. It also makes the cost of a FALSE isolation directly measurable —
 * schedule an honest node and read off the damage.
 */

#ifndef MBTR_ISOLATION_H
#define MBTR_ISOLATION_H

#include "ns3/core-module.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/mac48-address.h"
#include "ns3/traffic-control-module.h"

#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <vector>

namespace ns3
{

// ---------------------------------------------------------------------------
// Global blacklist state. Soft state with expiry: a verdict can be revised, so
// isolation must be reversible (docs/03-architecture.md).
// ---------------------------------------------------------------------------

struct IsolationEvent
{
    double timeS;
    uint32_t observer;  // node applying the blacklist; UINT32_MAX = all nodes
    uint32_t target;
    bool isolate;       // true = isolate, false = release
};

class IsolationRegistry
{
  public:
    static IsolationRegistry& Get()
    {
        static IsolationRegistry inst;
        return inst;
    }

    void RegisterNodeMac(uint32_t nodeId, Mac48Address mac)
    {
        m_nodeMac[nodeId] = mac;
    }

    Mac48Address MacOf(uint32_t nodeId) const
    {
        auto it = m_nodeMac.find(nodeId);
        return it == m_nodeMac.end() ? Mac48Address() : it->second;
    }

    void Isolate(uint32_t observer, uint32_t target)
    {
        m_blocked[observer].insert(MacOf(target));
        m_isolationCount++;
    }

    void Release(uint32_t observer, uint32_t target)
    {
        m_blocked[observer].erase(MacOf(target));
    }

    bool IsBlocked(uint32_t observer, Mac48Address nextHop) const
    {
        auto it = m_blocked.find(observer);
        return it != m_blocked.end() && it->second.count(nextHop) > 0;
    }

    void NoteBlockedFrame()
    {
        m_blockedFrames++;
    }

    uint64_t BlockedFrames() const
    {
        return m_blockedFrames;
    }

    uint64_t IsolationCount() const
    {
        return m_isolationCount;
    }

  private:
    std::map<uint32_t, Mac48Address> m_nodeMac;
    std::map<uint32_t, std::set<Mac48Address>> m_blocked;
    uint64_t m_blockedFrames = 0;
    uint64_t m_isolationCount = 0;
};

// ---------------------------------------------------------------------------
// BlacklistQueueDisc — root qdisc enforcing next-hop exclusion.
// ---------------------------------------------------------------------------

class BlacklistQueueDisc : public QueueDisc
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("BlacklistQueueDisc")
                                .SetParent<QueueDisc>()
                                .SetGroupName("TrafficControl")
                                .AddConstructor<BlacklistQueueDisc>();
        return tid;
    }

    BlacklistQueueDisc()
        : QueueDisc(QueueDiscSizePolicy::SINGLE_INTERNAL_QUEUE)
    {
    }

    void SetNodeId(uint32_t id)
    {
        m_nodeId = id;
    }

  private:
    bool DoEnqueue(Ptr<QueueDiscItem> item) override
    {
        Address addr = item->GetAddress();
        if (Mac48Address::IsMatchingType(addr))
        {
            Mac48Address nextHop = Mac48Address::ConvertFrom(addr);
            if (IsolationRegistry::Get().IsBlocked(m_nodeId, nextHop))
            {
                // Silent discard. A blacklisted next hop must look like a dead
                // link, so AODV raises RERR and rediscovers a route on its own.
                IsolationRegistry::Get().NoteBlockedFrame();
                DropBeforeEnqueue(item, "BLACKLISTED_NEXT_HOP");
                return false;
            }
        }
        return GetInternalQueue(0)->Enqueue(item);
    }

    Ptr<QueueDiscItem> DoDequeue() override
    {
        return GetInternalQueue(0)->Dequeue();
    }

    Ptr<const QueueDiscItem> DoPeek() override
    {
        return GetInternalQueue(0)->Peek();
    }

    bool CheckConfig() override
    {
        if (GetNInternalQueues() == 0)
        {
            AddInternalQueue(
                CreateObjectWithAttributes<DropTailQueue<QueueDiscItem>>(
                    "MaxSize", QueueSizeValue(QueueSize("100p"))));
        }
        return GetNInternalQueues() == 1;
    }

    void InitializeParams() override
    {
    }

    uint32_t m_nodeId = 0;
};

NS_OBJECT_ENSURE_REGISTERED(BlacklistQueueDisc);

// ---------------------------------------------------------------------------
// Schedule loading
// ---------------------------------------------------------------------------

// CSV: time_s,observer,target,action
// observer = "all" applies the verdict network-wide, which models a fully
// propagated notification. Per-observer rows model partial propagation, and the
// difference between the two is a measurable cost of the notification step.
inline std::vector<IsolationEvent>
LoadIsolationSchedule(const std::string& path)
{
    std::vector<IsolationEvent> out;
    std::ifstream fh(path);
    if (!fh.is_open())
    {
        return out;
    }

    std::string line;
    std::getline(fh, line); // header
    while (std::getline(fh, line))
    {
        if (line.empty())
        {
            continue;
        }
        std::stringstream ss(line);
        std::string tS, obsS, tgtS, actS;
        std::getline(ss, tS, ',');
        std::getline(ss, obsS, ',');
        std::getline(ss, tgtS, ',');
        std::getline(ss, actS, ',');

        IsolationEvent e;
        e.timeS = std::stod(tS);
        e.observer = (obsS == "all") ? UINT32_MAX : static_cast<uint32_t>(std::stoul(obsS));
        e.target = static_cast<uint32_t>(std::stoul(tgtS));
        e.isolate = (actS.find("isolate") != std::string::npos);
        out.push_back(e);
    }
    return out;
}

inline void
ApplyIsolationEvent(IsolationEvent e, uint32_t nNodes)
{
    if (e.observer == UINT32_MAX)
    {
        for (uint32_t i = 0; i < nNodes; ++i)
        {
            if (i == e.target)
            {
                continue;
            }
            if (e.isolate)
            {
                IsolationRegistry::Get().Isolate(i, e.target);
            }
            else
            {
                IsolationRegistry::Get().Release(i, e.target);
            }
        }
    }
    else if (e.isolate)
    {
        IsolationRegistry::Get().Isolate(e.observer, e.target);
    }
    else
    {
        IsolationRegistry::Get().Release(e.observer, e.target);
    }
}

} // namespace ns3

#endif // MBTR_ISOLATION_H
