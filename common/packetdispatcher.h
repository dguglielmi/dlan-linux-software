
//
// (c) 2006-2009 devolo AG, Aachen (Germany)
//

#ifndef _DLAN_PACKETDISPATCHER_H_
#define _DLAN_PACKETDISPATCHER_H_

#include <list>
#include "packetinterface.h"

class IPacketDispatcher
{
public:
  virtual bool Dispatch(const CMACAddress& adapter, const IPacket& packet) = 0;
};

class IPacketWaiter
{
public:
  virtual bool WaitSatisfied() const = 0;
};

class CPacketReceiverAndDispatcher : public IPacketReceiver
{
public:
  void AddDispatcher(IPacketDispatcher& dispatcher) { listDispatchers.push_back(&dispatcher); }
  void AddWaiter(IPacketWaiter& waiter) { listWaiters.push_back(&waiter); }

  virtual bool PacketIndication(const CMACAddress& adapter, const IPacket& packet)
  {
    std::list<IPacketDispatcher*>::iterator itDispatcher = listDispatchers.begin();
    while((itDispatcher != listDispatchers.end()) && ((*itDispatcher)->Dispatch(adapter, packet) == false))
      ++itDispatcher;

    bool bResult = false;
    std::list<IPacketWaiter*>::iterator itWaiter = listWaiters.begin();
    while((itWaiter != listWaiters.end()) && ((bResult = (*itWaiter)->WaitSatisfied()) == false))
      ++itWaiter;

    return bResult;
  }

  virtual ~CPacketReceiverAndDispatcher() {}

private:

  std::list<IPacketDispatcher*> listDispatchers;
  std::list<IPacketWaiter*> listWaiters;
};


#endif
