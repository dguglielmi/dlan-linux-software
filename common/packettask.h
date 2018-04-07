
//
// (c) 2007-2009 devolo AG, Aachen (Germany)
//

#ifndef _DLAN_PACKETTASK_H_
#define _DLAN_PACKETTASK_H_

#include "packetinterface.h"

class IPacketTask
{
public:

  virtual IPacketReceiver& GetReceiver() = 0;
  virtual unsigned long Drumbeat() = 0;
  virtual bool Complete() = 0;
  virtual bool Successful() = 0;
  virtual ~IPacketTask() {};
};

class CPacketTaskRunner
{
public:

  CPacketTaskRunner(IPacketInterface& i, IPacketTask& t) : ifc(i), task(t) {}
  
  bool Run()
  {
    while(!task.Complete())
    {
      unsigned long ulWait = task.Drumbeat();
      ifc.ReceivePackets(task.GetReceiver(), ulWait);
    }
    return task.Successful();
  }
  
  template<class TMSecCounterFunc> bool Run(unsigned long ulTimeout, TMSecCounterFunc fncGetMsCount)
  {
    unsigned long ulNow, ulStart = fncGetMsCount();
    while(!task.Complete() && (((ulNow = fncGetMsCount()) - ulStart) < ulTimeout))
    {
      unsigned long ulWait = task.Drumbeat();
      ifc.ReceivePackets(task.GetReceiver(), std::min<unsigned long>(ulWait, ulTimeout - (ulNow - ulStart)));
    }
    return task.Successful();
  }
  
private:
  
  IPacketInterface& ifc;
  IPacketTask& task;
};


#endif // _DLAN_PACKETTASK_H_
