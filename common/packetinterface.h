
//
// (c) 2006-2009 devolo AG, Aachen (Germany)
//

#ifndef _DLAN_PACKETINTERFACE_H_
#define _DLAN_PACKETINTERFACE_H_

#include <string>
#include <set>
#include "macaddress.h"
#include "packet.h"

class IPacketReceiver
{
public:
  virtual bool PacketIndication(const CMACAddress& adapter, const IPacket& packet) = 0;
};

class IPacketInterface
{
public:
  virtual const std::set<CMACAddress>& GetAdapters() = 0;
  virtual bool RefreshAdapters() = 0;
  virtual bool SendPacket(const CMACAddress& adapter, const IPacket& packet) = 0;
  virtual bool ReceivePackets(IPacketReceiver& receiver, unsigned long ulTimeout) = 0;
  virtual void StopReceiving() = 0;
  virtual bool Release() = 0;
protected: 
  virtual ~IPacketInterface() {}
};

#endif // _DLAN_PACKETINTERFACE_H_
