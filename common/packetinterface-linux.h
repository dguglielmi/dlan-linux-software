
//
// (c) 2007-2009 devolo AG, Aachen (Germany)
//

#ifndef _DLAN_PACKETINTERFACE_LINUX_H_
#define _DLAN_PACKETINTERFACE_LINUX_H_

#include <map>
#include <linux/types.h>
#include <linux/filter.h>

#include "packetinterface.h"

class CPacketInterfaceLinux : public IPacketInterface
{
public:

  CPacketInterfaceLinux(const std::set<std::string> &setIfcNames = std::set<std::string>());
  virtual ~CPacketInterfaceLinux();

  virtual const std::set<CMACAddress>& GetAdapters();
  virtual bool RefreshAdapters();
  virtual bool SendPacket(const CMACAddress& adapter, const IPacket& packet);
  virtual bool ReceivePackets(IPacketReceiver& receiver, unsigned long ulTimeout);
  virtual void StopReceiving();
  virtual bool Release();

private:

  std::set<std::string> m_ifcFilter;
  std::set<CMACAddress> m_macs;
  struct Interface { std::string ifname; int ifindex, fdsocket; };
  std::map<CMACAddress,Interface> m_ifcs;
  int m_interruptPipe[2];
  struct sock_fprog m_socketFilter;

  bool GetInterfaceNames(std::set<std::string>& setIfNames) const;
  bool InterfaceIsActive(const char* name, bool forceActivation) const;
  bool GetCMACAddress(const char* name, CMACAddress& mac) const;
  bool GetInterfaceIndex(const char* name, int& ifindex) const;
  int openNewSocket(const char* ifname, int ifindex) const;
  void closeAllSockets();
  void AttachFilter();
  void buildfdset(fd_set& recset, int& nfds) const;
  std::map<CMACAddress,Interface>::const_iterator nextifcfromfdset(fd_set & recset) const;
};

#endif // _DLAN_PACKET_LINUX_H_
