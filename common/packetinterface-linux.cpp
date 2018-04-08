
//
// (c) 2007-2009 devolo AG, Aachen (Germany)
//

#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> 
#include <string>
#include <set>
#include <map>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <cerrno>
#include <sys/time.h>
#include <ctime>
#include <cstring>

#include "macheader.h"
#include "packet.h"
#include "hpmmes.h"
#include "packetinterface-linux.h"

#define SOCKADDR_STAR(p) ((struct sockaddr *)(p))

class UnknownPacket : public IPacket
{
public:
  UnknownPacket(const size_t buflen, const unsigned char* buffer = NULL) {
    data = (unsigned char*) malloc((size_t)buflen);
    len = 0;
    if (data != NULL && buffer != NULL) {
      memcpy(data,buffer,(size_t)buflen);
      len = buflen;
    }
  }
  virtual ~UnknownPacket() { free(data); }

  virtual const unsigned char* Data() const { return data; }
  virtual size_t Size() const { return (size_t) len; }

  void SetSize(const size_t size) { len = size; }
private:
  unsigned char* data;
  size_t len;
};


CPacketInterfaceLinux::CPacketInterfaceLinux(const std::set<std::string> &setIfcNames)
{
  m_ifcFilter = setIfcNames;

  if(pipe(m_interruptPipe) != 0)
    perror("pipe");
    
  static struct sock_filter statBPFProgramm [] = 
  {
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),                                 
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, HomePlugMMEs::uEtherType, 2, 0),    
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,  HomePlugAvMMEs::uEtherType, 1, 0), 
    BPF_STMT(BPF_RET+BPF_K, 0),                                         
    BPF_STMT(BPF_RET+BPF_K, 0xFFFF)                                     
  };

  m_socketFilter.filter = statBPFProgramm;
  m_socketFilter.len = sizeof(statBPFProgramm) / sizeof(struct sock_filter);

  RefreshAdapters();
}

CPacketInterfaceLinux::~CPacketInterfaceLinux()
{
  closeAllSockets();
  close(m_interruptPipe[0]);
  close(m_interruptPipe[1]);
}

const std::set<CMACAddress>& CPacketInterfaceLinux::GetAdapters()
{
  return m_macs;
}

bool CPacketInterfaceLinux::RefreshAdapters()
{
  m_macs.clear();

  std::map<CMACAddress,Interface> newifcs;
  
  std::set<std::string> setIfNames;
  
  if(m_ifcFilter.empty())
    GetInterfaceNames(setIfNames);
  else
    setIfNames = m_ifcFilter;
  
  for(std::set<std::string>::iterator itIfName = setIfNames.begin(); 
    itIfName != setIfNames.end(); ++itIfName)
  {
    CMACAddress mac;
    if (GetCMACAddress(itIfName->c_str(), mac) && m_macs.find(mac) == m_macs.end())
    {
      int ifindex;
      if(InterfaceIsActive(itIfName->c_str(), !m_ifcFilter.empty()) && GetInterfaceIndex(itIfName->c_str(), ifindex))
      {
        m_macs.insert(mac);
        std::map<CMACAddress,Interface>::iterator itIfc;
        if(((itIfc = m_ifcs.find(mac)) != m_ifcs.end()) &&
          (itIfc->second.ifname == *itIfName) && 
          (itIfc->second.ifindex == ifindex))
        {
          newifcs[mac] = itIfc->second;
          m_ifcs.erase(itIfc);
        }
        else
        {
          Interface newIfc;
          newIfc.ifname = *itIfName;
          newIfc.ifindex = ifindex;
          newIfc.fdsocket = openNewSocket(itIfName->c_str(), ifindex);
          if(newIfc.fdsocket != -1)
            newifcs[mac] = newIfc;
        }
      }
    }
  }

  closeAllSockets();
  m_ifcs = newifcs;

  AttachFilter();

  return true;
}

void CPacketInterfaceLinux::closeAllSockets()
{
  std::map<CMACAddress,Interface>::iterator itIfc;
  for(itIfc = m_ifcs.begin(); itIfc != m_ifcs.end(); ++itIfc)
  {
    close(itIfc->second.fdsocket);
    itIfc->second.fdsocket = -1;
  }
}

bool CPacketInterfaceLinux::SendPacket(const CMACAddress& adapter, const IPacket& packet)
{
  bool bResult = false;

  std::map<CMACAddress,Interface>::const_iterator itIfc;
  if((itIfc = m_ifcs.find(adapter)) != m_ifcs.end())
  {
    struct sockaddr_ll destination = { 0 };
    destination.sll_family = AF_PACKET;
    destination.sll_protocol = ((CMACHeader*)packet.Data())->uEtherType;
    destination.sll_ifindex = itIfc->second.ifindex;
    destination.sll_halen = CMACAddress::size;
    memcpy(destination.sll_addr, ((CMACHeader*)packet.Data())->cDstAddr, CMACAddress::size);

    if(sendto(itIfc->second.fdsocket, (void*)packet.Data(), packet.Size(),
      0, SOCKADDR_STAR(&destination), sizeof(struct sockaddr_ll)) >= 0)
    {
      bResult = true;
    }
    else
    {
      perror("sendto");
    }
  }

  return bResult;
}

bool operator<(const struct timeval& lhs, const struct timeval& rhs)
{
  return (lhs.tv_sec < rhs.tv_sec) || ((lhs.tv_sec == rhs.tv_sec) && (lhs.tv_usec < rhs.tv_usec));
}

struct timeval operator-(const struct timeval& lhs, const struct timeval& rhs)
{
  struct timeval result;
  long underflow = (lhs.tv_usec < rhs.tv_usec) ? 1 : 0;
  result.tv_sec = lhs.tv_sec - (rhs.tv_sec + underflow);
  result.tv_usec = (underflow * 1000000) + lhs.tv_usec - rhs.tv_usec;
  return result; 
}

bool CPacketInterfaceLinux::ReceivePackets(IPacketReceiver& receiver, unsigned long ulTimeout)
{
  size_t buffersize = 3000;
  UnknownPacket packet(buffersize);

  bool infinite_timeout = (ulTimeout == (unsigned long)-1);
  struct timeval start, now, overall_timeout, select_timeout;

  if(!infinite_timeout)
  {
    overall_timeout.tv_sec = (long)(ulTimeout / 1000);
    overall_timeout.tv_usec = (long)(ulTimeout % 1000) * 1000;

    gettimeofday(&start, NULL);
    now = start;
  }
  bool stop_receiving = false;
  bool packet_indication = false;
  do
  {
    fd_set recset;
    int nfds;
    buildfdset(recset, nfds);

    if(!infinite_timeout)
      select_timeout = overall_timeout - (now - start);

    if(select(nfds, &recset, NULL, NULL, infinite_timeout ? 0 : &select_timeout) > 0)
    {
      std::map<CMACAddress,Interface>::const_iterator itIfc;
      if((itIfc = nextifcfromfdset(recset)) != m_ifcs.end())
      {
        struct sockaddr_ll source = { 0 };
        socklen_t sourcelen = sizeof(source);
        size_t recvbytes = (size_t) recvfrom(itIfc->second.fdsocket,
          (void*)packet.Data(), buffersize, 0, SOCKADDR_STAR(&source), &sourcelen);
        packet.SetSize(recvbytes);

        packet_indication = receiver.PacketIndication(itIfc->first, packet);
      }
      else if(FD_ISSET(m_interruptPipe[0], &recset))
      {
        char buffer[10];
        read(m_interruptPipe[0], buffer, sizeof(buffer));
        stop_receiving = true;
      }
    }

    if(!infinite_timeout)
      gettimeofday(&now, NULL);
  }
  while(!stop_receiving && !packet_indication && (infinite_timeout || ((now - start) < overall_timeout))); 

  return packet_indication;
}

void CPacketInterfaceLinux::StopReceiving()
{
  write(m_interruptPipe[1],"s",1);
}

bool CPacketInterfaceLinux::Release()
{
  delete this;
  return true;
}

#define isspace(c) ((((c) == ' ') || (((unsigned char)((c) - 9)) <= (13 - 9))))
bool CPacketInterfaceLinux::GetInterfaceNames(std::set<std::string>& setIfNames) const
{
    bool bResult = false;
    std::ifstream devfile("/proc/net/dev");
    if (devfile.is_open())
    {
        std::string buf;
        getline(devfile, buf);
        getline(devfile, buf);
        for (;;)
        {
            getline(devfile, buf);
            if (devfile.good() == false) break;
            std::string::size_type nameStart = 0, nameEnd;
            while (nameStart < buf.size() && isspace(buf[nameStart])) nameStart++;
            nameEnd = nameStart;
            while (nameEnd < buf.size() && buf[nameEnd] && buf[nameEnd] != ':' && !isspace(buf[nameEnd])) nameEnd++;
            if (nameStart != nameEnd && nameEnd < buf.size() && buf[nameEnd] == ':' && (nameEnd - nameStart) < IFNAMSIZ)
            {
                setIfNames.insert(buf.substr(nameStart, nameEnd-nameStart));
            }
        }
        devfile.close();
        bResult = true;
    }
    return bResult;
}

bool CPacketInterfaceLinux::InterfaceIsActive(const char* name, bool forceActivation) const
{
  bool bResult = false;

  if(name)
  {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock >= 0)
    {
      struct ifreq ifreq;
      memset(&ifreq, 0,sizeof(struct ifreq));
      strncpy(ifreq.ifr_name, name, sizeof(ifreq.ifr_name) - 1);
      if (ioctl(sock, SIOCGIFFLAGS, &ifreq) == 0)
      {
        if ((ifreq.ifr_flags & IFF_LOOPBACK) != IFF_LOOPBACK && (ifreq.ifr_flags & IFF_NOARP) != IFF_NOARP)
        {
          if ((ifreq.ifr_flags & IFF_UP) == IFF_UP)
          {
            if ((ifreq.ifr_flags & IFF_RUNNING) == IFF_RUNNING) bResult = true;
          }
        }
      }
      else perror("ioctl(SIOCGIFFLAGS)");
      close(sock);
    }
    else perror("socket");
  }
  return bResult;
}

bool CPacketInterfaceLinux::GetCMACAddress(const char* name, CMACAddress& mac) const
{
  bool bResult = false;
  
  if(name)
  {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock >= 0)
    {
      struct ifreq ifreq;
      memset(&ifreq, 0, sizeof(struct ifreq));
      strncpy(ifreq.ifr_name, name, IF_NAMESIZE);
      if(ioctl(sock, SIOCGIFHWADDR, &ifreq) >= 0)
      {
        mac = CMACAddress(ifreq.ifr_ifru.ifru_hwaddr.sa_data);
        bResult = true;
      }
      else
      {
        perror("ioctl(SIOGIFHWADDR)");
      }
      close(sock);
    }
    else
    {
      perror("socket");
    }
  }

  return bResult;
}

bool CPacketInterfaceLinux::GetInterfaceIndex(const char* name, int& ifindex) const
{
  bool bResult = false;
  
  if(name)
  {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock >= 0)
    {
      struct ifreq ifreq;
      memset(&ifreq, 0, sizeof(struct ifreq));
      strncpy(ifreq.ifr_name, name, IF_NAMESIZE);
      if(ioctl(sock, SIOCGIFINDEX, &ifreq) == 0)
      {
        ifindex = ifreq.ifr_ifindex;
        bResult = true;
      }
      else
      {
        perror("ioctl(SIOCGIFINDEX)");
      }
      close(sock);
    }
    else
    {
      perror("socket");
    }
  }

  return bResult;
}


int CPacketInterfaceLinux::openNewSocket(const char *unused_ifname, int ifindex) const
{
  int sock = socket(PF_PACKET, (int)SOCK_RAW, htons(ETH_P_ALL));
  if(sock >= 0)
  {
    struct sockaddr_ll saddr = { 0 };
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = ifindex;
    saddr.sll_halen = CMACAddress::size;
    memcpy(saddr.sll_addr, (unsigned char *) "\xff\xff\xff\xff\xff\xff" , 6);

    if(bind(sock, SOCKADDR_STAR(&saddr), sizeof(struct sockaddr_ll)) < 0)
    {
      close(sock);
      sock = -1;
      perror("bind");
    }
  }
  else
  {
    perror("socket(PF_PACKET)");
  }
  
  return sock;
}

void CPacketInterfaceLinux::AttachFilter()
{
  if(m_socketFilter.len > 0)
  {
    std::map<CMACAddress,Interface>::const_iterator itIfc;
    for(itIfc = m_ifcs.begin(); itIfc != m_ifcs.end(); ++itIfc)
    {
      if(setsockopt(itIfc->second.fdsocket, SOL_SOCKET, SO_ATTACH_FILTER, &m_socketFilter, sizeof(m_socketFilter)) < 0)
        perror("setsockopt(SO_ATTACH_FILTER)");
    }
  }
}

void CPacketInterfaceLinux::buildfdset(fd_set& fdset, int& nfds) const
{
  FD_ZERO(&fdset);
  nfds = 0;
  
  std::map<CMACAddress,Interface>::const_iterator itIfc;
  for(itIfc = m_ifcs.begin(); itIfc != m_ifcs.end(); ++itIfc)
  {
    FD_SET(itIfc->second.fdsocket, &fdset);
    nfds = std::max<int>(itIfc->second.fdsocket, nfds);
  }

  FD_SET(m_interruptPipe[0], &fdset);
  nfds = std::max<int>(m_interruptPipe[0], nfds);

  nfds++;
}

std::map<CMACAddress,CPacketInterfaceLinux::Interface>::const_iterator CPacketInterfaceLinux::nextifcfromfdset(fd_set & fdset) const
{
  std::map<CMACAddress,Interface>::const_iterator itIfc;
  for(itIfc = m_ifcs.begin(); itIfc != m_ifcs.end(); ++itIfc)
  {
    if(FD_ISSET(itIfc->second.fdsocket, &fdset))
    {
      FD_CLR(itIfc->second.fdsocket, &fdset);
      break;
    }
  }

  return itIfc;
}
