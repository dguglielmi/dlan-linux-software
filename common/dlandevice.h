
//
// (c) 2006-2010 devolo AG, Aachen (Germany)
//

#ifndef _DLAN_DLANDEVICE_H_
#define _DLAN_DLANDEVICE_H_

#include <map>
#include <set>
#include <list>
#include <string>
#include "macaddress.h"

class CDlanDevice
{
public:

  enum teType { eHP1, eTurbo, eThunderbolt };

  CDlanDevice(const CMACAddress& addr, teType type, const std::string& ver, 
    const std::string& mft, const std::string& user, const std::string& avln) :
    m_addr(addr), 
    m_eType(type), 
    m_strVersion(ver), 
    m_strMftString(mft),
    m_strUserString(user),
    m_strAvlnString(avln) {}

  CDlanDevice(const CDlanDevice& o) :
    m_addr(o.m_addr), 
    m_eType(o.m_eType), 
    m_strVersion(o.m_strVersion), 
    m_strMftString(o.m_strMftString),
    m_strUserString(o.m_strUserString),
    m_strAvlnString(o.m_strAvlnString) {}

  CDlanDevice& operator=(const CDlanDevice& rhs)
  { 
    m_addr = rhs.m_addr; 
    m_eType = rhs.m_eType; 
    m_strVersion = rhs.m_strVersion; 
    m_strMftString = rhs.m_strMftString; 
    m_strUserString = rhs.m_strUserString; 
    m_strAvlnString = rhs.m_strAvlnString;
    return *this; 
  }

  bool operator==(const CDlanDevice& rhs) const 
  { 
    return
      (m_addr == rhs.m_addr) && 
      (m_eType == rhs.m_eType) &&
      (m_strVersion == rhs.m_strVersion) &&
      (m_strMftString == rhs.m_strMftString) && 
      (m_strUserString == rhs.m_strUserString) &&
      (m_strAvlnString == rhs.m_strAvlnString);
  }

  bool operator!=(const CDlanDevice& rhs) const { return !operator==(rhs); }

  const CMACAddress& GetAddress() const { return m_addr; }
  teType GetType() const { return m_eType; }
  const std::string& GetVersion() const { return m_strVersion; }
  const std::string& GetManufacturingString() const { return m_strMftString; }
  const std::string& GetUserDeviceName() const { return m_strUserString; }
  const std::string& GetUserNetworkName() const { return m_strAvlnString; }

private:

  CMACAddress m_addr;
  teType m_eType;
  std::string m_strVersion, m_strMftString, m_strUserString, m_strAvlnString;
};


class CDlanDataRates
{
public:

  CDlanDataRates(double tx = 0.0, double rx = 0.0) : m_fTxRate(tx), m_fRxRate(rx) {}
  CDlanDataRates(const CDlanDataRates& o) : m_fTxRate(o.m_fTxRate), m_fRxRate(o.m_fRxRate) {}
  
  CDlanDataRates& operator=(const CDlanDataRates& rhs)
  {
    m_fTxRate = rhs.m_fTxRate; 
    m_fRxRate = rhs.m_fRxRate;
    return *this;
  }

  bool operator==(const CDlanDataRates& rhs) const 
  { 
    return  
      (m_fTxRate == rhs.m_fTxRate) && 
      (m_fRxRate == rhs.m_fRxRate); 
  }

  bool operator!=(const CDlanDataRates& rhs) const { return !operator==(rhs); }

  double GetTxRate() const { return m_fTxRate; }
  double GetRxRate() const { return m_fRxRate; }

private:

  double m_fTxRate;
  double m_fRxRate;
};


typedef std::map<CMACAddress, CDlanDataRates> CDlanDataRateMap;



class CDlanRemoteDevice : public CDlanDevice, public CDlanDataRates
{
public:

  CDlanRemoteDevice(const CMACAddress& addr, teType type, const std::string& ver, 
    const std::string& mft, const std::string& user, const std::string& avln, double tx, double rx,
    const CDlanDataRateMap& remoteDataRates = CDlanDataRateMap(),
    const std::set<CMACAddress>& bridgedAddresses = std::set<CMACAddress>()) :
    CDlanDevice(addr, type, ver, mft, user, avln), 
    CDlanDataRates(tx, rx),
    m_remoteDataRates(remoteDataRates),
    m_bridgedAddresses(bridgedAddresses) {}

  CDlanRemoteDevice(const CDlanRemoteDevice& o) :
    CDlanDevice(o), 
    CDlanDataRates(o),
    m_remoteDataRates(o.m_remoteDataRates),
    m_bridgedAddresses(o.m_bridgedAddresses) {}

  CDlanRemoteDevice& operator=(const CDlanRemoteDevice& rhs) 
  { 
    CDlanDevice::operator=(rhs); 
    CDlanDataRates::operator=(rhs);
    m_remoteDataRates = rhs.m_remoteDataRates;
    m_bridgedAddresses = rhs.m_bridgedAddresses;
    return *this;
  }

  bool operator==(const CDlanRemoteDevice& rhs) const 
  {
    return 
      CDlanDevice::operator==(rhs) && 
      CDlanDataRates::operator==(rhs) && 
      (m_remoteDataRates == rhs.m_remoteDataRates) &&
      (m_bridgedAddresses == rhs.m_bridgedAddresses);
  }

  bool operator!=(const CDlanRemoteDevice& rhs) const { return !operator==(rhs); }

  const CDlanDataRateMap& GetRemoteRates() const { return m_remoteDataRates; }
  const std::set<CMACAddress>& GetBridgedAddresses() const { return m_bridgedAddresses; }

private:

  CDlanDataRateMap m_remoteDataRates;
  std::set<CMACAddress> m_bridgedAddresses;
};


typedef std::list<CDlanRemoteDevice> CDlanRemoteDeviceList;


class CDlanLocalDevice : public CDlanDevice
{
public:

  CDlanLocalDevice(const CMACAddress& nic, const CMACAddress& addr, teType type, const std::string& ver, 
    const std::string& mft, const std::string& user, const std::string& avln, 
    const CMACAddress& cco, const CDlanRemoteDeviceList& remotes = CDlanRemoteDeviceList()) :
    CDlanDevice(addr, type, ver, mft, user, avln),
    m_addrNIC(nic),
    m_addrCCo(cco),
    m_remoteDeviceList(remotes) {}

  CDlanLocalDevice(
    const CDlanLocalDevice& o) :
    CDlanDevice(o),
    m_addrNIC(o.m_addrNIC),
    m_addrCCo(o.m_addrCCo),
    m_remoteDeviceList(o.m_remoteDeviceList) {}

  CDlanLocalDevice& operator=(const CDlanLocalDevice& rhs) 
  { 
    CDlanDevice::operator=(rhs); 
    m_addrNIC = rhs.m_addrNIC; 
    m_addrCCo = rhs.m_addrCCo; 
    m_remoteDeviceList = rhs.m_remoteDeviceList; 
    return *this; 
  }

  bool operator==(const CDlanLocalDevice& rhs) const 
  { 
    return 
      CDlanDevice::operator==(rhs) && 
      (m_addrNIC == rhs.m_addrNIC) && 
      (m_addrCCo == rhs.m_addrCCo) && 
      (m_remoteDeviceList == rhs.m_remoteDeviceList);
  }

  bool operator!=(const CDlanLocalDevice& rhs) const { return !operator==(rhs); }

  bool UpdateRemoteDevice(const CDlanRemoteDevice& remoteDevice);
  bool RemoveRemoteDevice(const CMACAddress& remoteDeviceAddr);

  const CMACAddress& GetNICAddress() const { return m_addrNIC; }
  const CMACAddress& GetCCoAddress() const { return m_addrCCo; }
  const CDlanRemoteDeviceList& GetRemoteDevices() const { return m_remoteDeviceList; }

private:

  CMACAddress m_addrNIC, m_addrCCo;
  CDlanRemoteDeviceList m_remoteDeviceList;
};


typedef std::list<CDlanLocalDevice> CDlanLocalDeviceList;


#endif
