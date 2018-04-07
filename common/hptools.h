
//
// (c) 2006-2010 devolo AG, Aachen (Germany)
//

#ifndef _DLAN_HPTOOLS_H_
#define _DLAN_HPTOOLS_H_

#include <string>

namespace HomePlugTools
{
  void KeyFromPassword(const std::string& strPassword, unsigned char cKEY[8]);
}

namespace HomePlugAvTools
{
  void NetworkKeyFromPassword(const std::string& strPassword, unsigned char cKEY[16]);
  void DeviceAccessKeyFromSecurityID(const std::string& strSecurityID, unsigned char cDAK[16]);
  uint32_t Checksum(const uint32_t* pData, size_t iWords);
}

#endif // _DLAN_HPTOOLS_H_
