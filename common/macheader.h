
//
// (c) 2006-2010 devolo AG, Aachen (Germany)
//

#ifndef _DLAN_MACHEADER_H_
#define _DLAN_MACHEADER_H_

#include <string.h>
#include "platform.h"
#include "packet.h"
#include "macaddress.h"

__packing_begin__


struct __packed__ CMACHeader
{
  unsigned char cDstAddr[CMACAddress::size];
  unsigned char cSrcAddr[CMACAddress::size];
  uint16_t uEtherType;

  CMACHeader() {}
  CMACHeader(const CMACAddress& dst, const CMACAddress& src, uint16_t etherType)
  {
    memcpy(cDstAddr, dst, CMACAddress::size);
    memcpy(cSrcAddr, src, CMACAddress::size);
    uEtherType = htons(etherType);
  }

  static bool IsValid(const IPacket& packet, uint16_t expectedEtherType)
  {
    return
      (packet.Size() >= sizeof(CMACHeader)) &&
      (((CMACHeader*)packet.Data())->uEtherType == htons(expectedEtherType));
  }
  
  static bool IsValid(const IPacket& packet, const CMACAddress& expectedDestAddr, uint16_t expectedEtherType)
  {
    return
      (packet.Size() >= sizeof(CMACHeader)) &&
      (CMACAddress(((CMACHeader*)packet.Data())->cDstAddr) == expectedDestAddr) &&
      (((CMACHeader*)packet.Data())->uEtherType == htons(expectedEtherType));
  }
};


__packing_end__

#endif // _DLAN_MACHEADER_H_
