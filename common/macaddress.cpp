
//
// (c) 2006-2010 devolo AG, Aachen (Germany)
//

#include <iomanip>
#include <sstream>
#include <sstream>
#include <stdlib.h>
#include "macaddress.h"

static const char* pHexDigits = "0123456789ABCDEFabcdef"; 

std::string CMACAddress::ToString(const std::string& strSeparator) const
{
  std::ostringstream ostr;

  ostr 
    << pHexDigits[(m_addr[0] & 0xF0) >> 4] << pHexDigits[m_addr[0] & 0x0F] << strSeparator
    << pHexDigits[(m_addr[1] & 0xF0) >> 4] << pHexDigits[m_addr[1] & 0x0F] << strSeparator
    << pHexDigits[(m_addr[2] & 0xF0) >> 4] << pHexDigits[m_addr[2] & 0x0F] << strSeparator
    << pHexDigits[(m_addr[3] & 0xF0) >> 4] << pHexDigits[m_addr[3] & 0x0F] << strSeparator
    << pHexDigits[(m_addr[4] & 0xF0) >> 4] << pHexDigits[m_addr[4] & 0x0F] << strSeparator
    << pHexDigits[(m_addr[5] & 0xF0) >> 4] << pHexDigits[m_addr[5] & 0x0F];

  return ostr.str();
}

bool CMACAddress::FromString(const std::string& strMACAddr)
{
  // Loop over six bytes
  size_t iByte = 0;
  unsigned char cMacAddrBuff[size] = {0};
  const char* pString = strMACAddr.c_str();
  for( ; iByte < size; iByte++)
  {
    // Skip separator chars
    if((iByte > 0) && ((pString[0] == ':') || (pString[0] == '-')))
      pString++;

    // Check for valid hex representation of a byte
    if(strspn(pString, pHexDigits) >= 2)
    {
      // Convert into byte
      char cTmp[3] = { pString[0], pString[1], 0 };
      cMacAddrBuff[iByte] = (unsigned char)strtoul(cTmp, 0, 16);
      pString += 2;
    }
    else
    {
      break;
    }
  }

  // Check if six bytes have been converted and nothing remains
  if((iByte == size) && (pString[0] == 0))
  {
    memcpy(m_addr, cMacAddrBuff, size);
    return true;
  }
  else
  {
    return false;
  }
}
