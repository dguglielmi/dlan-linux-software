
//
// (c) 2006-2009 devolo AG, Aachen (Germany)
//

#ifndef _DLAN_MACADDRESS_H_
#define _DLAN_MACADDRESS_H_

#include <string>
#include <cstring>

class CMACAddress
{
public:

  enum { size = 6 };

  CMACAddress(
    unsigned char c0 = 0, unsigned char c1 = 0, unsigned char c2 = 0, 
    unsigned char c3 = 0, unsigned char c4 = 0, unsigned char c5 = 0)
  {
    m_addr[0] = c0; m_addr[1] = c1;
    m_addr[2] = c2; m_addr[3] = c3;
    m_addr[4] = c4; m_addr[5] = c5;
  }

  CMACAddress(const CMACAddress& addr) { memcpy(m_addr, addr.m_addr, size); }
  CMACAddress(const unsigned char szMACAddr[size]) { memcpy(m_addr, szMACAddr, size); }
  CMACAddress(const char szMACAddr[size]) { memcpy(m_addr, szMACAddr, size); }

  ~CMACAddress() {}

  int Compare(const CMACAddress& addr, size_t count = size) const { return memcmp(m_addr, addr.m_addr, std::min<size_t>(count, size)); }
  bool CheckOUI(const CMACAddress& addr) const { return (Compare(addr, 3) == 0); }

  std::string ToString(const std::string& strSeparator = ":") const;
  bool FromString(const std::string& strMACAddr);
  
  static CMACAddress Broadcast() { return CMACAddress(0xff, 0xff, 0xff, 0xff, 0xff, 0xff); }
  static CMACAddress Null() { return CMACAddress(0x00, 0x00, 0x00, 0x00, 0x00, 0x00); }

  operator bool() const { return (Compare(Null()) != 0); }
  operator const unsigned char*() const { return m_addr; }
  operator const char*() const { return (const char*)m_addr; }
  operator const void*() const { return (const void*)m_addr; }

  CMACAddress& operator=(const CMACAddress& addr) { if(&addr != this) memcpy(m_addr, addr.m_addr, size); return *this; }
  CMACAddress& operator&=(const CMACAddress& addr) { for(size_t i = 0; i < size; i++) m_addr[i] &= addr.m_addr[i]; return *this; }
  CMACAddress& operator|=(const CMACAddress& addr) { for(size_t i = 0; i < size; i++) m_addr[i] |= addr.m_addr[i]; return *this; }

  CMACAddress operator~() const { CMACAddress r; for(size_t i = 0; i < size; i++) r.m_addr[i] = ~m_addr[i]; return r; }

private:

  unsigned char m_addr[size];
};

inline CMACAddress operator&(CMACAddress lhs, const CMACAddress& rhs) { lhs &= rhs; return lhs; }
inline CMACAddress operator|(CMACAddress lhs, const CMACAddress& rhs) { lhs |= rhs; return lhs; }
inline bool operator==(const CMACAddress& lhs, const CMACAddress& rhs) { return (lhs.Compare(rhs) == 0); }
inline bool operator!=(const CMACAddress& lhs, const CMACAddress& rhs) { return (lhs.Compare(rhs) != 0); }
inline bool operator<(const CMACAddress& lhs, const CMACAddress& rhs) { return (lhs.Compare(rhs) < 0); }
inline bool operator>(const CMACAddress& lhs, const CMACAddress& rhs) { return (lhs.Compare(rhs) > 0); }
inline bool operator<=(const CMACAddress& lhs, const CMACAddress& rhs) { return (lhs.Compare(rhs) <= 0); }
inline bool operator>=(const CMACAddress& lhs, const CMACAddress& rhs) { return (lhs.Compare(rhs) >= 0); }

#endif //_DLAN_MACADDRESS_H_
