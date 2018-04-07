
//
// (c) 2006-2009 devolo AG, Aachen (Germany)
//

#ifndef _DLAN_PACKET_H_
#define _DLAN_PACKET_H_

class IPacket
{
public:
  virtual const unsigned char* Data() const = 0;
  virtual size_t Size() const = 0;
};


#endif
