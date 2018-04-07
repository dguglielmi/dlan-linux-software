
#ifndef _DLAN_PLATFORM_H_
#define _DLAN_PLATFORM_H_

#include <cstdio>
#include <cstdarg>

#define __packing_begin__
#define __packing_end__
#define __packed__         __attribute__((packed))

#include <arpa/inet.h>

#include <endian.h>
#if (BYTE_ORDER == BIG_ENDIAN)
#include <byteswap.h>
#define letohl(x) __bswap_32(x)
#define letohs(x) __bswap_16(x)
#define htolel(x) __bswap_32(x)
#define htoles(x) __bswap_16(x)
#else
#define letohl(x) (x)
#define letohs(x) (x)
#define htolel(x) (x)
#define htoles(x) (x)
#endif

#endif // _DLAN_PLATFORM_H_
