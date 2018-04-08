
//
// (c) 2006-2010 devolo AG, Aachen (Germany)
//

#ifndef _DLAN_HPMMES_H_
#define _DLAN_HPMMES_H_

#include <algorithm>
#include <iterator>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include "platform.h"
#include "macheader.h"
#include "packet.h"
#include "packetdispatcher.h"
#include "hptools.h"

__packing_begin__

namespace
{
  inline void InitFromPacket(void* pDest, size_t iSize, const IPacket& pkt)
  {
    memset(pDest, 0, iSize); 
    memcpy(pDest, pkt.Data(), std::min<size_t>(pkt.Size(), iSize)); 
  }

  uint8_t letohx(uint8_t i) { return i; }
  uint16_t letohx(uint16_t i) { return letohs(i); }
}

namespace HomePlugMMEs
{
  static const uint16_t uEtherType = 0x887B;

  struct __packed__ MmeHdr
  {
    CMACHeader machdr;
    uint8_t cMmeCtrl;
    uint8_t cMmeHdr; 
    uint8_t cMmeLen; 

    MmeHdr() : machdr() {}
    MmeHdr(const CMACAddress& dst, const CMACAddress& src, uint8_t mmeType, uint8_t mmeLen) :
      machdr(dst, src, uEtherType), cMmeCtrl(1), cMmeHdr(mmeType), cMmeLen(mmeLen) {}

    static bool IsValid(const IPacket& pkt, uint8_t expectedMmeHdr, uint8_t expectedMmeLen)
    {
      MmeHdr* pHdr = (MmeHdr*)pkt.Data();
      return
        (pkt.Size() >= sizeof(MmeHdr)) &&
        (((pHdr)->cMmeCtrl & 0x7F) >= 1) &&
        ((pHdr)->cMmeHdr == expectedMmeHdr) &&
        ((pHdr)->cMmeLen <= (pkt.Size() - sizeof(MmeHdr)) &&
        ((pHdr)->cMmeLen >= expectedMmeLen));
    }
  };

  namespace SetNetworkEncKey
  {
    enum { eMmeReqHdr = 0x04, eMmeConfHdr = 0x06 };

    struct __packed__ ReqData
    {
      MmeHdr hdr;
      uint8_t cEncKeySelect;
      uint8_t cNetworkEncKey[8];
      ReqData(const CMACAddress& dst, const CMACAddress& src, uint8_t EKS) :
        hdr(dst, src, eMmeReqHdr, sizeof(ReqData) - sizeof(hdr)), cEncKeySelect(EKS) {}
    };

    class __packed__ CRequest : public IPacket
    {
      ReqData data;
    public:
      CRequest(const CMACAddress& dst, const CMACAddress& src, uint8_t EKS, const uint8_t NEK[8]) : 
        data(dst, src, EKS) { memcpy(data.cNetworkEncKey, NEK, sizeof(data.cNetworkEncKey)); }        
      CRequest(const CMACAddress& dst, const CMACAddress& src, uint8_t EKS, const std::string& strPassword) : 
        data(dst, src, EKS) { HomePlugTools::KeyFromPassword(strPassword, data.cNetworkEncKey); }
      virtual const uint8_t* Data() const { return (const uint8_t*)&data; }
      virtual size_t Size() const { return sizeof(data); }
    };

    class __packed__ CConfirm
    {
      MmeHdr hdr;
    public:
      static bool IsValid(const IPacket& pkt) { return MmeHdr::IsValid(pkt, eMmeConfHdr, 0); }
      CConfirm(const IPacket& pkt) { InitFromPacket(this, sizeof(*this), pkt); }
      CMACAddress GetAddress() const { return CMACAddress(hdr.machdr.cSrcAddr); }
    };
  }

  namespace ParamsAndStats
  {
    enum { eMmeReqHdr = 0x07, eMmeRespHdr = 0x08 };

    struct __packed__ RspData
    {
      MmeHdr hdr;
      uint16_t uTxAck;    
      uint16_t uTxNack;   
      uint16_t uTxFail;   
      uint16_t uTxCLoss;  
      uint16_t uTxColl;   
      uint16_t uTxCA3Lat; 
      uint16_t uTxCA2Lat; 
      uint16_t uTxCA1Lat; 
      uint16_t uTxCA0Lat; 
      uint32_t uRxBP40;    
    };

    class __packed__ CRequest : public IPacket
    {
      MmeHdr hdr;
    public:
      CRequest(const CMACAddress& dst, const CMACAddress& src) : hdr(dst, src, eMmeReqHdr, 0) {}
      virtual const uint8_t* Data() const { return (const uint8_t*)&hdr; }
      virtual size_t Size() const { return sizeof(hdr); }
    };

    class __packed__ CResponse
    {
      RspData data;
    public:
      static bool IsValid(const IPacket& pkt) { return MmeHdr::IsValid(pkt, eMmeRespHdr, sizeof(RspData) - sizeof(MmeHdr)); }
      CResponse(const IPacket& pkt) { InitFromPacket(&data, sizeof(data), pkt); }
      CMACAddress GetAddress() const { return CMACAddress(data.hdr.machdr.cSrcAddr); }
    };
  }

  namespace Int51NetStat
  {
    enum { eMmeHdr = 0x1A };
    enum { eRequest = 0x80, eInt5130a1 = 0, eInt51x1Usb = 1, eInt51x1Phy = 2, eInt51x1Dte = 3, eInt5130a2 = 4 };

    static const double dConstantM = ((588.0 - 38.0) / 481.0);
    static const double dConstantB = (14.0 - dConstantM * (519.0 / 42.0));

    struct __packed__ ReqData
    {
      MmeHdr hdr;
      uint8_t cNetwCtrl;
      uint8_t cRsvd[186];
      ReqData(const CMACAddress& dst, const CMACAddress& src) :
        hdr(dst, src, eMmeHdr, sizeof(ReqData) - sizeof(hdr)), cNetwCtrl(eRequest) { memset(cRsvd, 0, sizeof(cRsvd)); }
    };
    struct __packed__ DstData
    {
      uint8_t cAddr[6];   
      uint16_t uBytes40;  
      uint16_t uFails;    
      uint16_t uDrops;    
    };
    struct __packed__ RspData
    {
      MmeHdr hdr;
      uint8_t cNetwCtrl;
      uint16_t uBytes40Robo; 
      uint16_t uFailsRobo;   
      uint16_t uDropsRobo;   
      DstData aDest[15];
    };

    class __packed__ CRequest : public IPacket
    {
      ReqData data;
    public:
      CRequest(const CMACAddress& dst, const CMACAddress& src) : data(dst, src) {}
      virtual const uint8_t* Data() const { return (const uint8_t*)&data; }
      virtual size_t Size() const { return sizeof(data); }
    };
   
    class __packed__ Destination
    {
      DstData data;
      friend class std::list<Destination>;
    public:
      Destination(const DstData& d) : data(d) {}
      CMACAddress GetAddress() const { return (CMACAddress(data.cAddr) & ~CMACAddress(0x01)); }
      bool IsToneMapValid() const { return ((CMACAddress(data.cAddr) & CMACAddress(0x01)) == CMACAddress::Null()); }
      double GetTxRate() const { return (dConstantM * (((double)letohs(data.uBytes40)) / 42.0)) + dConstantB; }
    };

    class __packed__ CResponse
    {
      RspData data;
    public:
      static bool IsValid(const IPacket& pkt)
      {
        return 
          MmeHdr::IsValid(pkt, eMmeHdr, sizeof(RspData) - sizeof(MmeHdr)) &&
          ((((RspData*)pkt.Data())->cNetwCtrl & eRequest) == 0);
      }
      CResponse(const IPacket& pkt) { InitFromPacket(&data, sizeof(data), pkt); }
      CMACAddress GetAddress() const { return CMACAddress(data.hdr.machdr.cSrcAddr); }
      uint8_t GetChipID() const { return data.cNetwCtrl; }
      std::list<Destination> GetDestinations() const { return std::list<Destination>(data.aDest, data.aDest + 15); }
    };
  }

  static const uint8_t cCogencyOUI[3] = { 0x00, 0x04, 0x87 };
  enum { eTurboVendorSpecMmeHdr = 0x02 };

  struct __packed__ TurboVSHdr
  {
    MmeHdr mmehdr;
    uint8_t cOUI[3];
    uint8_t cMsgID;

    TurboVSHdr() : mmehdr() {}
    TurboVSHdr(const CMACAddress& dst, const CMACAddress& src, uint8_t msgID, uint8_t msgLen) :
      mmehdr(dst, src, eTurboVendorSpecMmeHdr, 4 + msgLen), cMsgID(msgID)
    {
      cOUI[0] = cCogencyOUI[0];
      cOUI[1] = cCogencyOUI[1];
      cOUI[2] = cCogencyOUI[2];
    }

    static bool IsValid(const IPacket& pkt, uint8_t expectedMsgID, uint8_t expectedMsgLen)
    {
      return
        MmeHdr::IsValid(pkt, eTurboVendorSpecMmeHdr, (sizeof(TurboVSHdr) - sizeof(MmeHdr)) + expectedMsgLen) && 
        (((TurboVSHdr*)pkt.Data())->cOUI[0] == cCogencyOUI[0]) &&
        (((TurboVSHdr*)pkt.Data())->cOUI[1] == cCogencyOUI[1]) &&
        (((TurboVSHdr*)pkt.Data())->cOUI[2] == cCogencyOUI[2]) &&
        (((TurboVSHdr*)pkt.Data())->cMsgID == (expectedMsgID | 0x80));
    }
  };

  namespace TurboDeviceDescription
  {
    enum { eMsgID = 0x10 };
    enum { eFlagIsRemote = 0x01, eFlagValidProtocolVersion = 0x02 };

    struct __packed__ RspData
    {
      TurboVSHdr hdr;
      uint8_t cFlags;
      uint8_t cProtocolVersion[4];
      uint8_t cMftAndProdName[2];
      enum { eMftAndProdNameVarSize = 63 };
      uint8_t cMftAndProdNameVar[eMftAndProdNameVarSize];
    };
    enum { eRspDataFixedSize = sizeof(RspData) - RspData::eMftAndProdNameVarSize };

    class __packed__ CRequest : public IPacket
    {
      TurboVSHdr hdr;
    public:
      CRequest(const CMACAddress& dst, const CMACAddress& src) : hdr(dst, src, eMsgID, 0) {}
      virtual const uint8_t* Data() const { return (const uint8_t*)&hdr; }
      virtual size_t Size() const { return sizeof(hdr.mmehdr) + hdr.mmehdr.cMmeLen; }
    };

    class __packed__ CResponse
    {
      RspData data;
    public:
      static bool IsValid(const IPacket& pkt) { return TurboVSHdr::IsValid(pkt, eMsgID, eRspDataFixedSize - sizeof(TurboVSHdr)); }
      CResponse(const IPacket& pkt) { InitFromPacket(&data, sizeof(data), pkt);  }
      CMACAddress GetAddress() const { return CMACAddress(data.hdr.mmehdr.machdr.cSrcAddr); }
      bool IsRemote() const { return (data.cFlags & eFlagIsRemote) == eFlagIsRemote; }
      std::string GetManufacturer() const
      {
        size_t len1 = std::min<size_t>((size_t)data.cMftAndProdName[0], RspData::eMftAndProdNameVarSize);
        return std::string((const char*)data.cMftAndProdName + 1, len1);
      }
      std::string GetProductName() const
      {
        size_t len1 = std::min<size_t>((size_t)data.cMftAndProdName[0], RspData::eMftAndProdNameVarSize);
        size_t len2 = std::min<size_t>((size_t)data.cMftAndProdName[len1 + 1], RspData::eMftAndProdNameVarSize - len1);
        return std::string((const char*)data.cMftAndProdName + len1 + 2, len2);
      }
    };
  }

  namespace TurboChannelCapacities
  {
    enum { eMsgID = 0x18 };
    enum { eDirectionFlagRxCaps = 0, eDirectionFlagTxCaps = 1 };

    static const double dMaxTrueRate = 6.0;
    static const double dMaxHp1Rate = ((519.0 * 8.0) / (40.0 * 8.4));
    static const double dMaxTurboRate = ((2812.0 * 8.0) / (40.0 * 8.4));

    inline double RateFromBPBlk(uint32_t ulBytesPer336usBlock)
    {
      double dCalculatedPhyRate = ((double)ulBytesPer336usBlock) * 8.0 / (40.0 * 8.4);
      if(dCalculatedPhyRate <= dMaxTrueRate)
        return dCalculatedPhyRate;
      else if((dCalculatedPhyRate > dMaxTrueRate) && (dCalculatedPhyRate <= dMaxHp1Rate))
        return (((dCalculatedPhyRate - dMaxTrueRate) / (dMaxHp1Rate - dMaxTrueRate)) * (14 - 6)) + 6;
      else
        return (((dCalculatedPhyRate - dMaxHp1Rate) / (dMaxTurboRate - dMaxHp1Rate)) * (85 - 14)) + 14;
    }

    struct __packed__ ReqData
    {
      TurboVSHdr hdr;
      uint8_t cDirectionFlag;
      ReqData(const CMACAddress& dst, const CMACAddress& src, uint8_t directionFlag) : 
        hdr(dst, src, eMsgID, sizeof(ReqData) - sizeof(hdr)), cDirectionFlag(directionFlag) {}
    };
    struct __packed__ TxcData
    {
      uint8_t cAddr[6];
      uint8_t cBytesPer336usBlock[2];
    };
    struct __packed__ RxcData : public TxcData
    {
      uint8_t cSignalPower[3];
      uint8_t cNoisePower[3];
    };
    struct __packed__ RspData
    {
      TurboVSHdr hdr;
      uint8_t cData[256];
    };
    
    class __packed__ TxCap
    {
      TxcData data;
      friend class std::list<TxCap>;
    public:
      TxCap(const TxcData& d) : data(d) {}
      CMACAddress GetAddress() const { return CMACAddress(data.cAddr); }
      double GetTxRate() const { return RateFromBPBlk((data.cBytesPer336usBlock[0] << 8) + data.cBytesPer336usBlock[1]); }
    };

    class __packed__ RxCap
    {
      RxcData data;
      friend class std::list<RxCap>;
    public:
      RxCap(const RxcData& d) : data(d) {}
      CMACAddress GetAddress() const { return CMACAddress(data.cAddr); }
      double GetRxRate() const { return RateFromBPBlk((data.cBytesPer336usBlock[0] << 8) + data.cBytesPer336usBlock[1]); }
    };

    class __packed__ CRequest : public IPacket
    {
      ReqData data;
    public:
      CRequest(const CMACAddress& dst, const CMACAddress& src, uint8_t directionFlag) : data(dst, src, directionFlag) {}
      virtual const uint8_t* Data() const { return (const uint8_t*)&data; }
      virtual size_t Size() const { return sizeof(data); }
    };

    class __packed__ CResponse
    {
      RspData data;
      size_t Cnt(size_t iSize) const { return (data.hdr.mmehdr.cMmeLen - (sizeof(data.hdr) - sizeof(data.hdr.mmehdr))) / iSize; }
    public:
      static bool IsValid(const IPacket& pkt) { return TurboVSHdr::IsValid(pkt, eMsgID, 0); }
      CResponse(const IPacket& pkt) { InitFromPacket(&data, sizeof(data), pkt); }
      CMACAddress GetAddress() const { return CMACAddress(data.hdr.mmehdr.machdr.cSrcAddr); }
      std::list<RxCap> GetRxCapacities() const { return std::list<RxCap>((RxcData*)data.cData, ((RxcData*)data.cData) + Cnt(sizeof(RxcData))); }
      std::list<TxCap> GetTxCapacities() const { return std::list<TxCap>((TxcData*)data.cData, ((TxcData*)data.cData) + Cnt(sizeof(TxcData))); }
    };
  }

  enum { eTurboMacHostMmeReqHdr = 0x12, eTurboMacHostMmeRespHdr = 0x13 };  

  struct __packed__ TurboMHHdr
  {
    MmeHdr mmehdr;
    uint8_t cMsgID;

    TurboMHHdr() : mmehdr() {}
    TurboMHHdr(const CMACAddress& dst, const CMACAddress& src, uint8_t msgID, uint8_t msgLen) :
      mmehdr(dst, src, eTurboMacHostMmeReqHdr, 1 + msgLen), cMsgID(msgID) {}

    static bool IsValid(const IPacket& pkt, uint8_t expectedMsgID, uint8_t expectedMsgLen)
    {
      return
        MmeHdr::IsValid(pkt, eTurboMacHostMmeRespHdr, (sizeof(TurboMHHdr) - sizeof(MmeHdr)) + expectedMsgLen) && 
        (((TurboMHHdr*)pkt.Data())->cMsgID == expectedMsgID);
    }
  };

  class CDispatcher : public IPacketDispatcher
  {
  protected:

    virtual void OnSetNetworkEncKeyConfirm(const CMACAddress&, const SetNetworkEncKey::CConfirm&) {}
    virtual void OnParamsAndStatsResponse(const CMACAddress&, const ParamsAndStats::CResponse&) {}
    virtual void OnInt51NetStatResponse(const CMACAddress&, const Int51NetStat::CResponse&) {}
    virtual void OnTurboDeviceDescriptionResponse(const CMACAddress&, const TurboDeviceDescription::CResponse&) {}
    virtual void OnTurboChannelCapacitiesResponse(const CMACAddress&, const TurboChannelCapacities::CResponse&) {}
    virtual void OnUnknownMme(const CMACAddress&, const IPacket&) {}

  public:

    virtual bool Dispatch(const CMACAddress& adapter, const IPacket& pkt)
    {
      if(CMACHeader::IsValid(pkt, uEtherType))
      {
        if(SetNetworkEncKey::CConfirm::IsValid(pkt))
          OnSetNetworkEncKeyConfirm(adapter, SetNetworkEncKey::CConfirm(pkt));
        else if(ParamsAndStats::CResponse::IsValid(pkt))
          OnParamsAndStatsResponse(adapter, ParamsAndStats::CResponse(pkt));
        else if(Int51NetStat::CResponse::IsValid(pkt))
          OnInt51NetStatResponse(adapter, Int51NetStat::CResponse(pkt));
        else if(TurboDeviceDescription::CResponse::IsValid(pkt))
          OnTurboDeviceDescriptionResponse(adapter, TurboDeviceDescription::CResponse(pkt));
        else if(TurboChannelCapacities::CResponse::IsValid(pkt))
          OnTurboChannelCapacitiesResponse(adapter, TurboChannelCapacities::CResponse(pkt));
        else
          OnUnknownMme(adapter, pkt);

        return true;
      }
      else
        return false;
    };
  };
}


namespace HomePlugAvMMEs
{
  static const uint16_t uEtherType = 0x88E1;
  static const uint8_t cIntellonLocalBroadcastAddr[6] = { 0x00, 0xB0, 0x52, 0x00, 0x00, 0x01 };
  static const uint8_t cIntellonOUI[3] = { 0x00, 0xB0, 0x52 };
  
  enum { eMmeVersion0 = 0, eMmeVersion1 = 1 };
  enum { eReq = 0x0000, eCnf = 0x0001, eInd = 0x0002, eRsp = 0x0003 };  
  enum { eCC = 0x0000, eCP = 0x2000, eNN = 0x4000, eCM = 0x6000, eMS = 0x8000, eVS = 0xA000 };
  enum { eMmeMinimumSize = 64 }; 

  struct __packed__ ThunderV1Hdr
  {
    CMACHeader machdr;
    uint8_t cMmeVersion;
    uint16_t uMmeType;
    uint16_t uFragInfo;

    ThunderV1Hdr() : machdr() {}
    ThunderV1Hdr(const CMACAddress& dst, const CMACAddress& src, uint16_t mmeType) :
      machdr(dst, src, uEtherType), cMmeVersion(eMmeVersion1), uMmeType(htoles(mmeType)), uFragInfo(0) {}

    static bool IsValid(const IPacket& pkt, uint16_t expectedMmeType)
    {
      return
        (pkt.Size() >= sizeof(ThunderV1Hdr)) &&
        (((ThunderV1Hdr*)pkt.Data())->cMmeVersion == eMmeVersion1) &&
        (((ThunderV1Hdr*)pkt.Data())->uMmeType == htoles(expectedMmeType)) &&
        (((ThunderV1Hdr*)pkt.Data())->uFragInfo == 0);
    }
  };

  struct __packed__ ThunderVSHdr
  {
    CMACHeader machdr;
    uint8_t cMmeVersion;
    uint16_t uMmeType;
    uint8_t cOUI[3];

    ThunderVSHdr() : machdr() {}
    ThunderVSHdr(const CMACAddress& dst, const CMACAddress& src, uint16_t mmeType) :
      machdr(dst, src, uEtherType), cMmeVersion(eMmeVersion0), uMmeType(htoles(mmeType))
    {
      cOUI[0] = cIntellonOUI[0];
      cOUI[1] = cIntellonOUI[1];
      cOUI[2] = cIntellonOUI[2];
    }

    static bool IsValid(const IPacket& pkt, uint16_t expectedMmeType)
    {
      return
        (pkt.Size() >= sizeof(ThunderVSHdr)) &&
        (((ThunderVSHdr*)pkt.Data())->cMmeVersion == eMmeVersion0) &&
        (((ThunderVSHdr*)pkt.Data())->uMmeType == htoles(expectedMmeType)) &&
        (((ThunderVSHdr*)pkt.Data())->cOUI[0] == cIntellonOUI[0]) &&
        (((ThunderVSHdr*)pkt.Data())->cOUI[1] == cIntellonOUI[1]) &&
        (((ThunderVSHdr*)pkt.Data())->cOUI[2] == cIntellonOUI[2]);
    }
  };

  struct __packed__ ThunderVSV1Hdr
  {
    CMACHeader machdr;
    uint8_t cMmeVersion;
    uint16_t uMmeType;
    uint16_t uFragInfo;
    uint8_t cOUI[3];

    ThunderVSV1Hdr() : machdr() {}
    ThunderVSV1Hdr(const CMACAddress& dst, const CMACAddress& src, uint16_t mmeType) :
      machdr(dst, src, uEtherType), cMmeVersion(eMmeVersion1), uMmeType(htoles(mmeType)), uFragInfo(0)
    {
      cOUI[0] = cIntellonOUI[0];
      cOUI[1] = cIntellonOUI[1];
      cOUI[2] = cIntellonOUI[2];
    }

    static bool IsValid(const IPacket& pkt, uint16_t expectedMmeType)
    {
      return
        (pkt.Size() >= sizeof(ThunderVSHdr)) &&
        (((ThunderVSV1Hdr*)pkt.Data())->cMmeVersion == eMmeVersion1) &&
        (((ThunderVSV1Hdr*)pkt.Data())->uMmeType == htoles(expectedMmeType)) &&
        (((ThunderVSV1Hdr*)pkt.Data())->uFragInfo == 0) &&
        (((ThunderVSV1Hdr*)pkt.Data())->cOUI[0] == cIntellonOUI[0]) &&
        (((ThunderVSV1Hdr*)pkt.Data())->cOUI[1] == cIntellonOUI[1]) &&
        (((ThunderVSV1Hdr*)pkt.Data())->cOUI[2] == cIntellonOUI[2]);
    }
  };

  namespace ThunderGetVersion
  {
    enum { eMMType = 0x0000, eMMTypeReq = eVS + eMMType + eReq, eMMTypeCnf = eVS + eMMType + eCnf };
    enum { eSuccess = 0x00, eFail = 0x01 };                    
    enum { eINT6000 = 0x01, eINT6300 = 0x02, eINT6400 = 0x03 };

    struct __packed__ CnfData
    {
      ThunderVSHdr hdr;
      uint8_t uStatus;  
      uint8_t uDeviceID;             
      uint8_t uVersionLen;           
      enum { eVersionSize = 64 };
      uint8_t cVersion[eVersionSize];
    };
    enum { eCnfDataFixedSize = sizeof(CnfData) - CnfData::eVersionSize }; 

    class __packed__ CRequest : public IPacket
    {
      ThunderVSHdr hdr;
    public:
      CRequest(const CMACAddress& dst, const CMACAddress& src) : hdr(dst, src, eMMTypeReq) {}
      virtual const uint8_t* Data() const { return (const uint8_t*)&hdr; }
      virtual size_t Size() const { return sizeof(hdr); }
    };

    class __packed__ CConfirm
    {
      CnfData data;
    public:
      static bool IsValid(const IPacket& pkt) 
      {
        return 
          ThunderVSHdr::IsValid(pkt, eMMTypeCnf) && 
          (pkt.Size() >= eCnfDataFixedSize);
      }
      CConfirm(const IPacket& pkt) { InitFromPacket(&data, sizeof(data), pkt); }
      CMACAddress GetAddress() const { return CMACAddress(data.hdr.machdr.cSrcAddr); }
      uint8_t GetStatus() const { return data.uStatus; }
      uint8_t GetDeviceID() const { return data.uDeviceID; }
      std::string GetVersion() const { return std::string((char*)data.cVersion, std::min<size_t>(data.uVersionLen, sizeof(data.cVersion))).c_str(); }
    };
  }
  
  namespace ThunderReadModuleData
  {
    enum { eMMType = 0x0024, eMMTypeReq = eVS + eMMType + eReq, eMMTypeCnf = eVS + eMMType + eCnf };
    enum { eSoftLoader = 0x00, eFirmware = 0x01, ePib = 0x02 };
    enum { eSuccess = 0x00, eInvalidModuleID = 0x10, eInvalidLength = 0x12, eInvalidChkSum = 0x14 };

    struct __packed__ ReqData
    {
      ThunderVSHdr hdr;
      uint8_t uModuleID;
      uint8_t uReserved;
      uint16_t uLength;
      uint32_t uOffset;
      ReqData(const CMACAddress& dst, const CMACAddress& src,
        uint8_t moduleID, uint16_t length, uint32_t offset) :
        hdr(dst, src, eMMTypeReq), uModuleID(moduleID), uReserved(0), uLength(htoles(length)), uOffset(htolel(offset)) {}
    };
    struct __packed__ CnfData
    {
      ThunderVSHdr hdr;
      uint8_t uStatus;
      uint8_t cReserved[3];
      uint8_t uModuleID;
      uint8_t uReserved;
      uint16_t uLength;
      uint32_t uOffset;
      uint32_t uChecksum;
      enum { eDataSize = 1024 }; 
      uint8_t cData[eDataSize];
    };
    enum { eCnfDataFixedSize = sizeof(CnfData) - CnfData::eDataSize };

    class __packed__ CRequest : public IPacket
    {
      ReqData data;
    public:
      CRequest(const CMACAddress& dst, const CMACAddress& src,
        uint8_t moduleID, uint16_t length, uint32_t offset) : data(dst, src, moduleID, length, offset) {}
      virtual const uint8_t* Data() const { return (const uint8_t*)&data; }
      virtual size_t Size() const { return sizeof(data); }
    };

    class __packed__ CConfirm
    {
      CnfData data;
    public:
      static bool IsValid(const IPacket& pkt)
      { 
        return 
          ThunderVSHdr::IsValid(pkt, eMMTypeCnf) && 
          (pkt.Size() >= eCnfDataFixedSize);
      }
      CConfirm(const IPacket& pkt) { InitFromPacket(&data, sizeof(data), pkt); }
      CMACAddress GetAddress() const { return CMACAddress(data.hdr.machdr.cSrcAddr); }
      uint8_t GetStatus() const { return data.uStatus; }
      uint8_t GetModuleID() const { return data.uModuleID; }
      uint16_t GetLength() const { return letohs(data.uLength); }
      uint32_t GetOffset() const { return letohl(data.uOffset); }
      bool IsChecksumValid() const
      {
        return (HomePlugAvTools::Checksum((uint32_t*)data.cData, 
          std::min<size_t>(letohs(data.uLength), sizeof(data.cData)) / 4) == data.uChecksum);
      }
      std::basic_string<uint8_t> GetData() const
      {
        return std::basic_string<uint8_t>(data.cData, 
          data.cData + std::min<size_t>(letohs(data.uLength), sizeof(data.cData)));
      }
    };
  }

  namespace ThunderNetworkInfoCommon
  {
    enum { eMMType = 0x0038, eMMTypeReq = eVS + eMMType + eReq, eMMTypeCnf = eVS + eMMType + eCnf };
    enum { eStation = 0, eProxyCCo = 1, eCCo = 2 };
    
    class StationInfo
    {
      CMACAddress addr, firstBridgedAddr;
      uint32_t uAvgTxPhyRateMbps, uAvgRxPhyRateMbps;
      friend class std::list<StationInfo>;
    public:
      template<class TStaData>
      StationInfo(const TStaData& d) :
        addr(d.cAddr), firstBridgedAddr(d.cFirstBridgedAddr),
        uAvgTxPhyRateMbps(letohx(d.uAvgTxPhyRateMbps)), 
        uAvgRxPhyRateMbps(letohx(d.uAvgRxPhyRateMbps)) {}
      const CMACAddress& GetAddress() const { return addr; }
      const CMACAddress& GetFirstBridgedAddress() const { return firstBridgedAddr; }
      uint32_t GetTxCodedRate() const { return uAvgTxPhyRateMbps; }
      uint32_t GetRxCodedRate() const { return uAvgRxPhyRateMbps; }
      double GetTxRawRate() const { return uAvgTxPhyRateMbps * 21.0 / 16.0; }
      double GetRxRawRate() const { return uAvgRxPhyRateMbps * 21.0 / 16.0; }
    };
  }

  namespace ThunderNetworkInfo
  {
    using namespace ThunderNetworkInfoCommon;

    struct __packed__ StaData
    {
      uint8_t cAddr[6];
      uint8_t uTEI;
      uint8_t cFirstBridgedAddr[6];
      uint8_t uAvgTxPhyRateMbps;
      uint8_t uAvgRxPhyRateMbps;
    };
    struct __packed__ CnfData
    {
      ThunderVSHdr hdr;
      uint8_t uNumAVLNs;
      uint8_t cNID[7];
      uint8_t uSNID;
      uint8_t uTEI;
      uint8_t uStationRole;
      uint8_t cCCoAddr[6];
      uint8_t uCCoTEI;
      uint8_t uNumStations;
      enum { eStationsSize = 98 };
      StaData aStations[eStationsSize];
    };
    enum { eCnfDataFixedSize = sizeof(CnfData) - (CnfData::eStationsSize * sizeof(StaData)) }; 

    class __packed__ CRequest : public IPacket
    {
      ThunderVSHdr hdr;
    public:
      CRequest(const CMACAddress& dst, const CMACAddress& src) : hdr(dst, src, eMMTypeReq) {}
      virtual const uint8_t* Data() const { return (const uint8_t*)&hdr; }
      virtual size_t Size() const { return sizeof(hdr); }
    };

    class __packed__ CConfirm
    {
      CnfData data;
    public:
      static bool IsValid(const IPacket& pkt)
      {
        return
          ThunderVSHdr::IsValid(pkt, eMMTypeCnf) && 
          (pkt.Size() >= eCnfDataFixedSize) &&
          (pkt.Size() >= (eCnfDataFixedSize + (((CnfData*)pkt.Data())->uNumStations * sizeof(StaData))));
      }
      CConfirm(const IPacket& pkt) { InitFromPacket(&data, sizeof(data), pkt); }
      CMACAddress GetAddress() const { return CMACAddress(data.hdr.machdr.cSrcAddr); }
      CMACAddress GetCCoAddress() const { return CMACAddress(data.cCCoAddr); }
      std::list<StationInfo> GetStations() const { return std::list<StationInfo>(data.aStations, data.aStations + data.uNumStations); }
    };
  }

  namespace ThunderNetworkInfoV1
  {
    using namespace ThunderNetworkInfoCommon;

    struct __packed__ ReqData
    {
      ThunderVSV1Hdr hdr;
      uint8_t uMmeSubVer;
      uint8_t uReserved[3];
      ReqData(const CMACAddress& dst, const CMACAddress& src) : hdr(dst, src, eMMTypeReq) {}
    };
    struct __packed__ StaData
    {
      uint8_t cAddr[6];
      uint8_t uTEI;
      uint8_t cReserved1[3];
      uint8_t cFirstBridgedAddr[6];
      uint16_t uAvgTxPhyRateMbps;
      uint16_t uReserved2;
      uint16_t uAvgRxPhyRateMbps;
      uint16_t uReserved3;
    };
    struct __packed__ CnfData
    {
      ThunderVSV1Hdr hdr;
      uint8_t uMmeSubVer;
      uint8_t uReserved1;
      uint16_t uMmeDataLen;
      uint8_t uReserved2;
      uint8_t uNumAVLNs;      
      uint8_t cNID[7];
      uint16_t uReserved3;
      uint8_t uSNID;      
      uint8_t uTEI;
      uint32_t uReserved4;      
      uint8_t uStationRole;
      uint8_t cCCoAddr[6];
      uint8_t uCCoTEI;
      uint8_t cReserved5[3];      
      uint8_t uNumStations;
      uint8_t cReserved6[5];      
      enum { eStationsSize = 60 };
      StaData aStations[eStationsSize];
    };
    enum { eCnfDataFixedSize = sizeof(CnfData) - (CnfData::eStationsSize * sizeof(StaData)) };

    class __packed__ CRequest : public IPacket
    {
      ReqData data;
    public:
      CRequest(const CMACAddress& dst, const CMACAddress& src) : data(dst, src) {}
      virtual const uint8_t* Data() const { return (const uint8_t*)&data; }
      virtual size_t Size() const { return sizeof(data); }
    };

    class __packed__ CConfirm
    {
      CnfData data;
    public:
      static bool IsValid(const IPacket& pkt)
      {
        return
          ThunderVSV1Hdr::IsValid(pkt, eMMTypeCnf) && 
          (pkt.Size() >= eCnfDataFixedSize) &&
          (pkt.Size() >= (eCnfDataFixedSize + (((CnfData*)pkt.Data())->uNumStations * sizeof(StaData))));
      }
      CConfirm(const IPacket& pkt) { InitFromPacket(&data, sizeof(data), pkt); }
      CMACAddress GetAddress() const { return CMACAddress(data.hdr.machdr.cSrcAddr); }
      CMACAddress GetCCoAddress() const { return CMACAddress(data.cCCoAddr); }
      std::list<StationInfo> GetStations() const { return std::list<StationInfo>(data.aStations, data.aStations + data.uNumStations); }
    };
  }

  namespace ThunderSetKey
  {
    enum { eMMType = 0x0050, eMMTypeReq = eVS + eMMType + eReq, eMMTypeCnf = eVS + eMMType + eCnf };
    enum { eKeyTypeNMK = 1, eKeyTypeNMK_PreMac15 = 3 }; 
    enum { eKeyTargetRemote = 0x00,  eKeyTargetLocal = 0x0F };

    enum
    {
      eSuccess = 0x00,
      eInvalid_PEKS = 0x10,             
      eInvalid_PIB = 0x11,              
      eInvalid_PEKS_EncPayload = 0x12,  
      eRemote_Fail = 0x13,              
      eInvalidRemote_Answer = 0x14,         
      eRemoteDecryptionFailed = 0x15    
    };
    
    struct __packed__ ReqData
    {
      ThunderVSHdr hdr;
      uint8_t uPEKS;              
      uint8_t cKEY[16];
      uint8_t uPEKS_EncPayload;   
      uint8_t cRemoteMacAddr[6];  
      uint8_t cKEY_EncPayload[16];
      ReqData(const CMACAddress& dst, const CMACAddress& src, uint8_t keyType, uint8_t keyTarget) :
        hdr(dst, src, eMMTypeReq), uPEKS(keyType), uPEKS_EncPayload(keyTarget) {}
    };
    struct __packed__ CnfData
    {
      ThunderVSHdr hdr;
      uint8_t uStatus;      
    };

    class __packed__ CRequest : public IPacket
    {
      ReqData data;

    public:

      CRequest(const CMACAddress& dst, const CMACAddress& src, const std::string& strPassword, bool bPreMac15 = false) :
        data(dst, src, (bPreMac15 ? eKeyTypeNMK_PreMac15 : eKeyTypeNMK), eKeyTargetLocal)
      {
        HomePlugAvTools::NetworkKeyFromPassword(strPassword, data.cKEY);
        memset(data.cRemoteMacAddr, 0, sizeof(data.cRemoteMacAddr));
        memset(data.cKEY_EncPayload, 0, sizeof(data.cKEY_EncPayload));
      }

      CRequest(const CMACAddress& dst, const CMACAddress& src, const std::string& strPassword, 
        const std::string& strSecurityID, const CMACAddress& remoteAddr = CMACAddress::Broadcast(), bool bPreMac15 = false) :
        data(dst, src, (bPreMac15 ? eKeyTypeNMK_PreMac15 : eKeyTypeNMK), eKeyTargetRemote)
      {
        HomePlugAvTools::NetworkKeyFromPassword(strPassword, data.cKEY);
        memcpy(data.cRemoteMacAddr, remoteAddr, sizeof(data.cRemoteMacAddr));
        HomePlugAvTools::DeviceAccessKeyFromSecurityID(strSecurityID, data.cKEY_EncPayload);
      }

      CRequest(const CMACAddress& dst, const CMACAddress& src, const uint8_t networkKEY[16], bool bPreMac15 = false) :
        data(dst, src, (bPreMac15 ? eKeyTypeNMK_PreMac15 : eKeyTypeNMK), eKeyTargetLocal)
      {
        memcpy(data.cKEY, networkKEY, sizeof(data.cKEY));
        memset(data.cRemoteMacAddr, 0, sizeof(data.cRemoteMacAddr));
        memset(data.cKEY_EncPayload, 0, sizeof(data.cKEY_EncPayload));
      }

      CRequest(const CMACAddress& dst, const CMACAddress& src, const uint8_t networkKEY[16], 
        const uint8_t remoteDAK[16], const CMACAddress& remoteAddr = CMACAddress::Broadcast(), bool bPreMac15 = false) :
        data(dst, src, (bPreMac15 ? eKeyTypeNMK_PreMac15 : eKeyTypeNMK), eKeyTargetRemote)
      {
        memcpy(data.cKEY, networkKEY, sizeof(data.cKEY));
        memcpy(data.cRemoteMacAddr, remoteAddr, sizeof(data.cRemoteMacAddr));
        memcpy(data.cKEY_EncPayload, remoteDAK, sizeof(data.cKEY_EncPayload));
      }

      virtual const uint8_t* Data() const { return (const uint8_t*)&data; }
      virtual size_t Size() const { return sizeof(data); }
    };

    class __packed__ CConfirm
    {
      CnfData data;
    public:
      static bool IsValid(const IPacket& pkt)
      {
        return 
          ThunderVSHdr::IsValid(pkt, eMMTypeCnf) && 
          (pkt.Size() >= sizeof(CnfData));
      }
      CConfirm(const IPacket& pkt) { InitFromPacket(&data, sizeof(data), pkt); }
      CMACAddress GetAddress() const { return CMACAddress(data.hdr.machdr.cSrcAddr); }
      uint8_t GetStatus() const { return data.uStatus; }
    };
  }

  namespace ThunderGetManufacturingString
  {
    enum { eMMType = 0x0054, eMMTypeReq = eVS + eMMType + eReq, eMMTypeCnf = eVS + eMMType + eCnf };
    enum { eSuccess = 0x00, eFail = 0x01 }; 

    struct __packed__ CnfData
    {
      ThunderVSHdr hdr;
      uint8_t uStatus;                
      uint8_t uMftStrLen;             
      enum { eMftStrSize = 64 };
      uint8_t cMftStr[eMftStrSize];   
    };
    enum { eCnfDataFixedSize = sizeof(CnfData) - CnfData::eMftStrSize };

    class __packed__ CRequest : public IPacket
    {
      ThunderVSHdr hdr;
    public:
      CRequest(const CMACAddress& dst, const CMACAddress& src) : hdr(dst, src, eMMTypeReq) {}
      virtual const uint8_t* Data() const { return (const uint8_t*)&hdr; }
      virtual size_t Size() const { return sizeof(hdr); }
    };

    class __packed__ CConfirm
    {
      CnfData data;
    public:
      static bool IsValid(const IPacket& pkt) 
      {
        return 
          ThunderVSHdr::IsValid(pkt, eMMTypeCnf) && 
          (pkt.Size() >= eCnfDataFixedSize);
      }
      CConfirm(const IPacket& pkt) { InitFromPacket(&data, sizeof(data), pkt); }
      CMACAddress GetAddress() const { return CMACAddress(data.hdr.machdr.cSrcAddr); }
      uint8_t GetStatus() const { return data.uStatus; }
      std::string GetManufacturingString() const 
      { 
        return std::string((char*)data.cMftStr, std::min<size_t>(data.uMftStrLen, sizeof(data.cMftStr))).c_str();
      }
    };
  }

  class CDispatcher : public IPacketDispatcher
  {
  protected:

    virtual void OnThunderGetVersionConfirm(const CMACAddress&, const ThunderGetVersion::CConfirm&) {}
    virtual void OnThunderReadModuleDataConfirm(const CMACAddress&, const ThunderReadModuleData::CConfirm&) {}
    virtual void OnThunderNetworkInfoConfirm(const CMACAddress&, const ThunderNetworkInfo::CConfirm&) {}
    virtual void OnThunderNetworkInfoV1Confirm(const CMACAddress&, const ThunderNetworkInfoV1::CConfirm&) {}
    virtual void OnThunderSetKeyConfirm(const CMACAddress&, const ThunderSetKey::CConfirm&) {}
    virtual void OnThunderGetManufacturingStringConfirm(const CMACAddress&, const ThunderGetManufacturingString::CConfirm&) {}
    virtual void OnUnknownMme(const CMACAddress&, const IPacket&) {}

  public:

    virtual bool Dispatch(const CMACAddress& adapter, const IPacket& pkt)
    {
      if(CMACHeader::IsValid(pkt, uEtherType))
      {
        if(ThunderGetVersion::CConfirm::IsValid(pkt))
          OnThunderGetVersionConfirm(adapter, ThunderGetVersion::CConfirm(pkt));
        else if(ThunderReadModuleData::CConfirm::IsValid(pkt))
          OnThunderReadModuleDataConfirm(adapter, ThunderReadModuleData::CConfirm(pkt));
        else if(ThunderNetworkInfo::CConfirm::IsValid(pkt))
          OnThunderNetworkInfoConfirm(adapter, ThunderNetworkInfo::CConfirm(pkt));
        else if(ThunderNetworkInfoV1::CConfirm::IsValid(pkt))
          OnThunderNetworkInfoV1Confirm(adapter, ThunderNetworkInfoV1::CConfirm(pkt));
        else if(ThunderSetKey::CConfirm::IsValid(pkt))
          OnThunderSetKeyConfirm(adapter, ThunderSetKey::CConfirm(pkt));
        else if(ThunderGetManufacturingString::CConfirm::IsValid(pkt))
          OnThunderGetManufacturingStringConfirm(adapter, ThunderGetManufacturingString::CConfirm(pkt));
        else
          OnUnknownMme(adapter, pkt);

        return true;
      }
      else
        return false;
    };
  };
}


__packing_end__

#endif // _DLAN_HPMMES_H_
