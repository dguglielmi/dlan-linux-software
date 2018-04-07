
//
// (c) 2006-2010 devolo AG, Aachen (Germany)
//

#ifndef _DLAN_DLANMONITOR_H_
#define _DLAN_DLANMONITOR_H_

#include <climits>
#include <map>
#include <queue>
#include <set>
#include "dlandevice.h"
#include "hpmmes.h"
#include "packetdispatcher.h"
#include "packetinterface.h"
#include "packettask.h"

class IDlanMonitorObserver
{
public:
  virtual void OnUpdate() = 0;
};

struct CDlanMonitorTimings
{
  unsigned long TickInterval;
  unsigned long DelayedSendingInterval;
  int LocalVanishedAge;
  int RemoteRefreshAge;
  int RemoteVanishedAge;
};

const CDlanMonitorTimings dlanDefaultAging = { 250, 20, 60, 60, 120 };

class CDlanMonitor : public IPacketTask, 
  private HomePlugMMEs::CDispatcher, private HomePlugAvMMEs::CDispatcher
{
public:

  enum Mode
  {
    eMonitorLocalHP1 = 0x01,
    eMonitorHP1 = eMonitorLocalHP1 | 0x02,
    eMonitorLocalTurbo = 0x04,
    eMonitorTurbo = eMonitorLocalTurbo | 0x08,
    eMonitorLocalThunderbolt = 0x10,
    eMonitorThunderbolt = eMonitorLocalThunderbolt | 0x20,
    eMonitorAll = eMonitorHP1 | eMonitorTurbo | eMonitorThunderbolt
  };

  CDlanMonitor(IPacketInterface& ifc, Mode mode = eMonitorAll, const CDlanMonitorTimings &aging = dlanDefaultAging) :
    m_ulTick(0), m_eMode(mode), m_ifc(ifc), m_pObserver(0), m_timings(aging) { InitReceiver(); }
  CDlanMonitor(IPacketInterface& ifc, IDlanMonitorObserver& obs, Mode mode = eMonitorAll, const CDlanMonitorTimings &aging = dlanDefaultAging) :
    m_ulTick(0), m_eMode(mode), m_ifc(ifc), m_pObserver(&obs), m_timings(aging) { InitReceiver(); }
  virtual ~CDlanMonitor();

  virtual IPacketReceiver& GetReceiver() { return m_receiver; }
  virtual unsigned long Drumbeat();
  virtual bool Complete() { return false; }
  virtual bool Successful() { return false; }
  const CDlanLocalDeviceList& GetLocalDevices() const { return m_listLocalDevices; }
  void RemoveFromDeviceLists(const CMACAddress& addrDevice);
  void RemoveFromDeviceLists(const std::set<CMACAddress>& setDevices);

private:

  struct LocalDevice
  {
    LocalDevice(CDlanLocalDeviceList::iterator it) : iAge(0), itPublicDevice(it) {}
    int iAge;
    CDlanLocalDeviceList::iterator itPublicDevice;
    std::map<CMACAddress,int> mapRemoteDeviceAges, mapUserDataAges;
  };

  struct NetworkInfoResponse
  { 
    NetworkInfoResponse() {}
    NetworkInfoResponse(const CMACAddress& c, const std::list<HomePlugAvMMEs::ThunderNetworkInfo::StationInfo>& s) : ccoAddr(c), stations(s) {}
    CMACAddress ccoAddr;
    std::list<HomePlugAvMMEs::ThunderNetworkInfo::StationInfo> stations;
  };

  struct UserDataResponse
  {
    UserDataResponse() {}
    UserDataResponse(const std::string& mft) : strMft(mft) {}      
    UserDataResponse(const std::basic_string<unsigned char> userData) :
      strMft((const char*)userData.substr(0,64).c_str()),
      strUser((const char*)userData.substr(80,64).c_str()),
      strAvln((const char*)userData.substr(144,64).c_str()),
      bstrNMK(userData.substr(64,16)) {}
    std::string strMft, strUser, strAvln;
    std::basic_string<unsigned char> bstrNMK;    
  };

  struct NetwAdapter
  {
    NetwAdapter() : iTick(0), iFastBroadcastCnt(5), bNetworkInfoV1Sent(false) {}
    int iTick, iFastBroadcastCnt;
    bool bNetworkInfoV1Sent;
    std::set<CMACAddress> setParamsAndStatsResponses;
    std::set<CMACAddress> setRemoteTurboResponses;
    std::set<CMACAddress> setDevicesToTrigger;
    std::set<CMACAddress> setReadModDataResponses;
    std::map<CMACAddress,std::string> mapGetVersionResponses;
    std::map<CMACAddress,UserDataResponse> mapUserDataResponses;
    std::map<CMACAddress,NetworkInfoResponse> mapNetworkInfoResponses;
    std::map<CMACAddress,LocalDevice> mapLocalDevices;
    std::queue<IPacket*> queuePendingPackets;
  };

  unsigned long m_ulTick;
  Mode m_eMode;
  IPacketInterface& m_ifc;
  IDlanMonitorObserver* m_pObserver;
  CDlanMonitorTimings m_timings;
  CPacketReceiverAndDispatcher m_receiver;
  CDlanLocalDeviceList m_listLocalDevices;
  std::map<CMACAddress,NetwAdapter> m_mapNICs;

  void OnUpdate() { if(m_pObserver) m_pObserver->OnUpdate(); }
  void InitReceiver();
  void UpdateAdapters(bool&, const std::set<CMACAddress>& = std::set<CMACAddress>());
  void RemoveDevices(bool&, bool, const std::set<CMACAddress>& = std::set<CMACAddress>());
  void TickAdapters();
  void SendQueuedPackets(bool&);
  void SendLocalDeviceBroadcasts(std::map<CMACAddress,NetwAdapter>::iterator);
  void SendRemoteDeviceBroadcasts(std::map<CMACAddress,NetwAdapter>::iterator);
  void TriggerUnknownDevices(std::map<CMACAddress,NetwAdapter>::iterator);
  void ClearUnknownDevices(std::map<CMACAddress,NetwAdapter>::iterator);
  LocalDevice& UpdateLocalDevice(std::map<CMACAddress,NetwAdapter>::iterator, const CMACAddress&, bool,
    CDlanDevice::teType, bool, const std::string&, bool, const UserDataResponse&, bool, const CMACAddress&, bool, bool&);
  void UpdateRemoteDevice(LocalDevice&, const CMACAddress&, bool,
    CDlanDevice::teType, bool, const std::string&, bool, const UserDataResponse&, bool, double, double, bool, 
    const std::map<CMACAddress, CDlanDataRates>&, bool, const CMACAddress&, bool, bool&);
  void ThunderNetworkInfo(std::map<CMACAddress,NetwAdapter>::iterator, const CMACAddress&, const NetworkInfoResponse&);

  virtual void OnParamsAndStatsResponse(const CMACAddress&, const HomePlugMMEs::ParamsAndStats::CResponse&);
  virtual void OnInt51NetStatResponse(const CMACAddress&, const HomePlugMMEs::Int51NetStat::CResponse&);
  virtual void OnTurboDeviceDescriptionResponse(const CMACAddress&, const HomePlugMMEs::TurboDeviceDescription::CResponse&);
  virtual void OnTurboChannelCapacitiesResponse(const CMACAddress&, const HomePlugMMEs::TurboChannelCapacities::CResponse&);

  virtual void OnThunderReadModuleDataConfirm(const CMACAddress&, const HomePlugAvMMEs::ThunderReadModuleData::CConfirm&);
  virtual void OnThunderGetVersionConfirm(const CMACAddress&, const HomePlugAvMMEs::ThunderGetVersion::CConfirm&);
  virtual void OnThunderNetworkInfoConfirm(const CMACAddress&, const HomePlugAvMMEs::ThunderNetworkInfo::CConfirm&);
  virtual void OnThunderNetworkInfoV1Confirm(const CMACAddress&, const HomePlugAvMMEs::ThunderNetworkInfoV1::CConfirm&);
};

#endif // _DLAN_DLANMONITOR_H_
