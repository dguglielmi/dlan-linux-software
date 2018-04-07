
//
// (c) 2006-2010 devolo AG, Aachen (Germany)
//

#include <string>
#include <sstream>
#include "platform.h"
#include "dlanmonitor.h"

void CDlanMonitor::RemoveFromDeviceLists(
  const CMACAddress& addrDevice)
{
  std::set<CMACAddress> setDevices;
  setDevices.insert(addrDevice);
  RemoveFromDeviceLists(setDevices);
}

void CDlanMonitor::RemoveFromDeviceLists(
  const std::set<CMACAddress>& setDevices)
{
  bool bUpdate = false;
  RemoveDevices(bUpdate, false, setDevices);
  if(bUpdate) 
    OnUpdate();
}

void CDlanMonitor::InitReceiver()
{
  m_receiver.AddDispatcher(static_cast<HomePlugMMEs::CDispatcher&>(*this));
  m_receiver.AddDispatcher(static_cast<HomePlugAvMMEs::CDispatcher&>(*this));
}

unsigned long CDlanMonitor::Drumbeat()
{
  if(m_ulTick == 0)
  {
    bool bUpdate = false;
    UpdateAdapters(bUpdate, m_ifc.GetAdapters());
    RemoveDevices(bUpdate, true);
    TickAdapters();

    if(bUpdate)
      OnUpdate();
  }

  bool bStillPacketsPending = false;
  SendQueuedPackets(bStillPacketsPending);

  unsigned long ulWait = bStillPacketsPending ? 
    m_timings.DelayedSendingInterval : (m_timings.TickInterval - m_ulTick);

  m_ulTick += ulWait;
  m_ulTick %= m_timings.TickInterval;

  return ulWait;
}

void CDlanMonitor::UpdateAdapters(
  bool& bUpdate,
  const std::set<CMACAddress>& setAdapters)
{
  for(std::set<CMACAddress>::const_iterator itAdapter = setAdapters.begin(); 
    (itAdapter != setAdapters.end()); ++itAdapter)
  {
    if((*itAdapter != CMACAddress::Null()) && (m_mapNICs.find(*itAdapter) == m_mapNICs.end()))
      m_mapNICs.insert(std::make_pair(*itAdapter,NetwAdapter()));
  }

  std::map<CMACAddress,NetwAdapter>::iterator itNIC = m_mapNICs.begin();
  while(itNIC != m_mapNICs.end())
  {
    if(setAdapters.find(itNIC->first) == setAdapters.end())
    {
      while(!itNIC->second.mapLocalDevices.empty())
      {
        bUpdate = true;
        m_listLocalDevices.erase(itNIC->second.mapLocalDevices.begin()->second.itPublicDevice);
        itNIC->second.mapLocalDevices.erase(itNIC->second.mapLocalDevices.begin());
      }

      while(!itNIC->second.queuePendingPackets.empty()) 
      {
        delete itNIC->second.queuePendingPackets.front();
        itNIC->second.queuePendingPackets.pop();
      }

      m_mapNICs.erase(itNIC++);      
    }
    else
    {
      ++itNIC;
    }
  } 
}

void CDlanMonitor::RemoveDevices(
  bool& bUpdate,
  bool bAge,    
  const std::set<CMACAddress>& setForceRemove)
{
  for(std::map<CMACAddress,NetwAdapter>::iterator itNIC = m_mapNICs.begin(); 
    (itNIC != m_mapNICs.end()); ++itNIC)
  {
    std::map<CMACAddress,LocalDevice>::iterator itLocalDevice = itNIC->second.mapLocalDevices.begin();
    while(itLocalDevice != itNIC->second.mapLocalDevices.end())
    {
      if(bAge) ++itLocalDevice->second.iAge;

      if((itLocalDevice->second.iAge == m_timings.LocalVanishedAge) || 
        (setForceRemove.find(itLocalDevice->first) != setForceRemove.end()))
      {
        bUpdate = true;
        m_listLocalDevices.erase(itLocalDevice->second.itPublicDevice);
        itNIC->second.mapLocalDevices.erase(itLocalDevice++);
      }
      else
      {
        std::map<CMACAddress,int>::iterator itUserDataAge;
        if(bAge &&
          ((itUserDataAge = itLocalDevice->second.mapUserDataAges.find(itLocalDevice->first)) != itLocalDevice->second.mapUserDataAges.end()) &&
          (++itUserDataAge->second == m_timings.LocalVanishedAge))
        {
          UpdateLocalDevice(itNIC, itLocalDevice->first, false, CDlanDevice::eThunderbolt, true, 
            "", true, UserDataResponse(), false, CMACAddress::Null(), true, bUpdate);
          itLocalDevice->second.mapUserDataAges.erase(itUserDataAge);
        }

        std::map<CMACAddress,int>::iterator itRemoteDevice = itLocalDevice->second.mapRemoteDeviceAges.begin();
        while(itRemoteDevice != itLocalDevice->second.mapRemoteDeviceAges.end())
        {
          if(bAge) ++itRemoteDevice->second;
        
          if((itRemoteDevice->second == m_timings.RemoteVanishedAge) ||
            (setForceRemove.find(itRemoteDevice->first) != setForceRemove.end()))
          {
            bUpdate = true;
            itLocalDevice->second.itPublicDevice->RemoveRemoteDevice(itRemoteDevice->first);
            itLocalDevice->second.mapRemoteDeviceAges.erase(itRemoteDevice++);
          }
          else
          {
            if(bAge &&
              ((itUserDataAge = itLocalDevice->second.mapUserDataAges.find(itRemoteDevice->first)) != itLocalDevice->second.mapUserDataAges.end()) &&
              (++itUserDataAge->second == m_timings.RemoteVanishedAge))
            {
              UpdateRemoteDevice(itLocalDevice->second, itRemoteDevice->first, false,
                CDlanDevice::eThunderbolt, true, "", true, UserDataResponse(), false, 0.0, 0.0, true, 
                std::map<CMACAddress, CDlanDataRates>(), true, CMACAddress(), true, bUpdate);
              itLocalDevice->second.mapUserDataAges.erase(itUserDataAge);
            }

            ++itRemoteDevice;
          }
        }
        ++itLocalDevice;
      }
    }
  }
}

void CDlanMonitor::TickAdapters()
{
  for(std::map<CMACAddress,NetwAdapter>::iterator itNIC = m_mapNICs.begin(); 
    (itNIC != m_mapNICs.end()); ++itNIC)
  {
    itNIC->second.iTick++;
    
    if(itNIC->second.iFastBroadcastCnt)
    {
      if(itNIC->second.iTick == 1)
      {
        SendLocalDeviceBroadcasts(itNIC);
        SendRemoteDeviceBroadcasts(itNIC);
        TriggerUnknownDevices(itNIC);

        itNIC->second.iTick = 0;
        itNIC->second.iFastBroadcastCnt--;
      }
    }
    else if(itNIC->second.iTick == 12)
    {
      TriggerUnknownDevices(itNIC);
      ClearUnknownDevices(itNIC);
    }
    else if(itNIC->second.iTick == 16)
    {
      SendLocalDeviceBroadcasts(itNIC);
    }
    else if(itNIC->second.iTick == 20)
    {
      SendRemoteDeviceBroadcasts(itNIC);
      itNIC->second.iTick = 0;
    }
  }
}

void CDlanMonitor::SendQueuedPackets(
  bool& bStillPacketsPending)
{
  for(std::map<CMACAddress,NetwAdapter>::iterator itNIC = m_mapNICs.begin(); 
    (itNIC != m_mapNICs.end()); ++itNIC)
  {
    if(!itNIC->second.queuePendingPackets.empty())
    {
      IPacket* pPacket = itNIC->second.queuePendingPackets.front();
      itNIC->second.queuePendingPackets.pop();

      m_ifc.SendPacket(itNIC->first, *pPacket);
      delete pPacket;

      if(!itNIC->second.queuePendingPackets.empty())
        bStillPacketsPending = true;
    }
  }
}

void CDlanMonitor::SendLocalDeviceBroadcasts(
  std::map<CMACAddress,NetwAdapter>::iterator itNIC)
{
  if((m_eMode & eMonitorLocalThunderbolt) == eMonitorLocalThunderbolt)
  {
    itNIC->second.queuePendingPackets.push(
      new HomePlugAvMMEs::ThunderReadModuleData::CRequest(CMACAddress(HomePlugAvMMEs::cIntellonLocalBroadcastAddr), 
      itNIC->first, HomePlugAvMMEs::ThunderReadModuleData::ePib, 64, 36));

    itNIC->second.queuePendingPackets.push(
      new HomePlugAvMMEs::ThunderNetworkInfo::CRequest(CMACAddress::Broadcast(), itNIC->first));
      
    itNIC->second.bNetworkInfoV1Sent = false;

    itNIC->second.queuePendingPackets.push(
      new HomePlugAvMMEs::ThunderGetVersion::CRequest(CMACAddress::Broadcast(), itNIC->first));

    itNIC->second.queuePendingPackets.push(
      new HomePlugAvMMEs::ThunderReadModuleData::CRequest(CMACAddress::Broadcast(), 
      itNIC->first, HomePlugAvMMEs::ThunderReadModuleData::ePib, 208, 36));
  }

  if((m_eMode & eMonitorLocalTurbo) == eMonitorLocalTurbo)
  {
    itNIC->second.queuePendingPackets.push(
      new HomePlugMMEs::TurboDeviceDescription::CRequest(CMACAddress::Broadcast(), itNIC->first));
  }

  if((m_eMode & eMonitorLocalHP1) == eMonitorLocalHP1)
  {
    itNIC->second.queuePendingPackets.push(
      new HomePlugMMEs::Int51NetStat::CRequest(CMACAddress::Broadcast(), itNIC->first));
  }
}


void CDlanMonitor::SendRemoteDeviceBroadcasts(
  std::map<CMACAddress,NetwAdapter>::iterator itNIC)
{
  size_t iAvDeviceCnt = 0;
  for(std::map<CMACAddress,LocalDevice>::iterator itLocalDevice = itNIC->second.mapLocalDevices.begin();
    (itLocalDevice != itNIC->second.mapLocalDevices.end()); ++itLocalDevice)
  {
    if(itLocalDevice->second.itPublicDevice->GetType() == CDlanDevice::eThunderbolt)
      iAvDeviceCnt++;
  }

  if(itNIC->second.mapLocalDevices.size() > iAvDeviceCnt)
  {
    if(((m_eMode & eMonitorHP1) == eMonitorHP1) || ((m_eMode & eMonitorTurbo) == eMonitorTurbo))
    {
      itNIC->second.queuePendingPackets.push(
        new HomePlugMMEs::ParamsAndStats::CRequest(CMACAddress::Broadcast(), itNIC->first));

      itNIC->second.queuePendingPackets.push(
        new HomePlugMMEs::TurboChannelCapacities::CRequest(CMACAddress::Broadcast(), itNIC->first, 
        HomePlugMMEs::TurboChannelCapacities::eDirectionFlagTxCaps));
    }
  }
}


/**
 * @Info    Send directed StatReqs to all unknown devices
 * @Result  -
 */
void CDlanMonitor::TriggerUnknownDevices(
  std::map<CMACAddress,NetwAdapter>::iterator itNIC)
{
  if(((m_eMode & eMonitorHP1) == eMonitorHP1) || ((m_eMode & eMonitorTurbo) == eMonitorTurbo))
  {
    itNIC->second.setDevicesToTrigger.insert(
      itNIC->second.setParamsAndStatsResponses.begin(), itNIC->second.setParamsAndStatsResponses.end());
    itNIC->second.setDevicesToTrigger.insert(
      itNIC->second.setRemoteTurboResponses.begin(), itNIC->second.setRemoteTurboResponses.end());

    for(std::set<CMACAddress>::iterator itDeviceToTrigger = itNIC->second.setDevicesToTrigger.begin();
      (itDeviceToTrigger != itNIC->second.setDevicesToTrigger.end()); ++itDeviceToTrigger)
    {
      bool bIsWellKnown = false;

      if(itNIC->second.mapLocalDevices.find(*itDeviceToTrigger) != itNIC->second.mapLocalDevices.end())
        bIsWellKnown = true;

      for(std::map<CMACAddress,LocalDevice>::iterator itLocalDevice = itNIC->second.mapLocalDevices.begin();
        (bIsWellKnown == false) && (itLocalDevice != itNIC->second.mapLocalDevices.end()); ++itLocalDevice)
      {
        if(itLocalDevice->second.mapRemoteDeviceAges.find(*itDeviceToTrigger) != itLocalDevice->second.mapRemoteDeviceAges.end())
          bIsWellKnown = true;
      }

      if(!bIsWellKnown)
      {
        itNIC->second.queuePendingPackets.push(
          new HomePlugMMEs::ParamsAndStats::CRequest(*itDeviceToTrigger, itNIC->first));
      }
    }

    for(std::map<CMACAddress,LocalDevice>::iterator itLocalDevice = itNIC->second.mapLocalDevices.begin();
      (itLocalDevice != itNIC->second.mapLocalDevices.end()); ++itLocalDevice)
    {
      for(std::map<CMACAddress,int>::iterator itRemoteDevice = itLocalDevice->second.mapRemoteDeviceAges.begin();
        (itRemoteDevice != itLocalDevice->second.mapRemoteDeviceAges.end()); ++itRemoteDevice)
      {
        if(itRemoteDevice->second >= m_timings.RemoteRefreshAge)
        {
          itNIC->second.queuePendingPackets.push(
            new HomePlugMMEs::ParamsAndStats::CRequest(itRemoteDevice->first, itNIC->first));
        }
      }
    }
  }

  if((m_eMode & eMonitorThunderbolt) == eMonitorThunderbolt)
  {
    std::set<CMACAddress> setGetVersion, setGetUserData;
    std::map<CMACAddress,std::string> mapUnknownGetVersionResponses = itNIC->second.mapGetVersionResponses;
  
    for(std::map<CMACAddress,NetworkInfoResponse>::const_iterator itNetworkInfo = itNIC->second.mapNetworkInfoResponses.begin();
      itNetworkInfo != itNIC->second.mapNetworkInfoResponses.end(); ++itNetworkInfo)
    {
      mapUnknownGetVersionResponses.erase(itNetworkInfo->first);
    
      for(std::list<HomePlugAvMMEs::ThunderNetworkInfo::StationInfo>::const_iterator itStation = itNetworkInfo->second.stations.begin();
        itStation != itNetworkInfo->second.stations.end(); ++itStation)
      {
        mapUnknownGetVersionResponses.erase(itStation->GetAddress());

        if(itNIC->second.mapGetVersionResponses.find(itStation->GetAddress()) == itNIC->second.mapGetVersionResponses.end())
          setGetVersion.insert(itStation->GetAddress());

        if(itNIC->second.mapUserDataResponses.find(itStation->GetAddress()) == itNIC->second.mapUserDataResponses.end())
          setGetUserData.insert(itStation->GetAddress());
      }
    }

    for(std::set<CMACAddress>::iterator it = setGetVersion.begin(); it != setGetVersion.end(); ++it)
    {
      itNIC->second.queuePendingPackets.push(new HomePlugAvMMEs::ThunderGetVersion::CRequest(*it, itNIC->first));
    }

    for(std::map<CMACAddress,std::string>::iterator it = mapUnknownGetVersionResponses.begin(); 
      it != mapUnknownGetVersionResponses.end(); ++it)
    {
      itNIC->second.queuePendingPackets.push(new HomePlugAvMMEs::ThunderGetVersion::CRequest(it->first, itNIC->first));
    }

    for(std::set<CMACAddress>::iterator it = setGetUserData.begin(); it != setGetUserData.end(); ++it)
    {
      itNIC->second.queuePendingPackets.push(new HomePlugAvMMEs::ThunderReadModuleData::CRequest(*it, itNIC->first, 
        HomePlugAvMMEs::ThunderReadModuleData::ePib, 208, 36));
    }
  }
}


void CDlanMonitor::ClearUnknownDevices(
  std::map<CMACAddress,NetwAdapter>::iterator itNIC)
{
  itNIC->second.setParamsAndStatsResponses.clear();
  itNIC->second.setRemoteTurboResponses.clear();
  itNIC->second.setDevicesToTrigger.clear();
  itNIC->second.setReadModDataResponses.clear();
  itNIC->second.mapGetVersionResponses.clear();
  itNIC->second.mapUserDataResponses.clear();
  itNIC->second.mapNetworkInfoResponses.clear();
}


CDlanMonitor::LocalDevice& CDlanMonitor::UpdateLocalDevice(
  std::map<CMACAddress,NetwAdapter>::iterator itNIC,
  const CMACAddress& addr,
  bool bResetAge,
  CDlanDevice::teType type,
  bool bKeepType,
  const std::string& version,
  bool bKeepVersion,
  const UserDataResponse& userData,
  bool bKeepUserData,
  const CMACAddress& cco,
  bool bKeepCCo,
  bool& bUpdate)
{
  std::map<CMACAddress,LocalDevice>::iterator itDevice = itNIC->second.mapLocalDevices.find(addr);

  if(itDevice == itNIC->second.mapLocalDevices.end())
  {
    bUpdate = true;

    CDlanLocalDeviceList::iterator itPubDevice = m_listLocalDevices.begin();
    for( ; itPubDevice != m_listLocalDevices.end(); itPubDevice++)
      if((itPubDevice->GetNICAddress() > itNIC->first) || (itPubDevice->GetAddress() > addr))
        break;

    CDlanLocalDevice localDevice(itNIC->first, addr, type, version, 
      userData.strMft, userData.strUser, userData.strAvln, cco);
    itPubDevice = m_listLocalDevices.insert(itPubDevice, localDevice);
    itDevice = itNIC->second.mapLocalDevices.insert(std::make_pair(addr, LocalDevice(itPubDevice))).first;

    if(itNIC->second.iFastBroadcastCnt > 2)
      itNIC->second.iFastBroadcastCnt = 2;
  }
  else 
  {
    if(bResetAge)
      itDevice->second.iAge = 0;

    CDlanLocalDevice updatedDevice(itNIC->first, addr,
      bKeepType ? itDevice->second.itPublicDevice->GetType() : type,
      bKeepVersion ? itDevice->second.itPublicDevice->GetVersion() : version,
      bKeepUserData ? itDevice->second.itPublicDevice->GetManufacturingString() : userData.strMft,
      bKeepUserData ? itDevice->second.itPublicDevice->GetUserDeviceName() : userData.strUser,
      bKeepUserData ? itDevice->second.itPublicDevice->GetUserNetworkName() : userData.strAvln,
      bKeepCCo ? itDevice->second.itPublicDevice->GetCCoAddress() : cco,
      itDevice->second.itPublicDevice->GetRemoteDevices());
  
    if(*itDevice->second.itPublicDevice != updatedDevice)
    {
      bUpdate = true;
      *itDevice->second.itPublicDevice = updatedDevice;
    }
  }

  if(userData.strMft.size() > 0)
    itDevice->second.mapUserDataAges[addr] = 0;

  return itDevice->second; 
}

void CDlanMonitor::UpdateRemoteDevice(
  LocalDevice& localDevice,
  const CMACAddress& addr,
  bool bResetAge,
  CDlanDevice::teType type,
  bool bKeepType,
  const std::string& version,
  bool bKeepVersion,
  const UserDataResponse& userData,
  bool bKeepUserData,
  double tx,
  double rx,
  bool bKeepRates,
  const std::map<CMACAddress, CDlanDataRates>& remoteDataRates,
  bool bKeepRemoteRates,
  const CMACAddress& firstBridgedAddr,
  bool bKeepBrdgAddr,
  bool& bUpdate)
{
  CDlanRemoteDeviceList::const_iterator itPublicRemoteDevice = localDevice.itPublicDevice->GetRemoteDevices().begin();
  for( ; itPublicRemoteDevice != localDevice.itPublicDevice->GetRemoteDevices().end(); ++itPublicRemoteDevice)
  {
    if(itPublicRemoteDevice->GetAddress() == addr)
      break;
  }
  
  if(itPublicRemoteDevice == localDevice.itPublicDevice->GetRemoteDevices().end())
  {
    bUpdate = true;

    CDlanRemoteDevice remoteDevice(addr, type, version, 
      userData.strMft, userData.strUser, userData.strAvln, tx, rx, 
      remoteDataRates, std::set<CMACAddress>(&firstBridgedAddr, &firstBridgedAddr+ 1));
    localDevice.itPublicDevice->UpdateRemoteDevice(remoteDevice);
  }
  else
  {
    CDlanRemoteDevice remoteDevice(addr, 
      bKeepType ? itPublicRemoteDevice->GetType() : type,
      bKeepVersion ? itPublicRemoteDevice->GetVersion() : version,
      bKeepUserData ? itPublicRemoteDevice->GetManufacturingString() : userData.strMft,
      bKeepUserData ? itPublicRemoteDevice->GetUserDeviceName() : userData.strUser,
      bKeepUserData ? itPublicRemoteDevice->GetUserNetworkName() : userData.strAvln,
      bKeepRates ? itPublicRemoteDevice->GetTxRate() : tx,
      bKeepRates ? itPublicRemoteDevice->GetRxRate() : rx,
      bKeepRemoteRates ? itPublicRemoteDevice->GetRemoteRates() : remoteDataRates,
      bKeepBrdgAddr ? itPublicRemoteDevice->GetBridgedAddresses() : std::set<CMACAddress>(&firstBridgedAddr, &firstBridgedAddr + 1));
      
    if(localDevice.itPublicDevice->UpdateRemoteDevice(remoteDevice))
      bUpdate = true;
  }

  if(bResetAge)
    localDevice.mapRemoteDeviceAges[addr] = 0;
  
  if(userData.strMft.size() > 0)
    localDevice.mapUserDataAges[addr] = 0;
}

void CDlanMonitor::OnParamsAndStatsResponse(
  const CMACAddress& adapter,
  const HomePlugMMEs::ParamsAndStats::CResponse& mme)
{
  std::map<CMACAddress,NetwAdapter>::iterator itNIC;

  if((itNIC = m_mapNICs.find(adapter)) != m_mapNICs.end())
  {
    itNIC->second.setParamsAndStatsResponses.insert(mme.GetAddress());
  }
}


void CDlanMonitor::OnInt51NetStatResponse(
  const CMACAddress& adapter, 
  const HomePlugMMEs::Int51NetStat::CResponse& mme)
{
  std::map<CMACAddress,NetwAdapter>::iterator itNIC;

  if((itNIC = m_mapNICs.find(adapter)) != m_mapNICs.end())
  {
    bool bUpdate = false;

    LocalDevice& localDevice = UpdateLocalDevice(itNIC, mme.GetAddress(), true, 
      CDlanDevice::eHP1, false, "", false, UserDataResponse(), true, CMACAddress::Null(), false, bUpdate);

    std::list<HomePlugMMEs::Int51NetStat::Destination> listDestinations = mme.GetDestinations();
    for(std::list<HomePlugMMEs::Int51NetStat::Destination>::iterator itDest = listDestinations.begin();
      (itDest != listDestinations.end()); itDest++)
    {
      if(itDest->GetAddress() != CMACAddress::Null())
      {
        if(itDest->IsToneMapValid())
        {
          bool bTurbo =
            itNIC->second.setRemoteTurboResponses.find(itDest->GetAddress()) != itNIC->second.setRemoteTurboResponses.end();

          UpdateRemoteDevice(localDevice, itDest->GetAddress(), true, 
            bTurbo ? CDlanDevice::eTurbo : CDlanDevice::eHP1, !bTurbo, "", false, UserDataResponse(), true, 
            itDest->GetTxRate(), 0.0, false, std::map<CMACAddress, CDlanDataRates>(), true, CMACAddress(), true, bUpdate);
        }
        else
        {
          itNIC->second.setDevicesToTrigger.insert(itDest->GetAddress());
        }
      }
    }

    if(bUpdate)
      OnUpdate();
  }
}

void CDlanMonitor::OnTurboDeviceDescriptionResponse(
  const CMACAddress& adapter, 
  const HomePlugMMEs::TurboDeviceDescription::CResponse& mme)
{
  std::map<CMACAddress,NetwAdapter>::iterator itNIC;

  if((itNIC = m_mapNICs.find(adapter)) != m_mapNICs.end())
  {
    bool bUpdate = false;

    if(mme.IsRemote())
    {
      for(std::map<CMACAddress,LocalDevice>::iterator itLocalDevice = itNIC->second.mapLocalDevices.begin();
        (itLocalDevice != itNIC->second.mapLocalDevices.end()); ++itLocalDevice)
      {
        if(itLocalDevice->second.mapRemoteDeviceAges.find(mme.GetAddress()) != itLocalDevice->second.mapRemoteDeviceAges.end())
        {
          UpdateRemoteDevice(itLocalDevice->second, mme.GetAddress(), true, CDlanDevice::eTurbo, false, "", false, 
            UserDataResponse(mme.GetManufacturer() + " " + mme.GetProductName()), false, 0.0, 0.0, true, 
            std::map<CMACAddress, CDlanDataRates>(), true, CMACAddress(), true, bUpdate);
          break;
        }
      }

      itNIC->second.setRemoteTurboResponses.insert(mme.GetAddress());
    }
    else
    {
      UpdateLocalDevice(itNIC, mme.GetAddress(), true, CDlanDevice::eTurbo, false, "", false, 
        mme.GetManufacturer() + " " + mme.GetProductName(), false, CMACAddress::Null(), false, bUpdate);
    }

    if(bUpdate)
      OnUpdate();
  }
}

void CDlanMonitor::OnTurboChannelCapacitiesResponse(
  const CMACAddress& adapter, 
  const HomePlugMMEs::TurboChannelCapacities::CResponse& mme)
{
  std::map<CMACAddress,NetwAdapter>::iterator itNIC;
  std::map<CMACAddress,LocalDevice>::iterator itDevice; 
  
  if(((itNIC = m_mapNICs.find(adapter)) != m_mapNICs.end()) &&
    ((itDevice = itNIC->second.mapLocalDevices.find(mme.GetAddress())) != itNIC->second.mapLocalDevices.end()))
  {
    bool bUpdate = false;

    std::list<HomePlugMMEs::TurboChannelCapacities::TxCap> listCaps = mme.GetTxCapacities();
    for(std::list<HomePlugMMEs::TurboChannelCapacities::TxCap>::iterator itCap = listCaps.begin(); 
      (itCap != listCaps.end()); itCap++)
    {
      bool bUnknown =
        itNIC->second.setParamsAndStatsResponses.find(itCap->GetAddress()) != itNIC->second.setParamsAndStatsResponses.end();

      bool bTurbo =
        itNIC->second.setRemoteTurboResponses.find(itCap->GetAddress()) != itNIC->second.setRemoteTurboResponses.end();

      if(bUnknown || bTurbo)
      {
        UpdateRemoteDevice(itDevice->second, itCap->GetAddress(), true,
          bTurbo ? CDlanDevice::eTurbo : CDlanDevice::eHP1, !bTurbo, "", false, UserDataResponse(), true, 
          itCap->GetTxRate(), 0.0, false, 
          std::map<CMACAddress, CDlanDataRates>(), true, CMACAddress(), true, bUpdate);
      }
      else
      {
        itNIC->second.setDevicesToTrigger.insert(itCap->GetAddress());
      }
    }
    
    if(bUpdate)
      OnUpdate();
  }
}

void CDlanMonitor::OnThunderReadModuleDataConfirm(
  const CMACAddress& adapter, 
  const HomePlugAvMMEs::ThunderReadModuleData::CConfirm& mme)
{
  std::map<CMACAddress,NetwAdapter>::iterator itNIC;

  if(((itNIC = m_mapNICs.find(adapter)) != m_mapNICs.end()) &&
    (mme.GetStatus() == HomePlugAvMMEs::ThunderReadModuleData::eSuccess) &&
    (mme.GetModuleID() == HomePlugAvMMEs::ThunderReadModuleData::ePib))
  {
    bool bUpdate = false;

    if((mme.GetLength() == 64) && (mme.GetOffset() == 36))
    {
      itNIC->second.setReadModDataResponses.insert(mme.GetAddress());

      std::map<CMACAddress,UserDataResponse>::iterator itUserData = itNIC->second.mapUserDataResponses.find(mme.GetAddress());
      bool bKeepUserData = (itUserData == itNIC->second.mapUserDataResponses.end());

      std::map<CMACAddress,std::string>::const_iterator itVersion;
      if((itVersion = itNIC->second.mapGetVersionResponses.find(mme.GetAddress())) != itNIC->second.mapGetVersionResponses.end())
      {
        UpdateLocalDevice(itNIC, mme.GetAddress(), true, CDlanDevice::eThunderbolt, false,
          itVersion->second, false, bKeepUserData ? UserDataResponse() : itUserData->second, bKeepUserData, 
          CMACAddress::Null(), true, bUpdate);
      }
    }
    else if((mme.GetLength() == 208) && (mme.GetOffset() == 36))
    {
      UserDataResponse userData(mme.GetData());

      itNIC->second.mapUserDataResponses[mme.GetAddress()] = userData;

      if(itNIC->second.mapLocalDevices.find(mme.GetAddress()) != itNIC->second.mapLocalDevices.end())
      {
        UpdateLocalDevice(itNIC, mme.GetAddress(), false,
          CDlanDevice::eThunderbolt, true, "", true, userData, false, CMACAddress::Null(), true, bUpdate);
      }
      else
      {
        for(std::map<CMACAddress,LocalDevice>::iterator itLocalDevice = itNIC->second.mapLocalDevices.begin();
          (itLocalDevice != itNIC->second.mapLocalDevices.end()); ++itLocalDevice)
        {
          if(itLocalDevice->second.mapRemoteDeviceAges.find(mme.GetAddress()) != itLocalDevice->second.mapRemoteDeviceAges.end())
          {
            UpdateRemoteDevice(itLocalDevice->second, mme.GetAddress(), false,
              CDlanDevice::eThunderbolt, true, "", true, userData, false, 0.0, 0.0, true,
              std::map<CMACAddress, CDlanDataRates>(), true, CMACAddress(), true, bUpdate);
            break;
          }
        }
      }
    }

    if(bUpdate)
      OnUpdate();
  }
}


void CDlanMonitor::OnThunderGetVersionConfirm(
  const CMACAddress& adapter, 
  const HomePlugAvMMEs::ThunderGetVersion::CConfirm& mme)
{
  std::map<CMACAddress,NetwAdapter>::iterator itNIC;

  if(((itNIC = m_mapNICs.find(adapter)) != m_mapNICs.end()) &&
    (mme.GetStatus() == HomePlugAvMMEs::ThunderGetVersion::eSuccess))
  {
    bool bUpdate = false;

    itNIC->second.mapGetVersionResponses[mme.GetAddress()] = mme.GetVersion();

    std::map<CMACAddress,UserDataResponse>::iterator itUserData = itNIC->second.mapUserDataResponses.find(mme.GetAddress());
    bool bKeepUserData = (itUserData == itNIC->second.mapUserDataResponses.end());
    
    std::map<CMACAddress,NetworkInfoResponse>::const_iterator itNetworkInfo = itNIC->second.mapNetworkInfoResponses.find(mme.GetAddress());
    bool bKeepCCo = (itNetworkInfo == itNIC->second.mapNetworkInfoResponses.end());

    if(itNIC->second.setReadModDataResponses.find(mme.GetAddress()) != itNIC->second.setReadModDataResponses.end())
    {
      UpdateLocalDevice(itNIC, mme.GetAddress(), true, CDlanDevice::eThunderbolt, false, 
        mme.GetVersion(), false, bKeepUserData ? UserDataResponse() : itUserData->second, bKeepUserData, 
        bKeepCCo ? CMACAddress::Null() : itNetworkInfo->second.ccoAddr, bKeepCCo, bUpdate);
    }
    else
    {
      bool bDone = false;
      for(itNetworkInfo = itNIC->second.mapNetworkInfoResponses.begin();
        !bDone && (itNetworkInfo != itNIC->second.mapNetworkInfoResponses.end()); ++itNetworkInfo)
      {
        std::map<CMACAddress,LocalDevice>::iterator itLocalDevice = itNIC->second.mapLocalDevices.find(itNetworkInfo->first);
        if(itLocalDevice != itNIC->second.mapLocalDevices.end())
        {
          for(std::list<HomePlugAvMMEs::ThunderNetworkInfo::StationInfo>::const_iterator itStation = itNetworkInfo->second.stations.begin();
            !bDone && (itStation != itNetworkInfo->second.stations.end()); ++itStation)
          {
            if(itStation->GetAddress() == mme.GetAddress())
            {
              UpdateRemoteDevice(itLocalDevice->second, itStation->GetAddress(), true,
                CDlanDevice::eThunderbolt, false, mme.GetVersion(), false, 
                bKeepUserData ? UserDataResponse() : itUserData->second, bKeepUserData,
                itStation->GetTxRawRate(), itStation->GetRxRawRate(), false, 
                std::map<CMACAddress, CDlanDataRates>(), true, itStation->GetFirstBridgedAddress(), false, bUpdate);
              bDone = true;
            }
          }
        }
      }
    }

    if(bUpdate)
      OnUpdate();
  }
}

void CDlanMonitor::OnThunderNetworkInfoConfirm(
  const CMACAddress& adapter, 
  const HomePlugAvMMEs::ThunderNetworkInfo::CConfirm& mme)
{
  std::map<CMACAddress,NetwAdapter>::iterator itNIC;
  
  if((itNIC = m_mapNICs.find(adapter)) != m_mapNICs.end())
  {

    NetworkInfoResponse nwinfo(mme.GetCCoAddress(), mme.GetStations());

    std::list<HomePlugAvMMEs::ThunderNetworkInfo::StationInfo>::const_iterator itStation = nwinfo.stations.begin();
    for( ; (itStation != nwinfo.stations.end()); itStation++)
    {
      if((itStation->GetTxCodedRate() == 255) || (itStation->GetRxCodedRate() == 255))
        break;
    }
    if(itStation == nwinfo.stations.end())
    {
      ThunderNetworkInfo(itNIC, mme.GetAddress(), nwinfo);
    }
    else if(!itNIC->second.bNetworkInfoV1Sent)
    {
      itNIC->second.bNetworkInfoV1Sent = true;
      itNIC->second.queuePendingPackets.push(
        new HomePlugAvMMEs::ThunderNetworkInfoV1::CRequest(CMACAddress::Broadcast(), itNIC->first));
    }
  }
}


void CDlanMonitor::OnThunderNetworkInfoV1Confirm(
  const CMACAddress& adapter, 
  const HomePlugAvMMEs::ThunderNetworkInfoV1::CConfirm& mme)
{
  std::map<CMACAddress,NetwAdapter>::iterator itNIC;

  if((itNIC = m_mapNICs.find(adapter)) != m_mapNICs.end())
    ThunderNetworkInfo(itNIC, mme.GetAddress(), NetworkInfoResponse(mme.GetCCoAddress(), mme.GetStations()));
}

void CDlanMonitor::ThunderNetworkInfo(
  std::map<CMACAddress,NetwAdapter>::iterator itNIC,  
  const CMACAddress& addr, 
  const NetworkInfoResponse& nwinfo)
{
  bool bUpdate = false;
    
  itNIC->second.mapNetworkInfoResponses[addr] = nwinfo;
    
  std::map<CMACAddress,LocalDevice>::iterator itLocalDevice = itNIC->second.mapLocalDevices.find(addr);
  if(itLocalDevice != itNIC->second.mapLocalDevices.end())
  {
    for(std::list<HomePlugAvMMEs::ThunderNetworkInfo::StationInfo>::const_iterator itStation = nwinfo.stations.begin();
      (itStation != nwinfo.stations.end()); itStation++)
    {
      std::map<CMACAddress,std::string>::const_iterator itVersion;
      if((itVersion = itNIC->second.mapGetVersionResponses.find(itStation->GetAddress())) != 
        itNIC->second.mapGetVersionResponses.end())
      {
        std::map<CMACAddress,UserDataResponse>::iterator itUserData = itNIC->second.mapUserDataResponses.find(itStation->GetAddress());
        bool bKeepUserData = (itUserData == itNIC->second.mapUserDataResponses.end());

        UpdateRemoteDevice(itLocalDevice->second, itStation->GetAddress(), true,
          CDlanDevice::eThunderbolt, false, itVersion->second, false, 
          bKeepUserData ? UserDataResponse() : itUserData->second, bKeepUserData,
          itStation->GetTxRawRate(), itStation->GetRxRawRate(), false, 
          std::map<CMACAddress, CDlanDataRates>(), true, itStation->GetFirstBridgedAddress(), false, bUpdate);
      }
    }
  }
  else
  {
    for(std::map<CMACAddress,LocalDevice>::iterator itLocalDevice = itNIC->second.mapLocalDevices.begin();
      (itLocalDevice != itNIC->second.mapLocalDevices.end()); ++itLocalDevice)
    {
      if(itLocalDevice->second.mapRemoteDeviceAges.find(addr) != itLocalDevice->second.mapRemoteDeviceAges.end())
      {
        std::map<CMACAddress, CDlanDataRates> remoteDataRates;
        for(std::list<HomePlugAvMMEs::ThunderNetworkInfo::StationInfo>::const_iterator itStation = nwinfo.stations.begin(); 
          (itStation != nwinfo.stations.end()); itStation++)
        {
          remoteDataRates[itStation->GetAddress()] = CDlanDataRates(itStation->GetTxRawRate(), itStation->GetRxRawRate());
        }
        
        UpdateRemoteDevice(itLocalDevice->second, addr, false, CDlanDevice::eThunderbolt, false, 
          "", true, UserDataResponse(), true, 0.0, 0.0, true, remoteDataRates, false, CMACAddress(), true, bUpdate);

        break;
      }
    }

    if(bUpdate)
      OnUpdate();
  }
}

CDlanMonitor::~CDlanMonitor()
{
  bool bUpdate = false;
  UpdateAdapters(bUpdate);
}
