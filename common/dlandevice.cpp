
//
// (c) 2006-2009 devolo AG, Aachen (Germany)
//

#include "dlandevice.h"

bool CDlanLocalDevice::UpdateRemoteDevice(
  const CDlanRemoteDevice& remoteDevice)
{
  bool bResult = false;

  CDlanRemoteDeviceList::iterator itDevice = m_remoteDeviceList.begin();
  for( ; (itDevice != m_remoteDeviceList.end()); itDevice++)
  {
    if(itDevice->GetAddress() >= remoteDevice.GetAddress())
      break;
  }
  
  if((itDevice == m_remoteDeviceList.end()) || (itDevice->GetAddress() != remoteDevice.GetAddress()))
  {
    m_remoteDeviceList.insert(itDevice, remoteDevice);
    bResult = true;
  }
  else if(*itDevice != remoteDevice)
  {
    *itDevice = remoteDevice;
    bResult = true;
  }

  return bResult;
}

bool CDlanLocalDevice::RemoveRemoteDevice(
  const CMACAddress& remoteDeviceAddr)
{
  for(CDlanRemoteDeviceList::iterator itDevice = m_remoteDeviceList.begin();
    itDevice != m_remoteDeviceList.end(); ++itDevice)
  {
    if(itDevice->GetAddress() == remoteDeviceAddr)
    {
      m_remoteDeviceList.erase(itDevice);
      return true;
    }
  }
  
  return false;
}
