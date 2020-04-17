
//
// (c) 2008-2009 devolo AG, Aachen (Germany)
//

#include <cstdio>
#include "../common/mscounter.h"
#include "../common/dlanmonitor.h"
#include "../common/packetinterface-linux.h"

std::string VersionProductString(const CDlanDevice& device)
{
  if(device.GetType() == CDlanDevice::eThunderbolt)
  {
    return device.GetVersion() + " " + device.GetManufacturingString();
  }
  else if(!device.GetManufacturingString().empty())
  {
    return device.GetManufacturingString();
  }
  else if(device.GetType() == CDlanDevice::eTurbo)
  {
    return "devolo dLAN Highspeed";
  }
  else
  {
    return "devolo dLAN";
  }
}

int main(int argc, char** argv)
{
  int result = 0;
  std::set<std::string> setIfcNames;

  for(int i = 1; i < argc; ++i)
  {
    if(argv[i][0] == '-')
      result = -1;
    else
      setIfcNames.insert(argv[i]);
  }
  
  if(result == -1)
  {
    printf("Usage: dlanlist [IFACES...]\n"
           "\n"
           "List dlan devices found on the given network interfaces,\n"
           "or on all interfaces, if none where given.\n"
           "\n");

    return result;
  }

 CPacketInterfaceLinux pktIfc(setIfcNames);
 CDlanMonitor m(pktIfc);
 CPacketTaskRunner(pktIfc, m).Run(1000, MSCounter());

 if(m.GetLocalDevices().empty())
 {
   printf("no devices found\n");
   return 1;
 }

  printf("Type    MAC address        Mbps TX/RX       Version/Product\n");
  for(CDlanLocalDeviceList::const_iterator itLocal = m.GetLocalDevices().begin();
    (itLocal != m.GetLocalDevices().end()); ++itLocal)
  {
    printf("local   %s  ---.-- / ---.--  %s\n",
      itLocal->GetAddress().ToString().c_str(),
      VersionProductString(*itLocal).c_str());
 
    for(CDlanRemoteDeviceList::const_iterator itRemote = itLocal->GetRemoteDevices().begin();
      (itRemote != itLocal->GetRemoteDevices().end()); ++itRemote)
    {
      if(itRemote->GetType() == CDlanDevice::eThunderbolt)
      {
        printf("remote  %s  %6.02f / %6.02f  %s\n",
          itRemote->GetAddress().ToString().c_str(),
          itRemote->GetTxRate(),
          itRemote->GetRxRate(),
          itRemote->GetVersion().c_str());
      }
      else
      {
        printf("remote  %s  %6.02f / ---.--  %s\n",
          itRemote->GetAddress().ToString().c_str(),
          itRemote->GetTxRate(),
          VersionProductString(*itRemote).c_str());
      }
    }
  }
  
  return result;
}
