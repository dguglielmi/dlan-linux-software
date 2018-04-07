
//
// (c) 2009 devolo AG, Aachen (Germany)
//

#include <stdio.h>
#include <fstream>
#include <sstream>
#include <string>
#include "../common/mscounter.h"
#include "../common/dlanmonitor.h"
#include "../common/hpsecurity.h"
#include "../common/packetinterface-linux.h"

struct CFindLocalDevice : public IDlanMonitorObserver, public CDlanMonitor
{
  bool stop;
  IPacketInterface& ifc;
  CMACAddress& devToFind;
  CDlanLocalDeviceList::const_iterator itDevice;

  CFindLocalDevice(IPacketInterface& i, CMACAddress& d) : 
    stop(false), ifc(i), devToFind(d), itDevice(GetLocalDevices().end()), CDlanMonitor(i, *this) {}

  virtual void OnUpdate()
  {
    if(devToFind)
    {
      for(CDlanLocalDeviceList::const_iterator itLocal = GetLocalDevices().begin(); 
        !stop && (itLocal != GetLocalDevices().end()); ++itLocal)
      {
        if(itLocal->GetAddress() == devToFind)
        {
          itDevice = itLocal;
          stop = true;
          ifc.StopReceiving();
        }
      }
    }
    else if(GetLocalDevices().size() > 0)
    {
      itDevice = GetLocalDevices().begin();
      stop = true;
      ifc.StopReceiving();
    }
  }

  virtual bool Complete() { return stop; }
  virtual bool Successful() { return stop; }
};

int main(int argc, char** argv)
{
  int result = 0;
  CMACAddress addrDevice;
  
  if((argc < 3) || !addrDevice.FromString(argv[1]))
  {
    printf("Usage: dlanpasswd MAC-ADDRESS PASSWORD\n"
           "   or: dlanpasswd MAC-ADDRESS PASSWORD SECURITY-ID\n"
           "\n"
           "In the 1st form, assign PASSWORD to the local dLAN adapter MAC-ADDRESS.\n"
           "\n"    
           "In the 2nd form, assign PASSWORD to the remote dLAN 200 AV adapter identified \n"
           "by SECURITY-ID, using the local dLAN 200 AV adapter MAC-ADDRESS to forward the\n"
           "request to the PowerLine.\n"
           "\n");
           
    result = -1;
  }
  else
  {
    std::string strPassword = argv[2];
    std::string strSecurityID = (argc > 3) ? argv[3] : "";

    CPacketInterfaceLinux pktIfc;
    CFindLocalDevice finder(pktIfc, addrDevice);
    if(CPacketTaskRunner(pktIfc, finder).Run(3000, MSCounter()))
    {
      if(finder.itDevice->GetType() == CDlanDevice::eThunderbolt)
      {
        if(strSecurityID.empty())
        {
          printf("assigning password to local device %s: ", 
            finder.itDevice->GetAddress().ToString().c_str());
            
          HomePlugAvSecurity::CSetKeyTask setKey(pktIfc,
            finder.itDevice->GetNICAddress(), finder.itDevice->GetAddress(), strPassword);

          if(CPacketTaskRunner(pktIfc, setKey).Run())
          {
            printf("OK\n");
          }
          else
          {
            printf("failed\n");
            result = 2;          
          }
        }
        else
        {
          printf("assigning password to remote device %s via %s: ", 
            strSecurityID.c_str(), finder.itDevice->GetAddress().ToString().c_str());
            
          HomePlugAvSecurity::CSetKeyTask setKey(pktIfc, 
            finder.itDevice->GetNICAddress(), finder.itDevice->GetAddress(), strPassword, 
            CMACAddress::Broadcast(), strSecurityID);

          if(CPacketTaskRunner(pktIfc, setKey).Run())
          {
            printf("OK\n");
          }
          else
          {
            printf("failed\n");
            result = 2;          
          }
        }
      }
      else
      {
        if(strSecurityID.empty())
        {
          printf("assigning password to local device %s: ", 
            finder.itDevice->GetAddress().ToString().c_str());
            
          HomePlugSecurity::CSetKeyTask setKey(pktIfc, 
            finder.itDevice->GetNICAddress(), finder.itDevice->GetAddress(), strPassword);

          if(CPacketTaskRunner(pktIfc, setKey).Run())
          {
            printf("OK\n");
          }
          else
          {
            printf("failed\n");
            result = 2;          
          }
        }
        else
        {
          printf("error: assigning remote password is only supported for dLAN 200 AV devices\n");
          result = 3;
        }
      }
    }
    else
    {
      printf("no device found\n");
      result = 1;
    }
  }

  return result;
}
