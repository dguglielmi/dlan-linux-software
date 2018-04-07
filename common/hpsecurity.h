
//
// (c) 2006-2010 devolo AG, Aachen (Germany)
//

#ifndef _DLAN_HPSECURITY_H_
#define _DLAN_HPSECURITY_H_

#include <string>
#include <list>
#include <map>
#include "hpmmes.h"
#include "macheader.h"
#include "packetinterface.h"
#include "packettask.h"

namespace HomePlugSecurity
{
  class CSetKeyTask
  : public IPacketTask, private HomePlugMMEs::CDispatcher, private IPacketWaiter
  {
  public:

    CSetKeyTask(
      IPacketInterface& ifc,               
      const CMACAddress& addrNIC,          
      const CMACAddress& addrLocalDevice,  
      const unsigned char cKEY[8],         
      unsigned long ulTimeout = 5000)      
      :
      m_ifc(ifc), m_addrNIC(addrNIC), m_addrLocalDev(addrLocalDevice),
      m_req(addrLocalDevice, addrNIC, 1, cKEY),
      m_ulTimeout(ulTimeout), m_ulRetryTimer(1000),
      m_bSuccessful(false), m_iRetries(0) { m_receiver.AddDispatcher(*this); m_receiver.AddWaiter(*this); }
      
    CSetKeyTask(
      IPacketInterface& ifc,               
      const CMACAddress& addrNIC,          
      const CMACAddress& addrLocalDevice,  
      const std::string& strPassword,      
      unsigned long ulTimeout = 5000)      
      :
      m_ifc(ifc), m_addrNIC(addrNIC), m_addrLocalDev(addrLocalDevice),
      m_req(addrLocalDevice, addrNIC, 1, strPassword),
      m_ulTimeout(ulTimeout), m_ulRetryTimer(1000),
      m_bSuccessful(false), m_iRetries(0) { m_receiver.AddDispatcher(*this); m_receiver.AddWaiter(*this); }

    virtual IPacketReceiver& GetReceiver() { return m_receiver; }
    virtual unsigned long Drumbeat();
    virtual bool Complete() { return m_bSuccessful || (m_iRetries > (m_ulTimeout / m_ulRetryTimer)); }
    virtual bool Successful() { return m_bSuccessful; }
    virtual ~CSetKeyTask() {}
    
  private:
    
    IPacketInterface& m_ifc;
    CMACAddress m_addrNIC, m_addrLocalDev;
    HomePlugMMEs::SetNetworkEncKey::CRequest m_req;
    unsigned long m_ulTimeout, m_ulRetryTimer;
    bool m_bSuccessful;
    size_t m_iRetries;
    CPacketReceiverAndDispatcher m_receiver;
    virtual bool WaitSatisfied() const { return (m_iRetries == 0); }
    virtual void OnSetNetworkEncKeyConfirm(const CMACAddress&, const HomePlugMMEs::SetNetworkEncKey::CConfirm&);
  };
}

namespace HomePlugAvSecurity
{
  class CSetKeyTask
  : public IPacketTask, private HomePlugAvMMEs::CDispatcher, private IPacketWaiter
  {
  public:

    CSetKeyTask(
      IPacketInterface& ifc,              
      const CMACAddress& addrNIC,         
      const CMACAddress& addrLocalDevice, 
      const unsigned char cKEY[16],       
      unsigned long ulTimeout = 5000,     
      bool bPreMac15 = false)             
      :
      m_ifc(ifc), m_addrNIC(addrNIC), m_addrLocalDev(addrLocalDevice),
      m_req(addrLocalDevice, addrNIC, cKEY, bPreMac15),
      m_ulTimeout(ulTimeout), m_ulRetryTimer(1000),
      m_bSuccessful(false), m_iRetries(0) { m_receiver.AddDispatcher(*this); m_receiver.AddWaiter(*this); }
    
    CSetKeyTask(
      IPacketInterface& ifc,                
      const CMACAddress& addrNIC,           
      const CMACAddress& addrLocalDevice,   
      const std::string& strPassword,       
      unsigned long ulTimeout = 5000,       
      bool bPreMac15 = false)               
      :
      m_ifc(ifc), m_addrNIC(addrNIC), m_addrLocalDev(addrLocalDevice),
      m_req(addrLocalDevice, addrNIC, strPassword, bPreMac15),
      m_ulTimeout(ulTimeout), m_ulRetryTimer(1000),
      m_bSuccessful(false), m_iRetries(0) { m_receiver.AddDispatcher(*this); m_receiver.AddWaiter(*this); }

    CSetKeyTask(
      IPacketInterface& ifc,                
      const CMACAddress& addrNIC,           
      const CMACAddress& addrLocalDevice,   
      const unsigned char cKEY[16],         
      const unsigned char cDAK[16],         
      unsigned long ulTimeout = 5000,       
      bool bPreMac15 = false)               
      :
      m_ifc(ifc), m_addrNIC(addrNIC), m_addrLocalDev(addrLocalDevice), m_addrRemoteDev(CMACAddress::Broadcast()),
      m_req(addrLocalDevice, addrNIC, cKEY, cDAK, CMACAddress::Broadcast(), bPreMac15),
      m_ulTimeout(ulTimeout), m_ulRetryTimer(1000),
      m_bSuccessful(false), m_iRetries(0) { m_receiver.AddDispatcher(*this); m_receiver.AddWaiter(*this); }
    
    CSetKeyTask(
      IPacketInterface& ifc,                
      const CMACAddress& addrNIC,           
      const CMACAddress& addrLocalDevice,   
      const std::string& strPassword,       
      const std::string& strSecurityID,     
      unsigned long ulTimeout = 5000,       
      bool bPreMac15 = false)               
      :
      m_ifc(ifc), m_addrNIC(addrNIC), m_addrLocalDev(addrLocalDevice), m_addrRemoteDev(CMACAddress::Broadcast()),
      m_req(addrLocalDevice, addrNIC, strPassword, strSecurityID, CMACAddress::Broadcast(), bPreMac15),
      m_ulTimeout(ulTimeout), m_ulRetryTimer(1000),
      m_bSuccessful(false), m_iRetries(0) { m_receiver.AddDispatcher(*this); m_receiver.AddWaiter(*this); }
      
    CSetKeyTask(
      IPacketInterface& ifc,                
      const CMACAddress& addrNIC,           
      const CMACAddress& addrLocalDevice,   
      const unsigned char cKEY[16],         
      const CMACAddress& addrRemoteDevice,  
      const unsigned char cDAK[16],         
      unsigned long ulTimeout = 5000,       
      bool bPreMac15 = false)               
      :
      m_ifc(ifc), m_addrNIC(addrNIC), m_addrLocalDev(addrLocalDevice), m_addrRemoteDev(addrRemoteDevice),
      m_req(addrLocalDevice, addrNIC, cKEY, cDAK, addrRemoteDevice, bPreMac15),
      m_ulTimeout(ulTimeout), m_ulRetryTimer(1000),
      m_bSuccessful(false), m_iRetries(0) { m_receiver.AddDispatcher(*this); m_receiver.AddWaiter(*this); }

    CSetKeyTask(
      IPacketInterface& ifc,                
      const CMACAddress& addrNIC,           
      const CMACAddress& addrLocalDevice,   
      const std::string& strPassword,       
      const CMACAddress& addrRemoteDevice,  
      const std::string& strSecurityID,     
      unsigned long ulTimeout = 5000,       
      bool bPreMac15 = false)               
      :
      m_ifc(ifc), m_addrNIC(addrNIC), m_addrLocalDev(addrLocalDevice), m_addrRemoteDev(addrRemoteDevice),
      m_req(addrLocalDevice, addrNIC, strPassword, strSecurityID, addrRemoteDevice, bPreMac15),
      m_ulTimeout(ulTimeout), m_ulRetryTimer(1000),
      m_bSuccessful(false), m_iRetries(0) { m_receiver.AddDispatcher(*this); m_receiver.AddWaiter(*this); }
      
    virtual IPacketReceiver& GetReceiver() { return m_receiver; }
    virtual unsigned long Drumbeat();
    virtual bool Complete() { return m_bSuccessful || (m_iRetries > (m_ulTimeout / m_ulRetryTimer)); }
    virtual bool Successful() { return m_bSuccessful; }
    virtual ~CSetKeyTask() {}
    
  private:
    
    IPacketInterface& m_ifc;
    CMACAddress m_addrNIC, m_addrLocalDev, m_addrRemoteDev;
    HomePlugAvMMEs::ThunderSetKey::CRequest m_req;
    unsigned long m_ulTimeout, m_ulRetryTimer;
    bool m_bSuccessful;
    size_t m_iRetries;
    CPacketReceiverAndDispatcher m_receiver;
    virtual bool WaitSatisfied() const { return (m_iRetries == 0); }
    virtual void OnThunderSetKeyConfirm(const CMACAddress&, const HomePlugAvMMEs::ThunderSetKey::CConfirm&);
  };
}

#endif // _DLAN_HPSECURITY_H_
