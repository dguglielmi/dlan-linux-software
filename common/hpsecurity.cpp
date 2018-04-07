
//
// (c) 2006-2010 devolo AG, Aachen (Germany)
//

#include <string>
#include "hpmmes.h"
#include "hpsecurity.h"
#include "packetinterface.h"

unsigned long HomePlugSecurity::CSetKeyTask::Drumbeat()
{
  unsigned long ulTimeout = 0;

  if(!CSetKeyTask::Complete()) 
    m_iRetries++;

  if(!CSetKeyTask::Complete())
  {
    m_ifc.SendPacket(m_addrNIC, m_req);            
    ulTimeout = m_ulRetryTimer;
  }

  return ulTimeout;
}

void HomePlugSecurity::CSetKeyTask::OnSetNetworkEncKeyConfirm(
  const CMACAddress& adapter, 
  const HomePlugMMEs::SetNetworkEncKey::CConfirm& mme)
{
  if((adapter == m_addrNIC) && (mme.GetAddress() == m_addrLocalDev))
  {
    m_bSuccessful = true;
    m_iRetries = 0;
  }
}

unsigned long HomePlugAvSecurity::CSetKeyTask::Drumbeat()
{
  unsigned long ulTimeout = 0;

  if(!CSetKeyTask::Complete()) 
    m_iRetries++;

  if(!CSetKeyTask::Complete())
  {
    m_ifc.SendPacket(m_addrNIC, m_req);
    ulTimeout = m_ulRetryTimer;
  }

  return ulTimeout;
}

void HomePlugAvSecurity::CSetKeyTask::OnThunderSetKeyConfirm(
  const CMACAddress& adapter, 
  const HomePlugAvMMEs::ThunderSetKey::CConfirm& mme)
{
  if((adapter == m_addrNIC) && (mme.GetAddress() == m_addrLocalDev))
  {
    if(mme.GetStatus() == HomePlugAvMMEs::ThunderSetKey::eSuccess)
    {
      m_bSuccessful = true;
      m_iRetries = 0;
    }
  }
}
