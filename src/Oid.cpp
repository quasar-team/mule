/* 
 * @author:     Paris Moschovakos <paris.moschovakos@cern.ch>
 * 
 * @copyright:  2020 CERN
 * 
 * @license:
 * LICENSE:
 * Copyright (c) 2020, CERN
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT  HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS  OR IMPLIED  WARRANTIES, INCLUDING, BUT NOT  LIMITED TO, THE IMPLIED
 * WARRANTIES  OF  MERCHANTABILITY  AND  FITNESS  FOR  A  PARTICULAR  PURPOSE  ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL,  SPECIAL, EXEMPLARY, OR  CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT  NOT LIMITED TO,  PROCUREMENT OF  SUBSTITUTE GOODS OR  SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS  INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY  THEORY  OF  LIABILITY,   WHETHER IN  CONTRACT, STRICT  LIABILITY,  OR  TORT
 * (INCLUDING  NEGLIGENCE OR OTHERWISE)  ARISING IN ANY WAY OUT OF  THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */

#include <Oid.h>
#include <MuleLogComponents.h>

#include <vector>

using namespace Snmp;
using Mule::LogComponentLevels;

Oid::Oid() : m_deviceTypeOid(0), m_subDeviceTypeOid(0), m_variableOid(0), m_deviceNumOid(0), m_sequenceNumOid(0)
{

}

Oid::Oid( unsigned int deviceTypeOid, unsigned int subDeviceTypeOid, unsigned int variableOid, unsigned int deviceNumOid, unsigned int sequenceNumOid ) :
		m_deviceTypeOid(deviceTypeOid), m_subDeviceTypeOid(subDeviceTypeOid), m_variableOid(variableOid), m_deviceNumOid(deviceNumOid), m_sequenceNumOid(sequenceNumOid)
{

}

Oid::Oid( std::string oidOfInterest )
{
	this->assign(oidOfInterest);
}

Oid::~Oid()
{
}

void Oid::assign ( std::string oidOfInterest )
{

	std::vector<std::string> oidPart;
	char delim = '.';

	std::size_t current, previous = 0;
	current = oidOfInterest.find(delim);
	while (current != std::string::npos) {
		oidPart.push_back(oidOfInterest.substr(previous, current - previous));
		previous = current + 1;
		current = oidOfInterest.find(delim, previous);
	}
	oidPart.push_back(oidOfInterest.substr(previous, current - previous));

	m_oidSize = oidPart.size();

	if ( oidPart.at(6) != "16394" )
	{
		m_valid = false;
		LOG(Log::DBG, LogComponentLevels::snmpBackend()) << "Wrong OID provided: " << oidOfInterest;
	}
	else if ( m_oidSize == 12 )
	{
		LOG(Log::DBG, LogComponentLevels::snmpBackend()) << "Seed for discovering a device was provided: " << oidOfInterest;
		m_deviceTypeOid = stoi(oidPart.at(10));
		m_subDeviceTypeOid = stoi(oidPart.at(11));
		m_variableOid = 0;
		m_deviceNumOid = 0;
	}
	else if ( m_oidSize == 14 ) // This can also be a seed for sensors
	{
		LOG(Log::DBG, LogComponentLevels::snmpBackend()) << "Full OID provided or seed for discovering sensors: " << oidOfInterest;;
		m_deviceTypeOid = stoi(oidPart.at(10));
		m_subDeviceTypeOid = stoi(oidPart.at(11));
		m_variableOid = stoi(oidPart.at(12));
		m_deviceNumOid = stoi(oidPart.at(13));
	}
	else if ( m_oidSize == 15 )
	{
		LOG(Log::DBG, LogComponentLevels::snmpBackend()) << "Full sensor OID provided: " << oidOfInterest;
		m_deviceTypeOid = stoi(oidPart.at(10));
		m_subDeviceTypeOid = stoi(oidPart.at(11));
		m_variableOid = stoi(oidPart.at(12));
		m_deviceNumOid = stoi(oidPart.at(13));
		m_sequenceNumOid = stoi(oidPart.at(14));
		m_sensor = true;
	}
	else
	{
		LOG(Log::ERR, LogComponentLevels::snmpBackend()) << "Unknown OID size:"  << oidOfInterest;
	}
}

