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

#pragma once

#include <string>
#include <vector>
#include <variant>
#include <mutex>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <Oid.h>
#include <SnmpStatus.h>

namespace Snmp{

typedef std::variant<
					// ASN.1 INTEGER, SMIv2 Integer32
					int32_t,
					// ASN.1 OCTET STRING
					std::string,
					// SMIv2 Counter32/Gauge32/TimeTicks/Unsigned32
					uint32_t,
					// mule bool
					bool> 
					snmpSetValue;

class SnmpBackend {

public:
	SnmpBackend(std::string hostname,
				std::string snmpVersion,
				std::string community,
				std::string username,
				std::string securityLevel,
				std::string authenticationProtocol,
				std::string authenticationPassPhrase,
				int snmpMaxRetries,
				int snmpTimeoutUs);
	~SnmpBackend();

private:
	snmp_session createSessionV2 ();
	snmp_session createSessionV3 ();
	void openSession ( snmp_session snmpSession );
	void closeSession ();

	std::string m_hostname;
	std::string m_snmpVersion;
	std::string m_community;
	std::string m_username;
	std::string m_securityLevel;
	std::string m_authenticationProtocol;
	std::string m_authenticationPassPhrase;

	const int m_snmpMaxRetries;
	const int m_snmpTimeoutUs;

	void * m_sessp;
	snmp_session m_snmpSession;
	netsnmp_session * m_snmpSessionHandle;

	SnmpStatus throwIfSnmpResponseError ( int status, netsnmp_pdu *response );
	std::vector<oid> prepareOid ( const std::string& oidOfInterest );
	unsigned int authenticationProtocolStringToEnum ( const std::string & authenticationProtocol );
	std::string oidToString(const oid * objid, size_t objidlen, const netsnmp_variable_list * variable);
	std::pair<SnmpStatus, unsigned char > translateIntToBoolean ( int32_t rawValue );

	std::mutex m_mutex;

public:
	std::pair<SnmpStatus, int32_t> snmpGetInt( const std::string& oidOfInterest );
	std::pair<SnmpStatus, unsigned char > snmpGetBoolean( const std::string& oidOfInterest );
	std::pair<SnmpStatus, std::string> snmpGetString( const std::string& oidOfInterest );
	std::pair<SnmpStatus, std::string> snmpGetTime( const std::string& oidOfInterest );
	std::pair<SnmpStatus, std::vector<uint8_t>> snmpGetHex( const std::string& oidOfInterest );
	std::pair<SnmpStatus, float> snmpGetFloat( const std::string& oidOfInterest );

	std::vector<Oid> snmpDeviceWalk ( const std::string& seedOid );
	netsnmp_pdu * snmpGetNext( const std::string& oidOfInterest );
	SnmpStatus snmpSet( const std::string& oidOfInterest, snmpSetValue & value );
	netsnmp_pdu * snmpGet( const std::string& oidOfInterest );

	std::string getHostName() { return m_hostname; };

};

} // Snmp