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
#include <tuple>
#include <memory>
#include <functional>

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

struct PduDeleter
{
	void operator()(netsnmp_pdu* p)
	{
		snmp_free_pdu(p);
	}
};
typedef std::unique_ptr<netsnmp_pdu, PduDeleter> PduPtr;

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
	SnmpBackend(std::string hostname,
				std::string snmpVersion,
				std::string community,
				std::string username,
				std::string securityLevel,
				std::string authenticationProtocol,
				std::string authenticationPassPhrase,
				std::string privacyProtocol,
				std::string privacyPassPhrase,
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
	std::string m_privacyProtocol;
	std::string m_privacyPassPhrase;

	const int m_snmpMaxRetries;
	const int m_snmpTimeoutUs;

	void * m_sessp;
	snmp_session m_snmpSession;
	netsnmp_session * m_snmpSessionHandle;

	SnmpStatus throwIfSnmpResponseError ( int status, netsnmp_pdu *response );
	std::vector<oid> prepareOid ( const std::string& oidOfInterest );
	int securityLevelToInt ( const std::string & securityLevel );
	std::pair<oid*, size_t> securityProtocolToOidDetails( const std::string & protocol );
	std::string oidToString(const oid * objid, size_t objidlen, const netsnmp_variable_list * variable);
	std::pair<SnmpStatus, unsigned char > translateIntToBoolean ( int32_t rawValue );

	std::mutex m_mutex;

public:
	std::pair<SnmpStatus, int32_t> snmpGetInt( const std::string& oidOfInterest );
	std::pair<SnmpStatus, unsigned char > snmpGetBoolean( const std::string& oidOfInterest );
	std::pair<SnmpStatus, std::string> snmpGetString( const std::string& oidOfInterest );
	std::pair<SnmpStatus, std::string> snmpGetTime( const std::string& oidOfInterest );
	std::pair<SnmpStatus, std::vector<uint8_t>> snmpGetHex( const std::string& oidOfInterest );
	
	/**
	 * Gets a float value where the underlying SNMP data format is string. So, reads string value
	 * from remote resource, then parses string to get float value.
	 * @param oidOfInterest target oid on remote resource
	 * @return float value parsed from the SNMP string value
	 */
	std::pair<SnmpStatus, float> snmpGetFloatFromString( const std::string& oidOfInterest );

	/**
	 * Gets a float value where the underlying SNMP data format is string. So, reads int value
	 * from remote resource, then multiplies by the scale factor. So, if int value retrieved
	 * is 1234, and scale factor is 0.01, then returned value is ~12.34.
	 * @param oidOfInterest target oid on remote resource
	 * @param scaleFactor scaling factor, retrieved integer value will be multiplied by this
	 * @return float value scaled according to the scale factor
	 */
	std::pair<SnmpStatus, float> snmpGetFloatFromInt( const std::string& oidOfInterest, const float& scaleFactor );

	std::vector<Oid> snmpDeviceWalk ( const std::string& seedOid );
	netsnmp_pdu * snmpGetNext( const std::string& oidOfInterest );
	SnmpStatus snmpSet( const std::string& oidOfInterest, snmpSetValue & value );
	PduPtr snmpGet( const std::string& oidOfInterest );

	std::string getHostName() { return m_hostname; };

};

} // Snmp