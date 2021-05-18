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

#include <SnmpBackend.h>
#include <SnmpExceptions.h>
#include <SnmpDefinitions.h>
#include <MuleLogComponents.h>

using Mule::LogComponentLevels;

namespace Snmp
{

SnmpBackend::SnmpBackend(std::string hostname,
				std::string snmpVersion,
				std::string community,
				std::string username,
				std::string securityLevel,
				std::string authenticationProtocol,
				std::string authenticationPassPhrase ):
				m_hostname(hostname),
				m_snmpVersion(snmpVersion),
				m_community(community),
				m_username(username),
				m_securityLevel(securityLevel),
				m_authenticationProtocol(authenticationProtocol),
				m_authenticationPassPhrase(authenticationPassPhrase)
{

	try
	{
		( m_snmpVersion == "3" ) ? m_snmpSession = createSessionV3() : m_snmpSession = createSessionV2();
		openSession( m_snmpSession );
	}
	catch (const std::exception& e)
	{
		LOG(Log::ERR, LogComponentLevels::mule()) << "While initializing session: " << e.what();
	}

};

snmp_session SnmpBackend::createSessionV2 ()
{

	if ( m_snmpVersion != "2" && m_snmpVersion != "2c" && m_snmpVersion != "1" )
		snmp_throw_runtime_error_with_origin("Wrong or not supported SNMP version. Choose one from (1, 2c)");

	LOG(Log::INF, LogComponentLevels::mule()) << "[" << m_hostname << "] " << "Using SNMP version " << m_snmpVersion;
	snmp_session snmpSession;

	snmp_sess_init( &snmpSession );

	snmpSession.peername = strdup(m_hostname.c_str());

	if (m_snmpVersion == "1")
		snmpSession.version = SNMP_VERSION_1;
	else
		snmpSession.version = SNMP_VERSION_2c;

	snmpSession.community = (u_char*)(m_community.c_str());
	snmpSession.community_len = m_community.length();

	return snmpSession;

}

snmp_session SnmpBackend::createSessionV3 ()
{

	init_snmp("mule");

	snmp_session snmpSession;
	/*
	 * Initializes the session structure.
	 * May perform one time minimal library initialization.
	 */
	snmp_sess_init( &snmpSession );

	/*
	 *	Configuration parameters of the SNMP session
	 */
	snmpSession.retries = Snmp::Constants::SNMP_MAX_RETRIES;
	snmpSession.timeout = Snmp::Constants::SNMP_TIMEOUT;

	/*
	 * Initialize a "session" that defines who we're going to talk to
	 */
	snmpSession.peername = strdup(m_hostname.c_str());

	/* set up the authentication parameters for talking to the server */

	LOG(Log::INF, LogComponentLevels::mule()) << "[" << m_hostname << "] " << "Using SNMP version " << m_snmpVersion;

	/* set the SNMPv3 passphrase */
	const char *v3AuthenticationPassPhrase = m_authenticationPassPhrase.c_str();

	/* set the SNMP version number */
	snmpSession.version=SNMP_VERSION_3;

	/* set the SNMPv3 user name */
	snmpSession.securityName = strdup( m_username.c_str() );
	snmpSession.securityNameLen = strlen( snmpSession.securityName );

	/* set the security level to authenticated, but not encrypted */
	switch( authenticationProtocolStringToEnum(m_securityLevel) ) {
	   case Snmp::Constants::AUTH_NO_PRIV		:
		   LOG(Log::INF, LogComponentLevels::mule()) << "[" << m_hostname << "] " << "Setting security level to authenticated, but not encrypted (" << SNMP_SEC_LEVEL_AUTHNOPRIV << ")";
		   snmpSession.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
		   break;
	   case Snmp::Constants::AUTH_PRIV			:
		   LOG(Log::INF, LogComponentLevels::mule()) << "[" << m_hostname << "] " << "Setting security level to authenticated and encrypted (" << SNMP_SEC_LEVEL_AUTHPRIV << ")";
		   snmpSession.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
		   break;
	   case Snmp::Constants::NO_AUTH_NO_PRIV	:
		   LOG(Log::INF, LogComponentLevels::mule()) << "[" << m_hostname << "] " << "Setting security level to no authentication (" << SNMP_SEC_LEVEL_NOAUTH << ")";
		   snmpSession.securityLevel = SNMP_SEC_LEVEL_NOAUTH;
		   break;
	   default				:
		   LOG(Log::ERR, LogComponentLevels::mule()) << "[" << m_hostname << "] " << "Security level was not set properly";
		   snmpSession.securityLevel = 0;
		   break;
	}

	/* set the authentication method to MD5 */
	snmpSession.securityAuthProto = usmHMACMD5AuthProtocol;
	snmpSession.securityAuthProtoLen = sizeof(usmHMACMD5AuthProtocol)/sizeof(oid);
	snmpSession.securityAuthKeyLen = USM_AUTH_KU_LEN;

	/* set the authentication key to a MD5 hashed version of our
	* passphrase "The Net-SNMP Demo Password" (which must be at least 8
	* characters long)
	*/
	if (generate_Ku(snmpSession.securityAuthProto,
		   snmpSession.securityAuthProtoLen,
		   (u_char *) v3AuthenticationPassPhrase, strlen(v3AuthenticationPassPhrase),
		   snmpSession.securityAuthKey,
		   &snmpSession.securityAuthKeyLen) != SNMPERR_SUCCESS)
	{
	   snmp_perror("SnmpModule");
	   snmp_log(LOG_ERR, "Error generating Ku from authentication pass phrase. \n");
	   exit(1);
	}

	return snmpSession;

}

void SnmpBackend::openSession ( snmp_session snmpSession )
{

	SOCK_STARTUP

	try
	{
		m_sessp = snmp_sess_open(&snmpSession);
		m_snmpSessionHandle = snmp_sess_session( m_sessp );

		if ( !m_snmpSessionHandle ) {
			snmp_perror("ack");
			throw std::runtime_error("When trying to open SNMP session");
		}
	}
	catch (const std::exception& e)
	{
		LOG(Log::ERR, LogComponentLevels::mule()) << "Failed to establish communication. Exiting... " << e.what();
		SOCK_CLEANUP;
		exit(1);
	}

}

void SnmpBackend::closeSession ()
{

	snmp_sess_close( m_sessp );
	SOCK_CLEANUP;

}

std::vector<Oid> SnmpBackend::snmpDeviceWalk ( const std::string& seedOid )
{

	LOG(Log::INF, LogComponentLevels::mule()) << "SNMP device walk seed OID:" << seedOid << " on device: " << m_hostname;

	netsnmp_variable_list *vars;
	netsnmp_pdu * response = snmpGetNext ( seedOid );

	Snmp::Oid currentDeviceOid( seedOid );
	Snmp::Oid nextDeviceOid( seedOid );

	if ( nextDeviceOid.getOidSize() == 14)
	{
		currentDeviceOid.setSensor(true);
		nextDeviceOid.setSensor(true);
	}

	std::vector<Oid> walkedOids;

	while (  true  )
	{

		if (response)
		{
			for(vars = response->variables; vars; vars = vars->next_variable)
			{
				currentDeviceOid = nextDeviceOid;
				nextDeviceOid.assign( oidToString(vars->name, vars->name_length, vars) );
			}

			snmp_free_pdu(response);

			if ( ( currentDeviceOid.getVariable() != nextDeviceOid.getVariable() && currentDeviceOid.getVariable() != 0 ) ||
					currentDeviceOid.getDeviceType() != nextDeviceOid.getDeviceType() ||
					!nextDeviceOid.getOidValidity() )
				break;

			if ( currentDeviceOid.isSensor() &&
					nextDeviceOid.getDeviceNum() != currentDeviceOid.getDeviceNum() )
				break;

			walkedOids.push_back(nextDeviceOid);
			if ( nextDeviceOid.isSensor() )
			{
				LOG(Log::TRC, LogComponentLevels::mule()) << nextDeviceOid.getSensorOid();
				response = snmpGetNext ( nextDeviceOid.getSensorOid() );
			}
			else
			{
				LOG(Log::TRC, LogComponentLevels::mule()) << nextDeviceOid.getOid();
				response = snmpGetNext ( nextDeviceOid.getOid() );
			}


		}

	}

	return walkedOids;
}

netsnmp_pdu * SnmpBackend::snmpGet( const std::string& oidOfInterest )
{

	LOG(Log::TRC, LogComponentLevels::mule()) << "SNMP get OID:" << oidOfInterest << " on device with hostname: " << m_hostname;

	netsnmp_pdu *pdu, *response;

	pdu = snmp_pdu_create(SNMP_MSG_GET);

	std::vector<oid> subIdentifierList = prepareOid( oidOfInterest );

	/*
	 * snmp_add_null_var is a convenience function to add an empty varbind to the PDU. Without
     * needing to specify the NULL value explicitly. This is the normal mechanism for
     * constructing a GET (or similar) information retrieval request.
     * Again, this returns a pointer to the new varbind, or NULL.
	 */
	snmp_add_null_var( pdu, &subIdentifierList[0], subIdentifierList.size() );

	/*
	 * Send the Request out.
	 */

	LOG(Log::TRC, LogComponentLevels::mule()) << "Sending request";

	try
	{
		int snmp_status = snmp_sess_synch_response( m_sessp, pdu, &response );
		throwIfSnmpResponseError( snmp_status, response );
	}
	catch (const std::exception& e)
	{
		LOG(Log::ERR, LogComponentLevels::mule()) << e.what();
	}

	/*
	 * Caller shall cleanup the response (update functions so far)
	 */


	return response;
}

SnmpStatus SnmpBackend::snmpSet( const std::string& oidOfInterest, snmpSetValue & value )
{

	LOG(Log::TRC, LogComponentLevels::mule()) << "SNMP set OID:" << oidOfInterest << " on device with hostname: " << m_hostname;

	netsnmp_pdu *pdu;
	netsnmp_pdu *response = nullptr;
	SnmpStatus status = Snmp_BadNotImplemented;

	pdu = snmp_pdu_create(SNMP_MSG_SET);

	std::vector<oid> subIdentifierList = prepareOid( oidOfInterest );

	if ( std::holds_alternative<std::string>(value) )
	{

		std::string valueString = std::get<std::string>(value);

		snmp_pdu_add_variable(pdu, &subIdentifierList[0], subIdentifierList.size(), ASN_OCTET_STR, valueString.c_str(), valueString.size() );

	}
	else if ( std::holds_alternative<int32_t>(value) )
	{

		int32_t valueInt = std::get<int32_t>(value);
		const void * val = &valueInt;

		snmp_pdu_add_variable(pdu, &subIdentifierList[0], subIdentifierList.size(), ASN_INTEGER, val, sizeof( valueInt ) );

	}
	else if ( std::holds_alternative<uint32_t>(value) )
	{

		uint32_t valueInt = std::get<uint32_t>(value);
		const void * val = &valueInt;

		snmp_pdu_add_variable(pdu, &subIdentifierList[0], subIdentifierList.size(), 'B' /* GAUGE32 */, val, sizeof( valueInt ) );

	}
	else if ( std::holds_alternative<bool>(value) )
	{

		bool valueBool = std::get<bool>(value);
		int valueToInt = valueBool ? 1 : 0;
		const void * val = &valueToInt;

		snmp_pdu_add_variable(pdu, &subIdentifierList[0], subIdentifierList.size(), ASN_INTEGER, val, sizeof( valueToInt ) );

	}
	else
	{

		LOG(Log::ERR, LogComponentLevels::mule()) << "Type is not supported " << value.index();
		return Snmp_BadNotSupported;

	}

	LOG(Log::TRC, LogComponentLevels::mule()) << "Sending request";

	try
	{
		int snmp_status = snmp_sess_synch_response( m_sessp, pdu, &response );
		status = throwIfSnmpResponseError( snmp_status, response );
	}
	catch (const std::exception& e)
	{
		LOG(Log::ERR) << e.what();
	}

	if (response)
		snmp_free_pdu(response);

	return status;
}

netsnmp_pdu * SnmpBackend::snmpGetNext( const std::string& oidOfInterest )
{

	LOG(Log::TRC, LogComponentLevels::mule()) << "SNMP get next OID:" << oidOfInterest;

	netsnmp_pdu *pdu, *response;
	SnmpStatus status = Snmp_BadNotImplemented;

	pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);

	std::vector<oid> subIdentifierList = prepareOid( oidOfInterest );

	snmp_add_null_var( pdu, &subIdentifierList[0], subIdentifierList.size() );

	LOG(Log::TRC, LogComponentLevels::mule()) << "Sending request";

	try
	{
		int snmp_status = snmp_sess_synch_response( m_sessp, pdu, &response );
		status = throwIfSnmpResponseError( snmp_status, response );
	}
	catch (const std::exception& e)
	{
		LOG(Log::ERR, LogComponentLevels::mule()) << "With SNMP status: " << status << ". " << e.what();
	}

	return response;
}

std::vector<oid> SnmpBackend::prepareOid ( const std::string& oidOfInterest )
{

	LOG(Log::TRC, LogComponentLevels::mule()) << "Preparing OID: " << oidOfInterest;

	oid anOID[MAX_OID_LEN];
	size_t anOID_len = MAX_OID_LEN;

	if (! snmp_parse_oid(oidOfInterest.c_str(), anOID, &anOID_len))
	{
		  snmp_perror(oidOfInterest.c_str());
		  snmp_throw_runtime_error_with_origin("Failed to parse OID");
	}

	std::vector<oid> subIdentifierList(anOID_len, 0);
	subIdentifierList.shrink_to_fit();

	for ( unsigned int i = 0; i<anOID_len; i++ )
		subIdentifierList[i]=anOID[i];

	return subIdentifierList;
}

SnmpStatus SnmpBackend::throwIfSnmpResponseError ( int status, netsnmp_pdu *response )
{

	if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)
	{

		LOG(Log::TRC, LogComponentLevels::mule()) << "Received successful SNMP response";
		return Snmp_Good;

	}
	else
	{

		if (status == STAT_SUCCESS)
			snmp_throw_runtime_error_with_origin( "Error in packet. Reason: " + snmp_errstring(response->errstat) );
		else
		{
			snmp_throw_runtime_error_with_origin( "Session error" );
		}

	}
	return Snmp_Bad;
}

unsigned int SnmpBackend::authenticationProtocolStringToEnum ( const std::string & authenticationProtocol )
{

	if (authenticationProtocol == "authNoPriv") return Snmp::Constants::SecurityLevel::AUTH_NO_PRIV;
	if (authenticationProtocol == "authPriv") return Snmp::Constants::SecurityLevel::AUTH_PRIV;
	if (authenticationProtocol == "noAuthNoPriv") return Snmp::Constants::SecurityLevel::NO_AUTH_NO_PRIV;

	return 0;

}

}