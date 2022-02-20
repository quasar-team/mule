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

SnmpBackend::SnmpBackend(const std::string& hostname,
				const std::string& snmpVersion,
				const std::string& community,
				int snmpMaxRetries,
				int snmpTimeoutUs) :
				SnmpBackend(hostname, snmpVersion, community, "", "", "", "", "", "", snmpMaxRetries, snmpTimeoutUs)
{}

SnmpBackend::SnmpBackend(const std::string& hostname,
				const std::string& snmpVersion,
				const std::string& community,
				const std::string& username,
				const std::string& securityLevel,
				const std::string& authenticationProtocol,
				const std::string& authenticationPassPhrase,
				const std::string& privacyProtocol,
				const std::string& privacyPassPhrase,
				int snmpMaxRetries,
				int snmpTimeoutUs) :
				m_hostname(hostname),
				m_snmpVersion(snmpVersion),
				m_community(community),
				m_username(username),
				m_securityLevel(securityLevel),
				m_authenticationProtocol(authenticationProtocol),
				m_authenticationPassPhrase(authenticationPassPhrase),
				m_privacyProtocol(privacyProtocol),
				m_privacyPassPhrase(privacyPassPhrase),
				m_snmpMaxRetries(snmpMaxRetries),
				m_snmpTimeoutUs(snmpTimeoutUs)
{

	try
	{
		const auto envMIBS = getenv("MIBS");
		const auto envMIBDIRS = getenv("MIBDIRS");
		LOG(Log::INF, LogComponentLevels::mule()) << __FUNCTION__ << " calling init_snmp with $env:MIBS ["<<( envMIBS? envMIBS : "NULL" )<<"] $env.MIBDIRS ["<<( envMIBDIRS? envMIBDIRS : "NULL" )<<"]";
		init_snmp("mule");
		( m_snmpVersion == "3" ) ? m_snmpSession = createSessionV3() : m_snmpSession = createSessionV2();

		/*
		 *	Configuration parameters of the SNMP session
		 */
		m_snmpSession.retries = m_snmpMaxRetries;
		m_snmpSession.timeout = m_snmpTimeoutUs;

		openSession( m_snmpSession );
	}
	catch (const std::exception& e)
	{
		LOG(Log::ERR, LogComponentLevels::mule()) << "While initializing session: " << e.what();
		throw;
	}

};

SnmpBackend::SnmpBackend(const std::string& hostname,
				const std::string& snmpVersion,
				const std::string& community,
				const std::string& username,
				const std::string& securityLevel,
				const std::string& authenticationProtocol,
				const std::string& authenticationPassPhrase,
				int snmpMaxRetries,
				int snmpTimeoutUs) :
				SnmpBackend(hostname, snmpVersion, community, username, securityLevel, authenticationProtocol, m_authenticationPassPhrase, "", "", snmpMaxRetries, snmpTimeoutUs)
{}

SnmpBackend::~SnmpBackend()
{

	// RAII cleanup here
	closeSession();

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

	snmp_session snmpSession;
	/*
	 * Initializes the session structure.
	 * May perform one time minimal library initialization.
	 */
	snmp_sess_init( &snmpSession );

	/*
	 * Initialize a "session" that defines who we're going to talk to
	 */
	snmpSession.peername = strdup(m_hostname.c_str());

	/* set up the authentication parameters for talking to the server */

	LOG(Log::INF, LogComponentLevels::mule()) << "[" << m_hostname << "] " << "Using SNMP version " << m_snmpVersion;

	/* set the SNMP version number */
	snmpSession.version=SNMP_VERSION_3;

	/* set the SNMPv3 user name */
	snmpSession.securityName = strdup( m_username.c_str() );
	snmpSession.securityNameLen = strlen( snmpSession.securityName );

	/* set security level */
	LOG(Log::INF, LogComponentLevels::mule()) << "[" << m_hostname << "] " << "Setting security level to ["<<m_securityLevel<<"]";
	snmpSession.securityLevel = securityLevelToInt(m_securityLevel);

	auto generateSecurityKey = [] (const std::string& type, const oid* protocol, const size_t protocolLength, const char* passphrase, u_char* keyDestination, size_t* keyLength) {
		if (generate_Ku(protocol, protocolLength, (u_char *) passphrase, strlen(passphrase), keyDestination, keyLength) != SNMPERR_SUCCESS)
		{
			snmp_perror("mule");
			snmp_log(LOG_ERR, "Error generating Ku from %s pass phrase. \n", type.c_str());
			std::exit(EXIT_FAILURE);
		}
		LOG(Log::INF, LogComponentLevels::mule()) << "Generated Ku for type ["<<type<<"], key length ["<<*keyLength<<"]";
	};

	/* set authentication protocol details and key on session instance */
	if(snmpSession.securityLevel >= SNMP_SEC_LEVEL_AUTHNOPRIV)
	{
		/* set authentication protocol */
		const auto oidDetails = securityProtocolToOidDetails(m_authenticationProtocol);
		snmpSession.securityAuthProto = std::get<0>(oidDetails);
		snmpSession.securityAuthProtoLen = std::get<1>(oidDetails);
		snmpSession.securityAuthKeyLen = USM_AUTH_KU_LEN;

		generateSecurityKey("authentication", snmpSession.securityAuthProto, snmpSession.securityAuthProtoLen,
			m_authenticationPassPhrase.c_str(),
			snmpSession.securityAuthKey, &snmpSession.securityAuthKeyLen);
	}

	/* set privacy protocol details and key on session instance
	*/
	if(snmpSession.securityLevel >= SNMP_SEC_LEVEL_AUTHPRIV)
	{
		/* set privacy protocol */
		const auto oidDetails = securityProtocolToOidDetails(m_privacyProtocol);
		snmpSession.securityPrivProto = std::get<0>(oidDetails);
		snmpSession.securityPrivProtoLen = std::get<1>(oidDetails);
		snmpSession.securityPrivKeyLen = USM_PRIV_KU_LEN;

		generateSecurityKey("privacy", snmpSession.securityAuthProto, snmpSession.securityAuthProtoLen, // AuthProto - I know, internet says so.
			m_privacyPassPhrase.c_str(),
			snmpSession.securityPrivKey, &snmpSession.securityPrivKeyLen);
	}

	return snmpSession;

}

void SnmpBackend::openSession ( snmp_session snmpSession )
{

	SOCK_STARTUP;

	try
	{
		m_sessp = snmp_sess_open(&snmpSession);
		m_snmpSessionHandle = snmp_sess_session( m_sessp );

		if ( !m_snmpSessionHandle ) {
			snmp_perror("ack");
			snmp_throw_runtime_error_with_origin("When trying to open SNMP session to " + getHostName());
		}
	}
	catch (const std::exception& e)
	{
		LOG(Log::ERR, LogComponentLevels::mule()) << "Failed to establish communication: " << e.what();
		SOCK_CLEANUP;
		throw;
	}

}

void SnmpBackend::closeSession ()
{

	snmp_sess_close( m_sessp );
	SOCK_CLEANUP;

}

std::vector<Oid> SnmpBackend::snmpDeviceWalk ( const std::string& seedOid )
{

	LOG(Log::INF, LogComponentLevels::mule()) << "SNMP device walk seed OID:" << seedOid << " from: " << getHostName();

	netsnmp_variable_list *vars;
	netsnmp_pdu * response = snmpGetNext ( seedOid );

	Snmp::Oid currentDeviceOid( seedOid );
	Snmp::Oid nextDeviceOid( seedOid );

	std::vector<Oid> walkedOids;

	while (  true  )
	{

        if (response)
	    {
	 		for(vars = response->variables; vars; vars = vars->next_variable)
	 		{
	 			currentDeviceOid = nextDeviceOid;
	 			nextDeviceOid(oidToString(vars->name, vars->name_length, vars));
	 		}

	 		snmp_free_pdu(response);

			// Test criteria to break the walking loop
			LOG(Log::TRC, LogComponentLevels::mule()) << "Current OID: " << currentDeviceOid.getOidString();
			LOG(Log::TRC, LogComponentLevels::mule()) << "Next OID: " << nextDeviceOid.getOidString();

			// Stop walking due to level change
			if ( currentDeviceOid.getOidVector()[currentDeviceOid.getOidSize() - 2] != nextDeviceOid.getOidVector()[nextDeviceOid.getOidSize() - 2] )
			{
			 	LOG(Log::INF, LogComponentLevels::mule()) << "SNMP walk reached its end";
				break;
			}

			// Stop walking due size change
			if ( currentDeviceOid.getOidSize() != nextDeviceOid.getOidSize() )
			{
			 	LOG(Log::INF, LogComponentLevels::mule()) << "SNMP walk reached its end";
				break;
			}

	 		walkedOids.push_back(nextDeviceOid);

            response = snmpGetNext ( nextDeviceOid.getOidString() );

	    }

	}

 	return walkedOids;
}

PduPtr SnmpBackend::snmpGet( const std::string& oidOfInterest )
{

	LOG(Log::TRC, LogComponentLevels::mule()) << "SNMP get OID:" << oidOfInterest << " on device with hostname: " << m_hostname;

	netsnmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GET);

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

	netsnmp_pdu *response = nullptr;
	try
	{
		std::lock_guard<std::mutex> guard(m_mutex);
		int snmp_status = snmp_sess_synch_response( m_sessp, pdu, &response );
		throwIfSnmpResponseError( snmp_status, response );
	}
	catch (const std::exception& e)
	{
		LOG(Log::ERR, LogComponentLevels::mule()) << "At snmpGet OID:" << oidOfInterest << " from: " << getHostName() << " ." << e.what();
		throw;
	}

	return PduPtr(response);
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

		snmp_pdu_add_variable(pdu, &subIdentifierList[0], subIdentifierList.size(), 'B' /* Needed by PDU server */, val, sizeof( valueInt ) );

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
		std::lock_guard<std::mutex> guard(m_mutex);
		int snmp_status = snmp_sess_synch_response( m_sessp, pdu, &response );
		status = throwIfSnmpResponseError( snmp_status, response );
	}
	catch (const std::exception& e)
	{
		LOG(Log::ERR, LogComponentLevels::mule()) << "At snmpSet OID:" << oidOfInterest << " from: " << getHostName() << " ." << e.what();
		if (response) snmp_free_pdu(response);
		throw;
	}

	if (response) snmp_free_pdu(response);

	return status;
}

netsnmp_pdu * SnmpBackend::snmpGetNext( const std::string& oidOfInterest )
{

	LOG(Log::TRC, LogComponentLevels::mule()) << "SNMP get next OID:" << oidOfInterest;

	netsnmp_pdu *pdu, *response;

	pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);

	std::vector<oid> subIdentifierList = prepareOid( oidOfInterest );

	snmp_add_null_var( pdu, &subIdentifierList[0], subIdentifierList.size() );

	LOG(Log::TRC, LogComponentLevels::mule()) << "Sending request";

	try
	{
		std::lock_guard<std::mutex> guard(m_mutex);
		int snmp_status = snmp_sess_synch_response( m_sessp, pdu, &response );
		throwIfSnmpResponseError( snmp_status, response );
	}
	catch (const std::exception& e)
	{
        LOG(Log::ERR, LogComponentLevels::mule()) << "At snmpGetNext OID:" << oidOfInterest << " from: " << getHostName() << " ." << e.what();
		throw;
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

		if ( status == STAT_SUCCESS )
		{
			snmp_throw_runtime_error_with_origin( "Error in packet due to " + snmp_errstring(response->errstat) );
		}
		else if ( status == STAT_ERROR )
		{
			snmp_throw_runtime_error_with_origin( "Error due to STAT_ERROR");
		}
		else if ( status == STAT_TIMEOUT )
		{
			snmp_throw_runtime_error_with_origin( "Error due to STAT_TIMEOUT");
		}
		else
		{
			snmp_throw_runtime_error_with_origin( "Unknown session error" );
		}

	}
	return Snmp_Bad;
}

int SnmpBackend::securityLevelToInt ( const std::string & securityLevel )
{
	if (securityLevel == "noAuthNoPriv") return SNMP_SEC_LEVEL_NOAUTH;
	if (securityLevel == "authNoPriv") 	 return SNMP_SEC_LEVEL_AUTHNOPRIV;
	if (securityLevel == "authPriv") 	 return SNMP_SEC_LEVEL_AUTHPRIV;
	snmp_throw_runtime_error_with_origin("invalid security level string received [" + securityLevel + "], valid options are [noAuthNoPriv|authNoPriv|authPriv]");
}

std::pair<oid*, size_t> SnmpBackend::securityProtocolToOidDetails( const std::string & protocol )
{
	if (protocol == "MD5") 	return std::make_pair(usmHMACMD5AuthProtocol, USM_AUTH_PROTO_MD5_LEN);
	if (protocol == "SHA") 	return std::make_pair(usmHMACSHA1AuthProtocol, USM_AUTH_PROTO_SHA_LEN);
	if (protocol == "DES") 	return std::make_pair(usmDESPrivProtocol, USM_PRIV_PROTO_DES_LEN);
	if (protocol == "AES") 	return std::make_pair(usmAESPrivProtocol, USM_PRIV_PROTO_AES_LEN);
	snmp_throw_runtime_error_with_origin("invalid security protocol string received [" + protocol + "], valid options are [MD5|SHA|DES|AES]");
}

}
