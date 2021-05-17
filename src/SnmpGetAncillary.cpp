/* 
 * @author:     Paris Moschovakos <paris.moschovakos@cern.ch>
 * 
 * @copyright:  2021 CERN
 * 
 * @license:
 * LICENSE:
 * Copyright (c) 2021, CERN
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

#include <SnmpExceptions.h>
#include <SnmpBackend.h>

#include <LogIt.h>
#include <statuscode.h>

namespace Snmp
{

std::pair<OpcUa_StatusCode, OpcUa_Int32> SnmpBackend::snmpGetInt( const std::string& oidOfInterest )
{

	netsnmp_variable_list *vars;
	OpcUa_Int32 value(0);
	netsnmp_pdu * response = snmpGet ( oidOfInterest );

	if (response)
	{

		/* manipulate the information ourselves */
		for(vars = response->variables; vars; vars = vars->next_variable)
		{
			if (vars->type == ASN_INTEGER)
			{
				value = *vars->val.integer;
				if (response) snmp_free_pdu(response);
				return std::pair<OpcUa_StatusCode, OpcUa_Int32>(OpcUa_Good, value);
			}
			else
			{
				LOG(Log::TRC) << "There is no such variable name in this MIB. Type: 0x" << std::hex << (int)(vars->type)
								<< ". Failed OID: " << oidOfInterest;
				if (response) snmp_free_pdu(response);
				return std::pair<OpcUa_StatusCode, OpcUa_Int32>(OpcUa_BadNoDataAvailable, value);
			}
		}

		snmp_free_pdu(response);

	}

	return std::pair<OpcUa_StatusCode, OpcUa_Int32>(OpcUa_Bad, value);

}

std::pair<OpcUa_StatusCode, UaString> SnmpBackend::snmpGetString( const std::string& oidOfInterest )
{

	netsnmp_variable_list *vars;
	UaString value = "";
	netsnmp_pdu * response = snmpGet ( oidOfInterest );

	if (response)
	{

		/* manipulate the information ourselves */
		for(vars = response->variables; vars; vars = vars->next_variable)
		{
			if (vars->type == ASN_OCTET_STR)
			{
				std::string castToString = (reinterpret_cast<const char*>(vars->val.string));
				value = ( UaString( castToString.c_str()  ) );
				if (response) snmp_free_pdu(response);
				return std::pair<OpcUa_StatusCode, UaString>(OpcUa_Good, value);
			}
			else
			{
				LOG(Log::TRC) << "There is no such variable name in this MIB. Type: 0x" << std::hex << (int)(vars->type)
								<< ". Failed OID: " << oidOfInterest;
				if (response) snmp_free_pdu(response);
				return std::pair<OpcUa_StatusCode, UaString>(OpcUa_BadNoDataAvailable, value);
			}
		}

		snmp_free_pdu(response);

	}

	return std::pair<OpcUa_StatusCode, UaString>(OpcUa_BadNotImplemented, value);

}

std::pair<OpcUa_StatusCode, OpcUa_Boolean> SnmpBackend::snmpGetBoolean( const std::string& oidOfInterest )
{

	LOG(Log::TRC) << "UpdateOidToBoolean:" << oidOfInterest << " on device: " << getHostName();

	netsnmp_variable_list *vars;
	OpcUa_Int32 value(0);
	netsnmp_pdu * response = snmpGet ( oidOfInterest );

	if (response)
	{

		/* manipulate the information ourselves */
		for(vars = response->variables; vars; vars = vars->next_variable)
		{
			if (vars->type == ASN_INTEGER)
			{
				value = *vars->val.integer;
				std::pair<OpcUa_StatusCode, OpcUa_Boolean> castedValue = translateIntToBoolean ( value );
				if (response) snmp_free_pdu(response);
				return std::pair<OpcUa_StatusCode, OpcUa_Boolean>( castedValue );
			}
			else
			{
				LOG(Log::TRC) << "There is no such variable name in this MIB. Type: 0x" << std::hex << (int)(vars->type)
								<< ". Failed OID: " << oidOfInterest;
				if (response) snmp_free_pdu(response);
				return std::pair<OpcUa_StatusCode, OpcUa_Boolean>(OpcUa_BadNoDataAvailable, value);
			}
		}

		snmp_free_pdu(response);

	}

	return std::pair<OpcUa_StatusCode, OpcUa_Boolean>(OpcUa_BadNotImplemented, value);

}

std::pair<OpcUa_StatusCode, UaString> SnmpBackend::snmpGetTime( const std::string& oidOfInterest )
{

	netsnmp_variable_list *vars;
	time_t value(0);
	netsnmp_pdu * response = snmpGet ( oidOfInterest );

	if (response)
	{

		/* manipulate the information ourselves */
		for(vars = response->variables; vars; vars = vars->next_variable)
		{
			if (vars->type == ASN_INTEGER)
				{
					value = *vars->val.integer;
					OpcUa_StatusCode status = OpcUa_Good;
					UaString timeString;

					if ( value == -1 )
						status = OpcUa_BadDataUnavailable;
					else
					{
						timeString = asctime(localtime (&value));
						status = OpcUa_Good;
					}
					if (response) snmp_free_pdu(response);
					return std::pair<OpcUa_StatusCode, UaString>( status, timeString );
				}
				else
				{
					LOG(Log::TRC) << "There is no such variable name in this MIB. Type: 0x" << std::hex << (int)(vars->type)
									<< ". Failed OID: " << oidOfInterest;
					if (response) snmp_free_pdu(response);
					return std::pair<OpcUa_StatusCode, UaString>(OpcUa_BadNoDataAvailable, "");
				}
		}


		snmp_free_pdu(response);

	}

	return std::pair<OpcUa_StatusCode, UaString>(OpcUa_BadNotImplemented, "");

}

std::pair<OpcUa_StatusCode, UaByteString> SnmpBackend::snmpGetHex( const std::string& oidOfInterest )
{

	netsnmp_variable_list *vars;
	UaByteString value;
	netsnmp_pdu * response = snmpGet ( oidOfInterest );

	if (response)
	{

		/* manipulate the information ourselves */
		for(vars = response->variables; vars; vars = vars->next_variable)
		{
			if (vars->type == ASN_OCTET_STR)
			{

				uint8_t* myHexValue = (reinterpret_cast<uint8_t*>(vars->val.string));
				value.setByteString( vars->val_len, myHexValue );
				if (response) snmp_free_pdu(response);
				return std::pair<OpcUa_StatusCode, UaByteString>(OpcUa_Good, value);

			}
			else
			{

				LOG(Log::TRC) << "There is no such variable name in this MIB. Type: 0x" << std::hex << (int)(vars->type)
								<< ". Failed OID: " << oidOfInterest;
				if (response) snmp_free_pdu(response);
				return std::pair<OpcUa_StatusCode, UaByteString>(OpcUa_BadNoDataAvailable, value);

			}
		}

		snmp_free_pdu(response);

	}

	return std::pair<OpcUa_StatusCode, UaByteString>(OpcUa_BadNotImplemented, value);

}

std::pair<OpcUa_StatusCode, OpcUa_Float> SnmpBackend::snmpGetFloat( const std::string& oidOfInterest )
{

	netsnmp_variable_list *vars;
	OpcUa_Float value = 0.0;
	netsnmp_pdu * response = snmpGet ( oidOfInterest );

	if (response)
	{

		/* manipulate the information ourselves */
		for(vars = response->variables; vars; vars = vars->next_variable)
		{
			if (vars->type == ASN_OCTET_STR)
			{

				std::string castToString = (reinterpret_cast<const char*>(vars->val.string));
				if ( castToString == "N/A" )
				{
					if (response) snmp_free_pdu(response);
					return std::pair<OpcUa_StatusCode, OpcUa_Float>(OpcUa_BadNoDataAvailable, value);
				}
				else
				{
					try
					{
						value = std::stof( castToString );
					}
					catch (const std::exception& e)
					{
						LOG(Log::ERR) << e.what() << ": Cannot convert sensor value. Due to sensor type? (OID:" << oidOfInterest << ")";
					}
				}
				if (response) snmp_free_pdu(response);
				return std::pair<OpcUa_StatusCode, OpcUa_Float>(OpcUa_Good, value);

			}
			else
			{

				LOG(Log::TRC) << "There is no such variable name in this MIB. Type: 0x" << std::hex << (int)(vars->type)
								<< ". Failed OID: " << oidOfInterest;
				if (response) snmp_free_pdu(response);
				return std::pair<OpcUa_StatusCode, OpcUa_Float>(OpcUa_BadNoDataAvailable, value);

			}
		}

		snmp_free_pdu(response);

	}

	return std::pair<OpcUa_StatusCode, OpcUa_Float>(OpcUa_BadNotImplemented, value);

}

std::string SnmpBackend::oidToString(const oid * objid, size_t objidlen, const netsnmp_variable_list * vars)
{
	char buf[MAX_OID_LEN];
	std::string oid;
	snprint_variable(buf, MAX_OID_LEN, objid, objidlen, vars);
	oid.assign(buf, MAX_OID_LEN);
	oid = oid.substr(0, oid.find_first_of(" "));
	return oid;
}

std::pair<OpcUa_StatusCode, OpcUa_Boolean> SnmpBackend::translateIntToBoolean ( int32_t rawValue )
{
	switch (rawValue) {
		case 1:
			return std::pair<OpcUa_StatusCode, OpcUa_Boolean>( OpcUa_Good, true );
			break;
		case 0:
			return std::pair<OpcUa_StatusCode, OpcUa_Boolean>( OpcUa_Good, false );
			break;
		case -1:
			return std::pair<OpcUa_StatusCode, OpcUa_Boolean>( OpcUa_BadDataUnavailable, false );
			break;
		default:
			return std::pair<OpcUa_StatusCode, OpcUa_Boolean>( OpcUa_Bad, false );
			break;
	}
}

}
