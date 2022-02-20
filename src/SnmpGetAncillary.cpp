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
#include <MuleLogComponents.h>

namespace Snmp
{

using Mule::LogComponentLevels;

std::pair<SnmpStatus, int32_t> SnmpBackend::snmpGetInt( const std::string& oidOfInterest )
{

	netsnmp_variable_list *vars;
	int32_t value(0);
	PduPtr response = snmpGet ( oidOfInterest );

	if (response)
	{

		/* manipulate the information ourselves */
		for(vars = response->variables; vars; vars = vars->next_variable)
		{
			if (vars->type == ASN_INTEGER)
			{
				value = *vars->val.integer;
				return std::pair<SnmpStatus, int32_t>(Snmp_Good, value);
			}
			else
			{
				LOG(Log::TRC, LogComponentLevels::mule()) << "There is no such variable name in this MIB. Type: 0x" << std::hex << (int)(vars->type)
								<< ". Failed OID: " << oidOfInterest;
				return std::pair<SnmpStatus, int32_t>(Snmp_BadNoDataAvailable, value);
			}
		}

	}

	return std::pair<SnmpStatus, int32_t>(Snmp_Bad, value);

}

std::pair<SnmpStatus, std::string> SnmpBackend::snmpGetString( const std::string& oidOfInterest )
{

	netsnmp_variable_list *vars;
	std::string value("");
	PduPtr response = snmpGet ( oidOfInterest );

	if (response)
	{

		/* manipulate the information ourselves */
		for(vars = response->variables; vars; vars = vars->next_variable)
		{
			if (vars->type == ASN_OCTET_STR)
			{
				value = (reinterpret_cast<const char*>(vars->val.string));
				return std::pair<SnmpStatus, std::string>(Snmp_Good, value);
			}
			else
			{
				LOG(Log::TRC, LogComponentLevels::mule()) << "There is no such variable name in this MIB. Type: 0x" << std::hex << (int)(vars->type)
								<< ". Failed OID: " << oidOfInterest;
				return std::pair<SnmpStatus, std::string>(Snmp_BadNoDataAvailable, value);
			}
		}

	}

	return std::pair<SnmpStatus, std::string>(Snmp_BadNotImplemented, value);

}

std::pair<SnmpStatus, unsigned char > SnmpBackend::snmpGetBoolean( const std::string& oidOfInterest )
{

	LOG(Log::TRC, LogComponentLevels::mule()) << "UpdateOidToBoolean:" << oidOfInterest << " on device: " << getHostName();

	netsnmp_variable_list *vars;
	int32_t value(0);
	PduPtr response = snmpGet ( oidOfInterest );

	if (response)
	{

		/* manipulate the information ourselves */
		for(vars = response->variables; vars; vars = vars->next_variable)
		{
			if (vars->type == ASN_INTEGER)
			{
				value = *vars->val.integer;
				std::pair<SnmpStatus, unsigned char > castedValue = translateIntToBoolean ( value );
				return std::pair<SnmpStatus, unsigned char >( castedValue );
			}
			else
			{
				LOG(Log::TRC, LogComponentLevels::mule()) << "There is no such variable name in this MIB. Type: 0x" << std::hex << (int)(vars->type)
								<< ". Failed OID: " << oidOfInterest;
				return std::pair<SnmpStatus, unsigned char >(Snmp_BadNoDataAvailable, value);
			}
		}

	}

	return std::pair<SnmpStatus, unsigned char >(Snmp_BadNotImplemented, value);

}

std::pair<SnmpStatus, std::string> SnmpBackend::snmpGetTime( const std::string& oidOfInterest )
{

	netsnmp_variable_list *vars;
	time_t value{};
	PduPtr response = snmpGet ( oidOfInterest );

	if (response)
	{

		/* manipulate the information ourselves */
		for(vars = response->variables; vars; vars = vars->next_variable)
		{
			if (vars->type == ASN_INTEGER)
				{
					value = *vars->val.integer;
					SnmpStatus status = Snmp_Good;
					
					char buf[64];
					strftime(buf, sizeof buf, "%a %b %e %H:%M:%S %Y\n", localtime(&value));
					std::string timeString(buf);

					if (value == -1 )
						status = Snmp_BadDataUnavailable;
					else
					{
						status = Snmp_Good;
					}
					return std::pair<SnmpStatus, std::string>( status, timeString );
				}
				else
				{
					LOG(Log::TRC, LogComponentLevels::mule()) << "There is no such variable name in this MIB. Type: 0x" << std::hex << (int)(vars->type)
									<< ". Failed OID: " << oidOfInterest;
					return std::pair<SnmpStatus, std::string>(Snmp_BadNoDataAvailable, "");
				}
		}

	}

	return std::pair<SnmpStatus, std::string>(Snmp_BadNotImplemented, "");

}

std::pair<SnmpStatus, std::vector<uint8_t>> SnmpBackend::snmpGetHex( const std::string& oidOfInterest )
{

	netsnmp_variable_list *vars;
	std::vector<uint8_t> value{};
	PduPtr response = snmpGet ( oidOfInterest );

	if (response)
	{

		/* manipulate the information ourselves */
		for(vars = response->variables; vars; vars = vars->next_variable)
		{
			if (vars->type == ASN_OCTET_STR)
			{

				uint8_t* myHexValue = (reinterpret_cast<uint8_t*>(vars->val.string));
				std::vector<uint8_t> hexValue(&myHexValue[0], &myHexValue[vars->val_len]);
				return std::pair<SnmpStatus, std::vector<uint8_t>>(Snmp_Good, hexValue);

			}
			else
			{

				LOG(Log::TRC, LogComponentLevels::mule()) << "There is no such variable name in this MIB. Type: 0x" << std::hex << (int)(vars->type)
								<< ". Failed OID: " << oidOfInterest;
				return std::pair<SnmpStatus, std::vector<uint8_t>>(Snmp_BadNoDataAvailable, value);

			}
		}

	}

	return std::pair<SnmpStatus, std::vector<uint8_t>>(Snmp_BadNotImplemented, value);

}

std::pair<SnmpStatus, float> SnmpBackend::snmpGetFloatFromString( const std::string& oidOfInterest )
{

	netsnmp_variable_list *vars;
	float value{0.0};
	PduPtr response = snmpGet ( oidOfInterest );

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
					return std::pair<SnmpStatus, float>(Snmp_BadNoDataAvailable, value);
				}
				else
				{
					try
					{
						value = std::stof( castToString );
					}
					catch (const std::exception& e)
					{
						LOG(Log::ERR, LogComponentLevels::mule()) << e.what() << ": Cannot convert sensor value. Due to sensor type? (OID:" << oidOfInterest << ")";
					}
				}
				return std::pair<SnmpStatus, float>(Snmp_Good, value);

			}
			else
			{

				LOG(Log::TRC, LogComponentLevels::mule()) << "There is no such variable name in this MIB. Type: 0x" << std::hex << (int)(vars->type)
								<< ". Failed OID: " << oidOfInterest;
				return std::pair<SnmpStatus, float>(Snmp_BadNoDataAvailable, value);

			}
		}

	}

	return std::pair<SnmpStatus, float>(Snmp_BadNotImplemented, value);

}

std::pair<SnmpStatus, float> SnmpBackend::snmpGetFloatFromInt( const std::string& oidOfInterest, const float& scaleFactor )
{
	const auto intResult = snmpGetInt(oidOfInterest);
	return { std::get<0>(intResult), scaleFactor * std::get<1>(intResult) };
}

std::string SnmpBackend::oidToString(const oid * objid, size_t objidlen, const netsnmp_variable_list * vars)
{

	std::string oid;
	oid = {std::to_string(*(objid))};
	for (uint32_t i = 1; i < objidlen; i++)
	{
	 	oid += "." + std::to_string(*(objid + i));
	}
	return oid;
}

std::pair<SnmpStatus, unsigned char > SnmpBackend::translateIntToBoolean ( int32_t rawValue )
{
	switch (rawValue) {
		case 1:
			return std::pair<SnmpStatus, unsigned char >( Snmp_Good, true );
			break;
		case 0:
			return std::pair<SnmpStatus, unsigned char >( Snmp_Good, false );
			break;
		case -1:
			return std::pair<SnmpStatus, unsigned char >( Snmp_BadDataUnavailable, false );
			break;
		default:
			return std::pair<SnmpStatus, unsigned char >( Snmp_Bad, false );
			break;
	}
}

}
