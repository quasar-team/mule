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

namespace Snmp
{

class Oid
{
public:
	Oid();
	Oid( unsigned int deviceTypeOid, 
		 unsigned int subDeviceTypeOid, 
		 unsigned int variableOid, 
		 unsigned int deviceNumOid, 
		 unsigned int sequenceNumOid );
	explicit Oid( std::string oidOfInterest );
	virtual ~Oid();

private:
	std::string m_rootOid;
	unsigned int m_deviceTypeOid;
	unsigned int m_subDeviceTypeOid;
	unsigned int m_variableOid;
	unsigned int m_deviceNumOid;
	unsigned int m_sequenceNumOid = 0;
	bool m_valid = true;
	bool m_sensor = false;
	unsigned int m_oidSize = 0;

public:

	std::string getOid() { return m_rootOid +
			"." + std::to_string(m_deviceTypeOid) +
			"." + std::to_string(m_subDeviceTypeOid) +
			"." + std::to_string(m_variableOid) +
			"." + std::to_string(m_deviceNumOid);};

	std::string getSensorOid() { return getOid() +
			"." + std::to_string(m_sequenceNumOid);
	}

	void nextDeviceType() { m_deviceTypeOid++; };
	void nextSubDeviceType() { m_subDeviceTypeOid++; };
	void nextVariable() { m_variableOid++; };
	void nextDeviceNum() { m_deviceNumOid++; };

	unsigned int getDeviceType() {return m_deviceTypeOid;};
	unsigned int getSubDeviceType() {return m_subDeviceTypeOid;};
	unsigned int getVariable() {return m_variableOid;};
	unsigned int getDeviceNum() {return m_deviceNumOid;};
	unsigned int getSequenceNum() {return m_sequenceNumOid;};

	bool getOidValidity(){return m_valid;};
	unsigned int getOidSize(){return m_oidSize;};

	bool isSensor(){return m_sensor;};
	void setSensor(bool sensor){m_sensor = sensor;};

	void assign( std::string );
};

} // oid