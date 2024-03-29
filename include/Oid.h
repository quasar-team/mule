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

#pragma once

#include <string>
#include <vector>

namespace Snmp
{

class Oid
{
public:
	explicit Oid( const std::string& oidOfInterest );
	virtual ~Oid() = default;

private:

	friend class SnmpBackend;

	std::string m_originalString;
	std::vector<std::string> m_oidVector;
	uint32_t m_oidSize;
	void assign( std::string );

public:

	const std::string& getOidString() const { return m_originalString; };
	const std::vector<std::string>& getOidVector() const { return m_oidVector; };
	void printOidFromVector();
	uint32_t getOidSize() { return m_oidSize; };
	Oid& operator()( const std::string& );

};

} // Snmp