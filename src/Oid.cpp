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
#include <vector>
#include <MuleLogComponents.h>

using namespace Snmp;
using Mule::LogComponentLevels;

Oid::Oid( const std::string& oidOfInterest ) : m_originalString(oidOfInterest)
{
	this->assign(oidOfInterest);
}

Oid& Oid::operator()( const std::string& oidOfInterest )
{
	this->assign(oidOfInterest);
	return *this;
}

void Oid::assign ( std::string oidOfInterest )
{

	m_originalString = oidOfInterest;
	m_oidVector.clear();
	char delim = '.';

	std::size_t current, previous = 0;
	current = oidOfInterest.find(delim);
	while (current != std::string::npos) {
		m_oidVector.push_back(oidOfInterest.substr(previous, current - previous));
		previous = current + 1;
		current = oidOfInterest.find(delim, previous);
	}
	m_oidVector.push_back(oidOfInterest.substr(previous, current - previous));

	m_oidSize = m_oidVector.size();

}

void Oid::printOidFromVector()
{
	std::string oid;

	for (const auto oidPart: m_oidVector) 
	{
        oid += oidPart + '.';
    }
	oid.pop_back();
	LOG(Log::INF, LogComponentLevels::mule()) << oid;
}

