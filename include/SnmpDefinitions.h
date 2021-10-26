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

	namespace Constants
	{

	int const SNMP_TIMEOUT = 1000000;
	int const SNMP_MAX_RETRIES = 2;

    enum Pdu
    {
        GET = 0,
        SET = 1,
        GET_NEXT = 2,
        GET_BULK = 3,
        TRAP = 4,
        INFORM = 5
    };

    enum Errors
    {
        NO_SUCH_NAME = 0,
        BAD_VALUE = 1,
        TOO_BIG = 2,
        GENERIC_ERROR = 3,
        // SNMP v2 +
        WRONG_VALUE = 4,
        WRONG_ENCODING = 5,
        WRONG_TYPE = 6,
        WRONG_LENGTH = 7,
        INCONSISTENT_VALUE = 8,
        NO_ACCESS = 9,
        NOT_WRITABLE = 10,
        NO_CREATION = 11,
        INCONSISTENT_NAME = 12,
        RESOURCE_UNAVAILABLE = 13,
        COMMIT_FAILED = 14,
        UNDO_FAILED = 15

    };

    enum Exceptions
    {
        NO_SUCH_OBJECT = 0,
        NO_SUCH_INSTANCE = 1
    };

  }

}
