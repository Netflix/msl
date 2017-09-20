/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "MessageContext.h"

namespace netflix {
namespace msl {
namespace msg {

const MessageContext::ReauthCode MessageContext::ReauthCode::USERDATA_REAUTH(ReauthCode::userdata_reauth, "USERDATA_REAUTH", MslConstants::ResponseCode::USERDATA_REAUTH);
const MessageContext::ReauthCode MessageContext::ReauthCode::SSOTOKEN_REJECTED(ReauthCode::ssotoken_rejected, "SSOTOKEN_REJECTED", MslConstants::ResponseCode::SSOTOKEN_REJECTED);
const MessageContext::ReauthCode MessageContext::ReauthCode::INVALID(ReauthCode::invalid, "INVALID", MslConstants::ResponseCode::FAIL);

const std::vector<MessageContext::ReauthCode>& MessageContext::ReauthCode::getValues() {
	static std::vector<MessageContext::ReauthCode> gValues;
	if (gValues.empty()) {
		gValues.push_back(USERDATA_REAUTH);
		gValues.push_back(SSOTOKEN_REJECTED);
		gValues.push_back(INVALID);
	}
	return gValues;
}

}}} // namespace netflix::msl::msg
