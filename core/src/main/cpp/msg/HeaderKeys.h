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

#ifndef SRC_MSG_HEADERKEYS_H_
#define SRC_MSG_HEADERKEYS_H_
#include <string>

namespace netflix {
namespace msl {
namespace msg {

/**
 * <p>Common header keys.</p>
 */
namespace HeaderKeys
{
/** Key entity authentication data. */
const std::string KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
/** Key master token. */
const std::string KEY_MASTER_TOKEN = "mastertoken";
/** Key header data. */
const std::string KEY_HEADERDATA = "headerdata";
/** Key error data. */
const std::string KEY_ERRORDATA = "errordata";
/** Key signature. */
const std::string KEY_SIGNATURE = "signature";
}

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_HEADERKEYS_H_ */
