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

#ifndef SRC_MSG_ERRORMESSAGEREGISTRY_H_
#define SRC_MSG_ERRORMESSAGEREGISTRY_H_

#include <MslError.h>
#include <string>

namespace netflix {
namespace msl {
namespace msg {

/**
 * <p>The error message registry is used to provide localized user-consumable
 * messages for specific MSL errors.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class ErrorMessageRegistry
{
public:
	virtual ~ErrorMessageRegistry() {}

    /**
     * Returns the user-consumable message associated with the given MSL error,
     * localized according to the list of preferred languages.
     *
     * @param err MSL error.
     * @param languages preferred languages as BCP-47 codes in descending
     *        order. May be empty.
     * @return the localized user message or the empty string if there is none.
     */
    virtual std::string getUserMessage(const MslError& err, const std::vector<std::string>& languages) = 0;

    /**
     * Returns the user-consumable message associated with a given non-MSL
     * error, localized according to the list of preferred languages.
     *
     * @param err non-MSL error.
     * @param languages preferred languages as BCP-47 codes in descending
     *        order. May be empty.
     * @return the localized user message or the empty string if there is none.
     */
    virtual std::string getUserMessage(const IException& err, const std::vector<std::string>& languages) = 0;
};

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_ERRORMESSAGEREGISTRY_H_ */
