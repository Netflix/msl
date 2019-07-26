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

#ifndef SRC_UTIL_NULLAUTHENTICATIONUTILS_H_
#define SRC_UTIL_NULLAUTHENTICATIONUTILS_H_

#include <util/AuthenticationUtils.h>

namespace netflix {
namespace msl {
namespace util {

/**
 * <p>An authentication utilities implementation where all operations are
 * permitted.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class NullAuthenticationUtils: public AuthenticationUtils
{
public:
    virtual ~NullAuthenticationUtils() {}

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isEntityRevoked(java.lang.String)
     */
    virtual bool isEntityRevoked(const std::string& identity) {
        return false;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.entityauth.EntityAuthenticationScheme)
     */
    virtual bool isSchemePermitted(const std::string& identity, const entityauth::EntityAuthenticationScheme& scheme) {
        return true;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    virtual bool isSchemePermitted(const std::string& identity, const userauth::UserAuthenticationScheme& scheme) {
        return true;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.tokens.MslUser, com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    virtual bool isSchemePermitted(const std::string& identity, std::shared_ptr<tokens::MslUser> user, const userauth::UserAuthenticationScheme& scheme) {
        return true;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.keyx.KeyExchangeScheme)
     */
    virtual bool isSchemePermitted(const std::string& identity, const keyx::KeyExchangeScheme& scheme) {
        return true;
    }
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_NULLAUTHENTICATIONUTILS_H_ */
