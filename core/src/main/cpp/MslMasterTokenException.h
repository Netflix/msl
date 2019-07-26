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

#ifndef SRC_MSLMASTERTOKENEXCEPTION_H_
#define SRC_MSLMASTERTOKENEXCEPTION_H_

#include <MslException.h>
#include <stdint.h>
#include <memory>

namespace netflix {
namespace msl {
namespace tokens { class MasterToken; class UserIdToken; }
namespace userauth { class UserAuthenticationData; }

class MslError;

/**
 * Thrown when there is a problem with a master token, but the token was
 * successfully parsed.
 */
class MslMasterTokenException : public MslException
{
public:
    virtual ~MslMasterTokenException() {}

    /**
     * Construct a new MSL master token exception with the specified error and
     * master token.
     *
     * @param error the error.
     * @param masterToken the master token. May be null.
     */
    MslMasterTokenException(const MslError& error, std::shared_ptr<tokens::MasterToken> masterToken) : MslException(error) {
        setMasterToken(masterToken);
    }

    /**
      * Construct a new MSL master token exception with the specified error and
      * master token.
      *
      * @param error the error.
      * @param masterToken the master token. May be null.
      * @param cause the exception that triggered this exception being thrown
      */
     MslMasterTokenException(const MslError& error, std::shared_ptr<tokens::MasterToken> masterToken, const IException& cause)
     : MslException(error, cause) {
         setMasterToken(masterToken);
     }

     virtual MslMasterTokenException& setMessageId(int64_t messageId) {
         MslException::setMessageId(messageId);
         return *this;
     }

     virtual MslMasterTokenException& setMasterToken(std::shared_ptr<tokens::MasterToken> masterToken) {
         MslException::setMasterToken(masterToken);
         return *this;
     }

     virtual MslMasterTokenException& setEntityAuthenticationData(std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData) {
         MslException::setEntityAuthenticationData(entityAuthData);
         return *this;
     }

     virtual MslMasterTokenException& setUserIdToken(std::shared_ptr<tokens::UserIdToken> userIdToken) {
         MslException::setUserIdToken(userIdToken);
         return *this;
     }

     virtual MslMasterTokenException& setUserAuthenticationData(std::shared_ptr<userauth::UserAuthenticationData> userAuthData) {
         MslException::setUserAuthenticationData(userAuthData);
         return *this;
     }

    DECLARE_EXCEPTION_CLONE(MslMasterTokenException);

private:
    MslMasterTokenException(); // not implemented
};

}} // namespace netflix::msl

#endif /* SRC_MSLMASTERTOKENEXCEPTION_H_ */
