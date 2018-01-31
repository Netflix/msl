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

#include <MslException.h>
#include <tokens/UserIdToken.h>
#include <userauth/UserAuthenticationData.h>
#include <sstream>

using namespace std;

namespace netflix {
namespace msl {

namespace {

// Recurse through the cause exception stack, until we find the first
// MslException (typename D) that has a non-empty func() return, or else
// return the default of whatever func() wants to return.
template<typename T, typename D>
T recurseCauses(shared_ptr<IException> cause, T (D::*func)() const) {
    if (cause && instanceof<D>(cause.get())) {
        const shared_ptr<D> mslCause = dynamic_pointer_cast<D>(cause);
        return (mslCause.get()->*func)();  // recurse
    } else {
        return T();
    }
}

} // namespace anonymous

MslException::MslException(const MslError& error)
    : Exception(error.getMessage()), error_(error), messageId_(0)
{
}

MslException::MslException(const MslError& error, const string& details)
    : Exception(error.getMessage() + " [" + details + "]"),
      error_(error),
      messageId_(0)
{
}

MslException::MslException(const MslError& error, const string& details,
        const IException& cause)
    : Exception(error.getMessage() + " [" + details + "]", cause),
      error_(error),
      messageId_(0)
{
}

MslException::MslException(const MslError& error, const IException& cause)
    : Exception(error.getMessage(), cause), error_(error), messageId_(0)
{
}

int64_t MslException::getMessageId() const
{
    if (messageId_ != 0)
        return messageId_;
    return recurseCauses(cause_, &MslException::getMessageId);
}

MslException& MslException::setMessageId(int64_t messageId)
{
    if (messageId > MslConstants::MAX_LONG_VALUE)
    {
        ostringstream sstream;
        sstream << "Message ID " << messageId << " is outside the valid range.";
        throw out_of_range(sstream.str());
    }
    if (getMessageId() == 0ll)
        messageId_ = messageId;
    return *this;
}

shared_ptr<tokens::MasterToken> MslException::getMasterToken() const
{
    if (masterToken_)
        return masterToken_;
    return recurseCauses(cause_, &MslException::getMasterToken);
}

MslException& MslException::setMasterToken(shared_ptr<tokens::MasterToken> masterToken)
{
    if (!getMasterToken() && !getEntityAuthenticationData())
        masterToken_ = masterToken;
    return *this;
}

std::shared_ptr<entityauth::EntityAuthenticationData> MslException::getEntityAuthenticationData() const
{
    if (entityAuthData_)
        return entityAuthData_;
    return recurseCauses(cause_, &MslException::getEntityAuthenticationData);
}

MslException& MslException::setEntityAuthenticationData(shared_ptr<entityauth::EntityAuthenticationData> entityAuthData)
{
    if (!getMasterToken() && !getEntityAuthenticationData())
        entityAuthData_ = entityAuthData;
    return *this;
}

MslException& MslException::setUserIdToken(shared_ptr<tokens::UserIdToken> userIdToken)
{
    if (!getUserIdToken() && !getUserAuthenticationData())
        userIdToken_ = userIdToken;
    return *this;
}

shared_ptr<tokens::UserIdToken> MslException::getUserIdToken() const
{
    if (userIdToken_)
        return userIdToken_;
    return recurseCauses(cause_, &MslException::getUserIdToken);
}

MslException& MslException::setUserAuthenticationData(shared_ptr<userauth::UserAuthenticationData> userAuthData)
{
    if (!getUserIdToken() && !getUserAuthenticationData())
        userAuthData_ = userAuthData;
    return *this;
}

std::shared_ptr<userauth::UserAuthenticationData> MslException::getUserAuthenticationData() const
{
    if (userAuthData_)
        return userAuthData_;
    return recurseCauses(cause_, &MslException::getUserAuthenticationData);
}

} /* namespace msl */
} /* namespace netflix */
