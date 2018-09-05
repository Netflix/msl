/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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

#ifndef SRC_MSG_IDEMPOTENT_RESPONSE_MESSAGE_BUILDER_H_
#define SRC_MSG_IDEMPOTENT_RESPONSE_MESSAGE_BUILDER_H_

#include <MslError.h>
#include <keyx/KeyExchangeFactory.h>
#include <msg/MessageBuilder.h>
#include <map>
#include <memory>
#include <set>
#include <string>

namespace netflix {
namespace msl {
namespace entityauth { class EntityAuthenticationData; }
namespace keyx { class KeyRequestData; }
namespace tokens { class MasterToken; class UserIdToken; class ServiceToken; class MslUser; }
namespace userauth { class UserAuthenticationData; }
namespace util { class MslContext; }
namespace msg {
class ErrorHeader; class MessageHeader; class MessageCapabilities;

/**
 * <p>A message builder provides methods for building messages.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class IdempotentResponseMessageBuilder : public MessageBuilder
{
public:

    /**
     * Create a new message builder that will craft a new message in response
     * to another message without issuing or renewing any master tokens or user
     * ID tokens. The constructed message may be used as a request.
     *
     * @param ctx MSL context.
     * @param requestHeader message header to respond to.
     * @return the message builder.
     * @throws MslCryptoException if there is an error accessing the remote
     *         entity identity.
     * @throws MslException if any of the request's user ID tokens is not bound
     *         to its master token.
     */
    IdempotentResponseMessageBuilder(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageHeader> requestHeader);
    
};
    
}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_IDEMPOTENT_RESPONSE_MESSAGE_BUILDER_H_ */
