/**
 * Copyright (c) 2018 Netflix, Inc.  All rights reserved.
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
#ifndef SRC_MSG_SERVERRECEIVEMESSAGECONTEXT_H_
#define SRC_MSG_SERVERRECEIVEMESSAGECONTEXT_H_

#include <msg/PublicMessageContext.h>

#include <map>
#include <string>

namespace netflix {
namespace msl {
namespace crypto { class ICryptoContext; }
namespace keyx { class KeyRequestData; }
namespace tokens { class MslUser; }
namespace userauth { class UserAuthenticationData; }
namespace msg {
class MessageDebugContext; class MessageOutputStream; class MessageServiceTokenBuilder;

/**
 * <p>A trusted services network message context used to receive client
 * messages suitable for use with
 * {@link MslControl#receive(com.netflix.msl.util.MslContext, MessageContext, java.io.InputStream, java.io.OutputStream, int)}.
 * Since this message context is only used for receiving messages, it cannot be
 * used to send application data back to the client and does not require
 * encryption or integrity protection.</p>
 *
 * <p>The application may wish to override
 * {@link #updateServiceTokens(MessageServiceTokenBuilder, boolean)} to
 * modify any service tokens sent in handshake responses.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class ServerReceiveMessageContext : public PublicMessageContext
{
public:
    virtual ~ServerReceiveMessageContext() {}

    /**
     * <p>Create a new receive message context.</p>
     *
     * @param cryptoContexts service token crypto contexts. May be
     *        {@code null}.
     * @param dbgCtx optional message debug context. May be {@code null}.
     */
    ServerReceiveMessageContext(std::map<std::string,std::shared_ptr<crypto::ICryptoContext>> cryptoContexts, std::shared_ptr<MessageDebugContext> dbgCtx)
        : cryptoContexts_(cryptoContexts)
        , dbgCtx_(dbgCtx)
    {}

    /** @inheritDoc */
    std::map<std::string,std::shared_ptr<crypto::ICryptoContext>> getCryptoContexts() {
        return std::map<std::string,std::shared_ptr<crypto::ICryptoContext>>(cryptoContexts_);
    }

    /** @inheritDoc */
    std::string getRecipient() { return std::string(); }

    /** @inheritDoc */
    bool isRequestingTokens() { return false; }

    /** @inheritDoc */
    std::string getUserId() { return std::string(); }

    /** @inheritDoc */
    std::shared_ptr<userauth::UserAuthenticationData> getUserAuthData(const ReauthCode& reauthCode, bool renewable, bool required) { return std::shared_ptr<userauth::UserAuthenticationData>(); }

    /** @inheritDoc */
    std::shared_ptr<tokens::MslUser> getUser() { return std::shared_ptr<tokens::MslUser>(); }

    /** @inheritDoc */
    std::set<keyx::KeyRequestData> getKeyRequestData() { return std::set<keyx::KeyRequestData>(); }

    /** @inheritDoc */
    void updateServiceTokens(std::shared_ptr<MessageServiceTokenBuilder> builder, bool handshake) {}

    /** @inheritDoc */
    void write(std::shared_ptr<MessageOutputStream> output) {}

    /** @inheritDoc */
    std::shared_ptr<MessageDebugContext> getDebugContext() { return dbgCtx_; }

protected:
    /** Service token crypto contexts. */
    std::map<std::string,crypto::ICryptoContext> cryptoContexts_;
    /** Message debug context. */
    std::shared_ptr<MessageDebugContext> dbgCtx_;
};

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_SERVERRECEIVEMESSAGECONTEXT_H_ */
