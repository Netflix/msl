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

#ifndef _MESSAGEHEADER_H_
#define _MESSAGEHEADER_H_

#include <msg/Header.h>
#include <io/MslEncoderFormat.h>
#include <stdint.h>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace netflix
{
namespace msl
{
class Date;
} /* namespace msl */
} /* namespace netflix */

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace crypto { class ICryptoContext; }
namespace entityauth { class EntityAuthenticationData; }
namespace io { class MslObject; class MslEncoderFormat; }
namespace keyx { class KeyRequestData; class KeyResponseData; }
namespace tokens { class MasterToken; class UserIdToken; class ServiceToken; class MslUser; }
namespace userauth { class UserAuthenticationData; }
namespace msg {
    
class MessageCapabilities;

/**
 * <p>If a master token exists, the header data chunks will be encrypted and
 * verified using the master token. The sender will also be included. If no
 * master token exists, the header data will be verified and encrypted based on
 * the entity authentication scheme.</p>
 *
 * <p>If peer tokens exist, the message recipient is expected to use the peer
 * master token to secure its response and send the peer user ID token and peer
 * service tokens back in the header data. The request's tokens should be
 * included as the response's peer tokens.</p>
 *
 * <p>If key response data exists, it applies to the token set the receiving
 * entity uses to identify itself. In a trusted services network the key
 * response data applies to the primary tokens. In a peer-to-peer network the
 * key response data applies to the peer tokens.</p>
 *
 * <p>The header data is represented as
 * {@code
 * headerdata = {
 *   "#mandatory" : [ "messageid", "renewable", "handshake" ],
 *   "timestamp" : "int64(0,2^53^)",
 *   "messageid" : "int64(0,2^53^)",
 *   "nonreplayableid" : "int64(0,2^53^)",
 *   "renewable" : "boolean",
 *   "handshake" : "boolean",
 *   "capabilities" : capabilities,
 *   "keyrequestdata" : [ keyrequestdata ],
 *   "keyresponsedata" : keyresponsedata,
 *   "userauthdata" : userauthdata,
 *   "useridtoken" : useridtoken,
 *   "servicetokens" : [ servicetoken ],
 *   "peermastertoken" : mastertoken,
 *   "peeruseridtoken" : useridtoken,
 *   "peerservicetokens" : [ servicetoken ]
 * }} where:
 * <ul>
 * <li>{@code timestamp} is the sender time when the header is created in seconds since the UNIX epoch</li>
 * <li>{@code messageid} is the message ID</li>
 * <li>{@code nonreplayableid} is the non-replayable ID</li>
 * <li>{@code renewable} indicates if the master token and user ID are renewable</li>
 * <li>{@code handshake} indicates a handshake message</li>
 * <li>{@code capabilities} lists the sender's message capabilities</li>
 * <li>{@code keyrequestdata} is session key request data</li>
 * <li>{@code keyresponsedata} is the session key response data</li>
 * <li>{@code userauthdata} is the user authentication data</li>
 * <li>{@code useridtoken} is the user ID token</li>
 * <li>{@code servicetokens} are the service tokens</li>
 * <li>{@code peermastertoken} is the peer master token</li>
 * <li>{@code peeruseridtoken} is the peer user ID token</li>
 * <li>{@code peerservicetokens} are the peer service tokens</li>
 * </ul></p>
 */
class MessageHeader : public Header
{
public:
    /**
     * Container struct for message header data.
     */
    struct HeaderData {
        /**
         * @param messageId the message ID.
         * @param nonReplayableId the message's non-replayable ID. May be -1.
         * @param renewable the message's renewable flag.
         * @param handshake the message's handshake flag.
         * @param capabilities the sender's message capabilities.
         * @param keyRequestData session key request data. May be null or
         *        empty.
         * @param keyResponseData session key response data. May be null.
         * @param userAuthData the user authentication data. May be null if a
         *        user ID token is provided or there is no user authentication
         *        for this message.
         * @param userIdToken the user ID token. May be null if user
         *        authentication data is provided or there is no user
         *        authentication for this message.
         * @param serviceTokens the service tokens. May be null or empty.
         */
        HeaderData(int64_t messageId, int64_t nonReplayableId,
            bool renewable, bool handshake, std::shared_ptr<MessageCapabilities> capabilities,
            std::set<std::shared_ptr<keyx::KeyRequestData>> keyRequestData, std::shared_ptr<keyx::KeyResponseData> keyResponseData,
            std::shared_ptr<userauth::UserAuthenticationData> userAuthData, std::shared_ptr<tokens::UserIdToken> userIdToken,
            std::set<std::shared_ptr<tokens::ServiceToken>> serviceTokens);

        const int64_t messageId;
        const int64_t nonReplayableId;  // Note: this -1 where 'null' is used in java
        const bool renewable;
        const bool handshake;
        std::shared_ptr<MessageCapabilities> capabilities;
        std::set<std::shared_ptr<keyx::KeyRequestData>> keyRequestData;
        std::shared_ptr<keyx::KeyResponseData> keyResponseData;
        std::shared_ptr<userauth::UserAuthenticationData> userAuthData;
        std::shared_ptr<tokens::UserIdToken> userIdToken;
        std::set<std::shared_ptr<tokens::ServiceToken>> serviceTokens;
    };

    /**
     * Container struct for header peer data.
     */
    struct HeaderPeerData
    {
        /**
         * @param peerMasterToken peer master token. May be null.
         * @param peerUserIdToken peer user ID token. May be null if there is
         *        no user authentication for the peer.
         * @param peerServiceTokens peer service tokens. May be empty.
         */
        HeaderPeerData(std::shared_ptr<tokens::MasterToken> peerMasterToken,
                std::shared_ptr<tokens::UserIdToken> peerUserIdToken,
                std::set<std::shared_ptr<tokens::ServiceToken>> peerServiceTokens);

        std::shared_ptr<tokens::MasterToken> peerMasterToken;
        std::shared_ptr<tokens::UserIdToken> peerUserIdToken;
        std::set<std::shared_ptr<tokens::ServiceToken>> peerServiceTokens;
    };

    /**
     * <p>Construct a new message header with the provided message data.</p>
     *
     * <p>Headers are encrypted and signed. If a master token is provided, it
     * will be used for this purpose. Otherwise the crypto context appropriate
     * for the entity authentication scheme will be used. N.B. Either the
     * entity authentication data or the master token must be provided.</p>
     *
     * <p>Peer tokens are only processed if operating in peer-to-peer mode.</p>
     *
     * @param ctx MSL context.
     * @param entityAuthData the entity authentication data. May be null if a
     *        master token is provided.
     * @param masterToken the master token. May be null if entity
     *        authentication data is provided.
     * @param headerData message header data container.
     * @param peerData message header peer data container.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslMasterTokenException if the header master token is not
     *         trusted and needs to be to accept this message header.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     */
    MessageHeader(std::shared_ptr<util::MslContext> ctx,
                  std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData,
                  std::shared_ptr<tokens::MasterToken> masterToken,
                  std::shared_ptr<HeaderData> headerData,
                  std::shared_ptr<HeaderPeerData> peerData);

    /**
     * @return true if the message header crypto context provides encryption.
     * @see #getCryptoContext()
     */
    bool isEncrypting() const;

    /**
     * Returns the crypto context that was used to process the header data.
     * This crypto context should also be used to process the payload data if
     * no key response data is included in the message.
     *
     * @return the header data crypto context.
     * @see #isEncrypting()
     */
    std::shared_ptr<crypto::ICryptoContext> getCryptoContext() const;

    /**
     * Returns the user if the user has been authenticated or a user ID token
     * was provided.
     *
     * @return the user. May be null.
     */
    std::shared_ptr<tokens::MslUser> getUser() const;

    /**
     * Returns the entity authentication data. May be null if the entity has
     * already been authenticated and is using a master token instead.
     *
     * @return the entity authentication data.
     */
    std::shared_ptr<entityauth::EntityAuthenticationData> getEntityAuthenticationData() const;

    /**
     * Returns the primary master token identifying the entity and containing
     * the session keys. May be null if the entity has not been authenticated.
     *
     * @return the master token. May be null.
     */
    std::shared_ptr<tokens::MasterToken> getMasterToken() const;

    /**
     * @return the timestamp. May be null.
     */
    std::shared_ptr<Date> getTimestamp() const;

    /**
     * @return the message ID.
     */
    int64_t getMessageId() const;

    /**
     * @return the non-replayable ID. May be -1 indicating no ID.
     */
    int64_t getNonReplayableId() const;

    /**
     * @return true if the message renewable flag is set.
     */
    bool isRenewable() const;

    /**
     * @return true if the message handshake flag is set.
     */
    bool isHandshake() const;

    /**
     * @return the message capabilities. May be null.
     */
    std::shared_ptr<MessageCapabilities> getMessageCapabilities() const;

    /**
     * @return key request data. May be empty.
     */
    std::set<std::shared_ptr<keyx::KeyRequestData>> getKeyRequestData() const;

    /**
     * @return key response data. May be null.
     */
    std::shared_ptr<keyx::KeyResponseData> getKeyResponseData() const;

    /**
     * Returns the user authentication data. May be null if the user has
     * already been authenticated and is using a user ID token or if there is
     * no user authentication requested.
     *
     * @return the user authentication data. May be null.
     */
    std::shared_ptr<userauth::UserAuthenticationData> getUserAuthenticationData() const;

    /**
     * Returns the primary user ID token identifying the user. May be null if
     * the user has not been authenticated.
     *
     * @return the user ID token. May be null.
     */
    std::shared_ptr<tokens::UserIdToken> getUserIdToken() const;

    /**
     * Returns the primary service tokens included in this message.
     *
     * The returned list is immutable.
     *
     * @return the service tokens. May be empty if no there are no service
     *         tokens.
     */
    std::set<std::shared_ptr<tokens::ServiceToken>> getServiceTokens() const;

    /**
     * Returns the master token that should be used by an entity responding to
     * this message. Will be null if the responding entity should use its own
     * entity authentication data or the primary master token.
     *
     * @return the peer master token. May be null.
     */
    std::shared_ptr<tokens::MasterToken> getPeerMasterToken() const;

    /**
     * Returns the user ID token that must be used by an entity responding to
     * this message if an peer master token is provided. May be null if peer
     * user authentication has not occurred. Will be null if there is no peer
     * master token.
     *
     * @return the peer user ID token. May be null.
     */
    std::shared_ptr<tokens::UserIdToken> getPeerUserIdToken() const;

    /**
     * <p>Returns the service tokens that must be used by an entity responding
     * to this message. May be null if the responding entity should use the
     * primary service tokens.</p>
     *
     * <p>The returned list is immutable.</p>
     *
     * @return the peer service tokens. May be empty if no there are no peer
     *         service tokens.
     */
    std::set<std::shared_ptr<tokens::ServiceToken>> getPeerServiceTokens() const;

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    virtual bool equals(std::shared_ptr<const Header> other) const;

//protected:  // FIXME: java code has the constructor below protected, but then Header.cpp does not compile

    /**
     * <p>Construct a new message from the provided JSON object.</p>
     *
     * <p>Headers are encrypted and signed. If a master token is found, it will
     * be used for this purpose. Otherwise the crypto context appropriate for
     * the entity authentication scheme will be used. Either the master token
     * or entity authentication data must be found.</p>
     *
     * <p>If user authentication data is included user authentication will be
     * performed. If a user ID token is included then its user information is
     * considered to be trusted.</p>
     *
     * <p>Service tokens will be decrypted and verified with the provided crypto
     * contexts identified by token name. A default crypto context may be
     * provided by using the empty string as the token name; if a token name is
     * not explicitly mapped onto a crypto context, the default crypto context
     * will be used.</p>
     *
     * @param ctx MSL context.
     * @param headerdataBytes encoded header data.
     * @param entityAuthData the entity authentication data. May be null if a
     *        master token is provided.
     * @param masterToken the master token. May be null if entity
     *        authentication data is provided.
     * @param signature the header signature.
     * @param cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header or creating the key exchange crypto context.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data or there is an error with the entity
     *         authentication data.
     * @throws MslKeyExchangeException if unable to create the key request data
     *         or key response data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data or authenticate the user.
     * @throws MslMasterTokenException if the header master token is not
     *         trusted and needs to be to accept this message header.
     * @throws MslMessageException if the message does not contain an entity
     *         authentication data or a master token, the header data is
     *         missing or invalid, or the message ID is negative, or the
     *         message is not encrypted and contains user authentication data.
     * @throws MslException if a token is improperly bound to another token.
     */
    MessageHeader(std::shared_ptr<util::MslContext> ctx,
                  std::shared_ptr<ByteArray> headerdataBytes,
                  std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData,
                  std::shared_ptr<tokens::MasterToken> masterToken,
                  std::shared_ptr<ByteArray> signature,
                  const std::map<std::string, std::shared_ptr<crypto::ICryptoContext>>& cryptoContexts);

protected:
    /** Entity authentication data. */
    std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData;
    /** Master token. */
    std::shared_ptr<tokens::MasterToken> masterToken;
    /** Header data. */
    std::shared_ptr<io::MslObject> headerdata;
    /** Message crypto context. */
    std::shared_ptr<crypto::ICryptoContext> messageCryptoContext;
    /** Cached encodings. */
    mutable std::map<io::MslEncoderFormat, std::shared_ptr<ByteArray>> encodings;

private:
    /** Timestamp in seconds since the epoch. */
    int64_t timestamp;   // Note: this is -1 where 'null' is used in java
    /** Message ID. */
    int64_t messageId;
    /** Non-replayable ID. */
    int64_t nonReplayableId;   // Note: this is -1 where 'null' is used in java
    /** Renewable. */
    bool renewable;
    /** Handshake message. */
    bool handshake;
    /** Message capabilities. */
    std::shared_ptr<MessageCapabilities> capabilities;
    /** Key request data. */
    std::set<std::shared_ptr<keyx::KeyRequestData>> keyRequestData;
    /** Key response data. */
    std::shared_ptr<keyx::KeyResponseData> keyResponseData;
    /** User authentication data. */
    std::shared_ptr<userauth::UserAuthenticationData> userAuthData;
    /** User ID token. */
    std::shared_ptr<tokens::UserIdToken> userIdToken;
    /** Service tokens (immutable). */
    std::set<std::shared_ptr<tokens::ServiceToken>> serviceTokens;

    /** Peer master token. */
    std::shared_ptr<tokens::MasterToken> peerMasterToken;
    /** Peer user ID token. */
    std::shared_ptr<tokens::UserIdToken> peerUserIdToken;
    /** Peer service tokens (immutable). */
    std::set<std::shared_ptr<tokens::ServiceToken>> peerServiceTokens;

    /** User (if authenticated). */
    std::shared_ptr<tokens::MslUser> user;

    friend std::ostream& operator<<(std::ostream& os, const MessageHeader& header);
};

bool operator==(const MessageHeader& a, const MessageHeader& b);
inline bool operator!=(const MessageHeader& a, const MessageHeader& b) { return !(a == b); }

std::ostream& operator<<(std::ostream& os, const MessageHeader& header);
std::ostream& operator<<(std::ostream& os, std::shared_ptr<MessageHeader> header);

}}} // namespace netflix::msl::msg

#endif
