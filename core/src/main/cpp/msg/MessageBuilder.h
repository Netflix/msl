/**
 * Copyright (c) 2016-2020 Netflix, Inc.  All rights reserved.
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

#ifndef SRC_MSG_MESSAGE_BUILDER_H_
#define SRC_MSG_MESSAGE_BUILDER_H_

#include <MslError.h>
#include <keyx/KeyExchangeFactory.h>
#include <memory>
#include <set>
#include <string>
#include <msg/MessageHeader.h>

namespace netflix {
namespace msl {
namespace entityauth { class EntityAuthenticationData; }
namespace keyx { class KeyRequestData; }
namespace tokens { class MasterToken; class UserIdToken; class ServiceToken; class MslUser; }
namespace userauth { class UserAuthenticationData; }
namespace util { class MslContext; }
namespace msg {
class ErrorHeader; class MessageCapabilities;

/**
 * <p>A message builder provides methods for building messages.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MessageBuilder : public std::enable_shared_from_this<MessageBuilder>
{
public:
    /**
     * Increments the provided message ID by 1, wrapping around to zero if
     * the provided value is equal to {@link MslConstants#MAX_LONG_VALUE}.
     * 
     * @param messageId the message ID to increment.
     * @return the message ID + 1.
     * @throws MslInternalException if the provided message ID is out of range.
     */
    static int64_t incrementMessageId(const int64_t messageId);
    
    /**
     * Decrements the provided message ID by 1, wrapping around to
     * {@link MslConstants#MAX_LONG_VALUE} if the provided value is equal to 0.
     * 
     * @param messageId the message ID to decrement.
     * @return the message ID - 1.
     * @throws MslInternalException if the provided message ID is out of range.
     */
    static int64_t decrementMessageId(const int64_t messageId);

    /**
     * <p>Create a new message builder that will craft a new message with the
     * specified message ID.</p>
     * 
     * @param ctx MSL context.
     * @param std::shared_ptr<tokens::MasterToken> master token. May be null unless a user ID token is
     *        provided.
     * @param std::shared_ptr<tokens::UserIdToken> user ID token. May be null.
     * @param messageId the message ID to use. Must be within range.
     * @throws MslException if a user ID token is not bound to its
     *         corresponding master token.
     */
    MessageBuilder(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<tokens::MasterToken> masterToken,
            std::shared_ptr<tokens::UserIdToken> userIdToken,
            int64_t messageId);

    /**
     * <p>Create a new message builder that will craft a new message.</p>
     * 
     * @param ctx MSL context.
     * @param std::shared_ptr<tokens::MasterToken> master token. May be null unless a user ID token is
     *        provided.
     * @param std::shared_ptr<tokens::UserIdToken> user ID token. May be null.
     * @throws MslException if a user ID token is not bound to its
     *         corresponding master token.
     */
    MessageBuilder(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<tokens::MasterToken> masterToken,
            std::shared_ptr<tokens::UserIdToken> userIdToken);

    /**
     * @return the message ID the builder will use.
     */
    int64_t getMessageId() { return messageId_; }
    
    /**
     * @return the primary master token or null if the message will use entity
     *         authentication data.
     */
    std::shared_ptr<tokens::MasterToken> getMasterToken() { return masterToken_; }

    /**
     * @return the primary user ID token or null if the message will use user
     *         authentication data.
     */
    std::shared_ptr<tokens::UserIdToken> getUserIdToken() { return userIdToken_; }

    /**
     * @return the key exchange data or null if there is none.
     */
    std::shared_ptr<keyx::KeyExchangeFactory::KeyExchangeData> getKeyExchangeData() { return keyExchangeData_; }

    /**
     * @return true if the message builder will create a message capable of
     *         encrypting the header data.
     */
    bool willEncryptHeader();

    /**
     * @return true if the message builder will create a message capable of
     *         encrypting the payload data.
     */
    bool willEncryptPayloads();

    /**
     * @return true if the message builder will create a message capable of
     *         integrity protecting the header data.
     */
    bool willIntegrityProtectHeader();

    /**
     * @return true if the message builder will create a message capable of
     *         integrity protecting the payload data.
     */
    bool willIntegrityProtectPayloads();

    /**
     * Construct the message header from the current message builder state.
     * 
     * @return the message header.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslMasterTokenException if the header master token is not
     *         trusted and needs to be to accept this message header.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     * @throws MslMessageException if the message is non-replayable but does
     *         not include a master token.
     * @throws MslException should not happen.
     */
    std::shared_ptr<MessageHeader> getHeader();

    /**
     * <p>Set the message ID.</p>
     *
     * <p>This method will override the message ID that was computed when the
     * message builder was created, and should not need to be called in most
     * cases.</p>
     *
     * @param messageId the message ID.
     * @return this.
     * @throws MslInternalException if the message ID is out of range.
     */
    std::shared_ptr<MessageBuilder> setMessageId(int64_t messageId);

    /**
     * @return true if the message will be marked non-replayable.
     */
    bool isNonReplayable() { return nonReplayable_; }
    
    /**
     * Make the message non-replayable. If true this will also set the
     * handshake flag to false.
     * 
     * @param nonReplayable true if the message should be non-replayable.
     * @return this.
     * @see #setHandshake(bool);
     */
    std::shared_ptr<MessageBuilder>setNonReplayable(bool nonReplayable);
    
    /**
     * @return true if the message will be marked renewable.
     */
    bool isRenewable() { return renewable_; }

    /**
     * Set the message renewable flag. If false this will also set the
     * handshake flag to false.
     *
     * @param renewable true if the message is renewable.
     * @return this.
     * @see #setHandshake(bool);
     */
    std::shared_ptr<MessageBuilder> setRenewable(bool renewable);

    /**
     * @return true if the message will be marked as a handshake message.
     */
    bool isHandshake() { return handshake_; }

    /**
     * Set the message handshake flag. If true this will also set the non-
     * replayable flag to false and the renewable flag to true.
     * 
     * @param handshake true if the message is a handshake message.
     * @return this.
     * @see #setNonReplayable(bool);
     * @see #setRenewable(bool);
     */
    std::shared_ptr<MessageBuilder> setHandshake(bool handshake);

    /**
     * <p>Set or change the master token and user ID token. This will overwrite
     * any existing tokens. If the user ID token is not null then any existing
     * user authentication data will be removed.</p>
     *
     * <p>Changing these tokens may result in invalidation of existing service
     * tokens. Those service tokens will be removed from the message being
     * built.</p>
     * 
     * <p>This is a special method for the {@link MslControl} class that assumes
     * the builder does not have key response data in trusted network mode.</p>
     * 
     * @param std::shared_ptr<tokens::MasterToken> the master token.
     * @param std::shared_ptr<tokens::UserIdToken> the user ID token. May be null.
     */
    void setAuthTokens(std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<tokens::UserIdToken> userIdToken);

    /**
     * <p>Set the user authentication data of the message.</p>
     * 
     * <p>This will overwrite any existing user authentication data.</p>
     * 
     * @param userAuthData user authentication data to set. May be null.
     * @return this.
     */
    std::shared_ptr<MessageBuilder> setUserAuthenticationData(std::shared_ptr<userauth::UserAuthenticationData> userAuthData);

    /**
     * <p>Set the remote user of the message. This will create a user ID token
     * in trusted network mode or peer user ID token in peer-to-peer mode.</p>
     * 
     * <p>Adding a new user ID token will not impact the service tokens; it is
     * assumed that no service tokens exist that are bound to the newly created
     * user ID token.</p>
     * 
     * <p>This is a special method for the {@link MslControl} class that assumes
     * the builder does not already have a user ID token for the remote user
     * and does have a master token that the new user ID token can be bound
     * against.</p>
     * 
     * @param user remote user.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslException if there is an error creating the user ID token.
     */
    void setUser(std::shared_ptr<tokens::MslUser> user);

    /**
     * Add key request data to the message.
     * 
     * @param std::shared_ptr<keyx::KeyRequestData> key request data to add.
     * @return this.
     */
    std::shared_ptr<MessageBuilder> addKeyRequestData(std::shared_ptr<keyx::KeyRequestData> keyRequestData);

    /**
     * Remove key request data from the message.
     * 
     * @param std::shared_ptr<keyx::KeyRequestData> key request data to remove.
     * @return this.
     */
    std::shared_ptr<MessageBuilder> removeKeyRequestData(std::shared_ptr<keyx::KeyRequestData> keyRequestData);

    /**
     * <p>Add a service token to the message. This will overwrite any service
     * token with the same name that is also bound to the master token or user
     * ID token in the same way as the new service token.</p>
     * 
     * <p>Adding a service token with empty data indicates the recipient should
     * delete the service token.</p>
     * 
     * @param serviceToken service token to add.
     * @return this.
     * @throws MslMessageException if the service token serial numbers do not
     *         match the primary master token or primary user ID token of the
     *         message being built.
     */
    std::shared_ptr<MessageBuilder> addServiceToken(std::shared_ptr<tokens::ServiceToken> serviceToken);

    /**
     * <p>Add a service token to the message if a service token with the same
     * name that is also bound to the master token or user ID token in the same
     * way as the new service token does not already exist.</p>
     * 
     * <p>Adding a service token with empty data indicates the recipient should
     * delete the service token.</p>
     * 
     * @param serviceToken service token to add.
     * @return this.
     * @throws MslMessageException if the service token serial numbers do not
     *         match the master token or user ID token of the message being
     *         built.
     */
    std::shared_ptr<MessageBuilder> addServiceTokenIfAbsent(std::shared_ptr<tokens::ServiceToken> serviceToken);

    /**
     * <p>Exclude a service token from the message. This matches the token name
     * and whether or not it is bound to the master token or to a user ID
     * token. It does not require the token to be bound to the exact same
     * master token or user ID token that will be used in the message.</p>
     *
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     *
     * <p>This function is equivalent to calling
     * {@link #excludeServiceToken(String, boolean, boolean)}.</p>
     *
     * @param serviceToken the service token.
     * @return this.
     * @see #excludeServiceToken(String, boolean, boolean)
     */
    std::shared_ptr<MessageBuilder> excludeServiceToken(std::shared_ptr<tokens::ServiceToken> serviceToken);

    /**
     * <p>Exclude a service token from the message matching all the specified
     * parameters. A false value for the master token bound or user ID token
     * bound parameters restricts exclusion to tokens that are not bound to a
     * master token or not bound to a user ID token respectively.</p>
     * 
     * <p>For example, if a name is provided and the master token bound
     * parameter is true while the user ID token bound parameter is false, then
     * the master token bound service token with the same name will be excluded
     * from the message. If a name is provided but both other parameters are
     * false, then only an unbound service token with the same name will be
     * excluded.</p>
     *
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     * 
     * @param name service token name.
     * @param masterTokenBound true to exclude a master token bound service
     *        token. Must be true if {@code userIdTokenBound} is true.
     * @param userIdTokenBound true to exclude a user ID token bound service
     *        token.
     * @return this.
     */
    std::shared_ptr<MessageBuilder> excludeServiceToken(const std::string& name, const bool masterTokenBound, const bool userIdTokenBound);

    /**
     * <p>Mark a service token for deletion.</p>
     *
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     *
     * <p>This function is equivalent to calling
     * {@link #deleteServiceToken(String, boolean, boolean)}.</p>
     *
     * @param serviceToken the service token.
     * @return this.
     */
    std::shared_ptr<MessageBuilder> deleteServiceToken(std::shared_ptr<tokens::ServiceToken> serviceToken);

    /**
     * <p>Mark a service token for deletion. A false value for the master token
     * bound or user ID token bound parameters restricts deletion to tokens
     * that are not bound to a master token or not bound to a user ID token
     * respectively.</p>
     * 
     * <p>For example, if a name is provided and the master token bound
     * parameter is true while the user ID token bound parameter is false, then
     * the master token bound service token with the same name will be marked
     * for deletion. If a name is provided but both other parameters are false,
     * then only an unbound service token with the same name will be marked for
     * deletion.</p>
     *
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     * 
     * @param name service token name.
     * @param masterTokenBound true to delete a master token bound service
     *        token. Must be true if {@code userIdTokenBound} is true.
     * @param userIdTokenBound true to delete a user ID token bound service
     *        token.
     * @return this.
     */
    std::shared_ptr<MessageBuilder> deleteServiceToken(const std::string& name, const bool masterTokenBound, const bool userIdTokenBound);

    /**
     * @return the unmodifiable set of service tokens that will be included in
     *         the built message.
     */
    std::set<std::shared_ptr<tokens::ServiceToken>> getServiceTokens();

    /**
     * @return the peer master token or null if there is none.
     */
    std::shared_ptr<tokens::MasterToken> getPeerMasterToken() { return peerMasterToken_; }

    /**
     * @return the peer user ID token or null if there is none.
     */
    std::shared_ptr<tokens::UserIdToken> getPeerUserIdToken() { return peerUserIdToken_; }

    /**
     * <p>Set the peer master token and peer user ID token of the message. This
     * will overwrite any existing peer master token or peer user ID token.</p>
     * 
     * <p>Changing these tokens may result in invalidation of existing peer
     * service tokens. Those peer service tokens will be removed from the
     * message being built.</p>
     * 
     * @param std::shared_ptr<tokens::MasterToken> peer master token to set. May be null.
     * @param std::shared_ptr<tokens::UserIdToken> peer user ID token to set. May be null.
     * @throws MslMessageException if the peer user ID token is not bound to
     *         the peer master token.
     */
    void setPeerAuthTokens(std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<tokens::UserIdToken> userIdToken);

    /**
     * <p>Add a peer service token to the message. This will overwrite any peer
     * service token with the same name that is also bound to a peer master
     * token or peer user ID token in the same way as the new service token.</p>
     * 
     * <p>Adding a service token with empty data indicates the recipient should
     * delete the service token.</p>
     * 
     * @param serviceToken service token to add.
     * @return this.
     * @throws MslMessageException if the service token serial numbers do not
     *         match the peer master token or peer user ID token of the message
     *         being built.
     */
    std::shared_ptr<MessageBuilder> addPeerServiceToken(std::shared_ptr<tokens::ServiceToken> serviceToken);

    /**
     * <p>Add a peer service token to the message if a peer service token with
     * the same name that is also bound to the peer master token or peer user
     * ID token in the same way as the new service token does not already
     * exist.</p>
     * 
     * <p>Adding a service token with empty data indicates the recipient should
     * delete the service token.</p>
     * 
     * @param serviceToken service token to add.
     * @return this.
     * @throws MslMessageException if the service token serial numbers do not
     *         match the peer master token or peer user ID token of the message
     *         being built.
     */
    std::shared_ptr<MessageBuilder> addPeerServiceTokenIfAbsent(std::shared_ptr<tokens::ServiceToken> serviceToken);

    /**
     * <p>Exclude a peer service token from the message. This matches the token
     * name and whether or not it is bound to the master token or to a user ID
     * token. It does not require the token to be bound to the exact same
     * master token or user ID token that will be used in the message.</p>
     *
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     *
     * <p>This function is equivalent to calling
     * {@link #excludePeerServiceToken(String, boolean, boolean)}.</p>
     *
     * @param serviceToken the service token.
     * @return this.
     */
    std::shared_ptr<MessageBuilder> excludePeerServiceToken(std::shared_ptr<tokens::ServiceToken> serviceToken);

    /**
     * <p>Exclude a peer service token from the message matching all the
     * specified parameters. A false value for the master token bound or user
     * ID token bound parameters restricts exclusion to tokens that are not
     * bound to a master token or not bound to a user ID token
     * respectively.</p>
     * 
     * <p>For example, if a name is provided and the master token bound
     * parameter is true while the user ID token bound parameter is false, then
     * the master token bound service token with the same name will be excluded
     * from the message. If a name is provided but both other parameters are
     * false, then only an unbound service token with the same name will be
     * excluded.</p>
     *
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     * 
     * @param name service token name.
     * @param masterTokenBound true to exclude a master token bound service
     *        token. Must be true if {@code userIdTokenBound} is true.
     * @param userIdTokenBound true to exclude a user ID token bound service
     *        token.
     * @return this.
     */
    std::shared_ptr<MessageBuilder> excludePeerServiceToken(const std::string& name, const bool masterTokenBound, const bool userIdTokenBound);

    /**
     * <p>Mark a peer service token for deletion.</p>
     *
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     *
     * <p>This function is equivalent to calling
     * {@link #deletePeerServiceToken(String, boolean, boolean)}.</p>
     *
     * @param serviceToken the service token.
     * @return this.
     */
    std::shared_ptr<MessageBuilder> deletePeerServiceToken(std::shared_ptr<tokens::ServiceToken> serviceToken);

    /**
     * <p>Mark a peer service token for deletion. A false value for the master
     * token bound or user ID token bound parameters restricts deletion to
     * tokens that are not bound to a master token or not bound to a user ID
     * token respectively.</p>
     * 
     * <p>For example, if a name is provided and the master token bound
     * parameter is true while the user ID token bound parameter is false, then
     * the master token bound service token with the same name will be marked
     * for deletion. If a name is provided but both other parameters are false,
     * then only an unbound service token with the same name will be marked for
     * deletion.</p>
     *
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     * 
     * @param name service token name.
     * @param masterTokenBound true to delete a master token bound service
     *        token. Must be true if {@code userIdTokenBound} is true.
     * @param userIdTokenBound true to delete a user ID token bound service
     *        token.
     * @return this.
     */
    std::shared_ptr<MessageBuilder> deletePeerServiceToken(const std::string& name, const bool masterTokenBound, const bool userIdTokenBound);

    /**
     * @return the unmodifiable set of peer service tokens that will be
     *         included in the built message.
     */
    std::set<std::shared_ptr<tokens::ServiceToken>> getPeerServiceTokens();

protected:

    /**
     * <p>Minimal constructor that sets the MSL context</p>
     *
     * @param ctx MSL context.
     */
    MessageBuilder(std::shared_ptr<util::MslContext> ctx) : ctx_(ctx), messageId_(-1) {}

    /**
     * initialize a message builder with the provided tokens and key exchange
     * data if a master token was issued or renewed.
     * 
     * @param messageId message ID.
     * @param capabilities message capabilities.
     * @param std::shared_ptr<tokens::MasterToken> master token. May be null unless a user ID token is
     *        provided.
     * @param std::shared_ptr<tokens::UserIdToken> user ID token. May be null.
     * @param serviceTokens initial set of service tokens. May be null.
     * @param peerstd::shared_ptr<tokens::MasterToken> peer master token. May be null unless a peer user
     *        ID token is provided.
     * @param peerstd::shared_ptr<tokens::UserIdToken> peer user ID token. May be null.
     * @param peerServiceTokens initial set of peer service tokens.
     *        May be null.
     * @param keyExchangeData key exchange data. May be null.
     * @throws MslException if a user ID token is not bound to its master
     *         token.
     */
    void initializeMessageBuilder(
            int64_t messageId,
            std::shared_ptr<msg::MessageCapabilities> capabilities,
            std::shared_ptr<tokens::MasterToken> masterToken,
            std::shared_ptr<tokens::UserIdToken> userIdToken,
            std::set<std::shared_ptr<tokens::ServiceToken>> serviceTokens,
            std::shared_ptr<tokens::MasterToken> peerMasterToken,
            std::shared_ptr<tokens::UserIdToken> peerUserIdToken,
            std::set<std::shared_ptr<tokens::ServiceToken>> peerServiceTokens,
            std::shared_ptr<keyx::KeyExchangeFactory::KeyExchangeData> keyExchangeData);

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
    std::shared_ptr<MessageHeader> createMessageHeader(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData,
            std::shared_ptr<tokens::MasterToken> masterToken,
            std::shared_ptr<MessageHeader::HeaderData> headerData,
            std::shared_ptr<MessageHeader::HeaderPeerData> peerData);

protected:
    /** MSL context. */
    std::shared_ptr<util::MslContext> ctx_;

    /** Message header master token. */
    std::shared_ptr<tokens::MasterToken> masterToken_;
    /** Header data message ID. */
    int64_t messageId_;
    /** Key exchange data. */
    std::shared_ptr<keyx::KeyExchangeFactory::KeyExchangeData> keyExchangeData_;
    /** Message non-replayable. */
    bool nonReplayable_ = false;
    /** Header data renewable. */
    bool renewable_ = false;
    /** Handshake message. */
    bool handshake_ = false;
    /** Message capabilities. */
    std::shared_ptr<MessageCapabilities> capabilities_;
    /** Header data key request data. */
    std::set<std::shared_ptr<keyx::KeyRequestData>> keyRequestData_;
    /** Header data user authentication data. */
    std::shared_ptr<userauth::UserAuthenticationData> userAuthData_;
    /** Header data user ID token. */
    std::shared_ptr<tokens::UserIdToken> userIdToken_;
    /** Header data service tokens. */
    std::set<std::shared_ptr<tokens::ServiceToken>> serviceTokens_;

    /** Header peer data master token. */
    std::shared_ptr<tokens::MasterToken> peerMasterToken_;
    /** Header peer data user ID token. */
    std::shared_ptr<tokens::UserIdToken> peerUserIdToken_;
    /** Header peer data service tokens. */
    std::set<std::shared_ptr<tokens::ServiceToken>> peerServiceTokens_;
};

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_MESSAGE_BUILDER_H_ */
