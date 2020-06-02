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

#ifndef _SRC_MSG_MESSAGESERVICETOKENBUILDER_H_
#define _SRC_MSG_MESSAGESERVICETOKENBUILDER_H_

#include <MslConstants.h>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace crypto { class ICryptoContext; }
namespace tokens { class MasterToken; class ServiceToken; }
namespace util { class MslContext; }
namespace msg {
class MessageBuilder; class MessageContext;

/**
 * <p>A message service token builder provides methods for intelligently
 * manipulating the primary and peer service tokens that will be included in a
 * message.</p>
 * 
 * <p>There are two categories of service tokens: primary and peer.
 * <ul>
 * <li>Primary service tokens are associated with the primary master token and
 * peer user ID token, and are the only category of service token to appear in
 * trusted network mode. Primary service tokens are also used in peer-to-peer
 * mode.</li>
 * <li>Peer service tokens are associated with the peer master token and peer
 * user ID token and only used in peer-to-peer mode.</li>
 * </ul></p>
 * 
 * <p>There are three levels of service token binding.
 * <ul>
 * <li>Unbound service tokens may be freely moved between entities and
 * users.</li>
 * <li>Master token bound service tokens must be accompanied by a master token
 * that they are bound to and will be rejected if sent with a different master
 * token or without a master token. This binds a service token to a specific
 * entity.</li>
 * <li>User ID token bound service tokens must be accompanied by a user ID
 * token that they are bound to and will be rejected if sent with a different
 * user or used without a user ID token. This binds a service token to a
 * specific user and by extension a specific entity.</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MessageServiceTokenBuilder
{
public:
    /**
     * Create a new message service token builder with the provided MSL and
     * message contexts and message builder.
     * 
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param builder message builder for message being built.
     */
    MessageServiceTokenBuilder(std::shared_ptr<util::MslContext> ctx,
                               std::shared_ptr<MessageContext> msgCtx,
                               std::shared_ptr<MessageBuilder> builder);

private:
    /**
     * Returns the master token that primary service tokens should be bound
     * against.
     *
     * @return the primary service token master token or {@code null} if there
     *         is none.
     */
    std::shared_ptr<tokens::MasterToken> getPrimaryMasterToken();

public:
    /**
     * Returns true if the message has a primary master token available for
     * adding master-bound primary service tokens.
     * 
     * @return true if the message has a primary master token.
     */
    bool isPrimaryMasterTokenAvailable();
    
    /**
     * @return true if the message has a primary user ID token.
     */
    bool isPrimaryUserIdTokenAvailable();
    
    /**
     * @return true if the message has a peer master token.
     */
    bool isPeerMasterTokenAvailable();
    
    /**
     * @return true if the message has a peer user ID token.
     */
    bool isPeerUserIdTokenAvailable();

    /**
     * @return the unmodifiable set of primary service tokens that will be
     *         included in the built message.
     */
    std::set<std::shared_ptr<tokens::ServiceToken>> getPrimaryServiceTokens();

    /**
     * @return the unmodifiable set of peer service tokens that will be
     *         included in the built message.
     */
    std::set<std::shared_ptr<tokens::ServiceToken>> getPeerServiceTokens();
    
    /**
     * Adds a primary service token to the message, replacing any existing
     * primary service token with the same name.
     * 
     * @param std::shared_ptr<tokens::ServiceToken>primary service token.
     * @return true if the service token was added, false if the service token
     *         is bound to a master token or user ID token and the message does
     *         not have the same token.
     * @throws MslMessageException if the service token serial numbers do not
     *         match the primary master token or primary user ID token of the
     *         message being built.
     */
    bool addPrimaryServiceToken(std::shared_ptr<tokens::ServiceToken> serviceToken);
    
    /**
     * Adds a peer service token to the message, replacing any existing peer
     * service token with the same name.
     * 
     * @param std::shared_ptr<tokens::ServiceToken>peer service token.
     * @return true if the service token was added, false if the service token
     *         is bound to a master token or user ID token and the message does
     *         not have the same token.
     * @throws MslMessageException if the service token serial numbers do not
     *         match the peer master token or peer user ID token of the message
     *         being built.
     */
    bool addPeerServiceToken(std::shared_ptr<tokens::ServiceToken>serviceToken);
    
    /**
     * Adds a new unbound primary service token to the message, replacing any
     * existing primary service token with the same name.
     * 
     * @param name service token name.
     * @param data service token data.
     * @param encrypt true if the service token data should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @return true if the service token was added, false if there is no crypto
     *         context found for this service token.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslException if there is an error compressing the data.
     */
    bool addUnboundPrimaryServiceToken(const std::string& name, std::shared_ptr<ByteArray> data, bool encrypt, MslConstants::CompressionAlgorithm compressionAlgo);
    
    /**
     * Adds a new unbound peer service token to the message, replacing any
     * existing peer service token with the same name.
     * 
     * @param name service token name.
     * @param data service token data.
     * @param encrypt true if the service token data should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @return true if the service token was added, false if there is no crypto
     *         context found for this service token.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslException if there is an error compressing the data.
     */
    bool addUnboundPeerServiceToken(const std::string& name, std::shared_ptr<ByteArray> data, bool encrypt, MslConstants::CompressionAlgorithm compressionAlgo);
    
    /**
     * Adds a new master token bound primary service token to the message,
     * replacing any existing primary service token with the same name.
     * 
     * @param name service token name.
     * @param data service token data.
     * @param encrypt true if the service token data should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @return true if the service token was added, false if there is no crypto
     *         context found for this service token or the message does not
     *         have a primary master token.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslException if there is an error compressing the data.
     */
    bool addMasterBoundPrimaryServiceToken(const std::string& name, std::shared_ptr<ByteArray> data, bool encrypt, MslConstants::CompressionAlgorithm compressionAlgo);
    
    /**
     * Adds a new master token bound peer service token to the message,
     * replacing any existing peer service token with the same name.
     * 
     * @param name service token name.
     * @param data service token data.
     * @param encrypt true if the service token data should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @return true if the service token was added, false if there is no crypto
     *         context found for this service token or the message does not
     *         have a peer master token.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslException if there is an error compressing the data.
     */
    bool addMasterBoundPeerServiceToken(const std::string& name, std::shared_ptr<ByteArray> data, bool encrypt, MslConstants::CompressionAlgorithm compressionAlgo);

    /**
     * Adds a new user ID token bound primary service token to the message,
     * replacing any existing primary service token with the same name.
     * 
     * @param name service token name.
     * @param data service token data.
     * @param encrypt true if the service token data should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @return true if the service token was added, false if there is no crypto
     *         context found for this service token or the message does not
     *         have a primary user ID token.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslException if there is an error compressing the data.
     */
    bool addUserBoundPrimaryServiceToken(const std::string& name, std::shared_ptr<ByteArray> data, bool encrypt, MslConstants::CompressionAlgorithm compressionAlgo);

    /**
     * Adds a new user ID token bound peer service token to the message,
     * replacing any peer existing service token with the same name.
     * 
     * @param name service token name.
     * @param data service token data.
     * @param encrypt true if the service token data should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @return true if the service token was added, false if there is no crypto
     *         context found for this service token or the message does not
     *         have a peer user ID token.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslException if there is an error compressing the data.
     */
    bool addUserBoundPeerServiceToken(const std::string& name, std::shared_ptr<ByteArray> data, bool encrypt, MslConstants::CompressionAlgorithm compressionAlgo);
    
    /**
     * <p>Exclude a primary service token from the message. This matches the
     * token name and whether or not it is bound to the master token or to a
     * user ID token. It does not require the token to be bound to the exact
     * same master token or user ID token that will be used in the message.</p>
     *
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     *
     * <p>This function is equivalent to calling
     * {@link #excludePrimaryServiceToken(String, boolean, boolean)}.</p>
     *
     * @param serviceToken the service token.
     * @return true if the service token was found and therefore removed.
     */
    bool excludePrimaryServiceToken(std::shared_ptr<tokens::ServiceToken> serviceToken);

    /**
     * <p>Exclude a primary service token from the message matching all
     * specified parameters. A false value for the master token bound or user
     * ID token bound parameters restricts exclusion to tokens that are not
     * bound to a master token or not bound to a user ID token
     * respectively.</p>
     * 
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     * 
     * @param name service token name.
     * @param masterTokenBound true to exclude a master token bound service
     *        token. Must be true if {@code userIdTokenBound} is true.
     * @param userIdTokenBound true to exclude a user ID token bound service
     *        token.
     * @return true if the service token was found and therefore removed.
     */
    bool excludePrimaryServiceToken(const std::string& name, const bool masterTokenBound, const bool userIdTokenBound);

    /**
     * <p>Exclude a peer service token from the message. This matches the
     * token name and whether or not it is bound to the master token or to a
     * user ID token. It does not require the token to be bound to the exact
     * same master token or user ID token that will be used in the message.</p>
     *
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     *
     * <p>This function is equivalent to calling
     * {@link #excludePeerServiceToken(String, boolean, boolean)}.</p>
     *
     * @param serviceToken the service token.
     * @return true if the service token was found and therefore removed.
     */
    bool excludePeerServiceToken(std::shared_ptr<tokens::ServiceToken> serviceToken);
    
    /**
     * <p>Exclude a peer service token from the message matching all specified
     * parameters. A false value for the master token bound or user ID token
     * bound parameters restricts exclusion to tokens that are not bound to a
     * master token or not bound to a user ID token respectively.</p>
     * 
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     * 
     * @param name service token name.
     * @param masterTokenBound true to exclude a master token bound service
     *        token. Must be true if {@code userIdTokenBound} is true.
     * @param userIdTokenBound true to exclude a user ID token bound service
     *        token.
     * @return true if the peer service token was found and therefore removed.
     */
    bool excludePeerServiceToken(const std::string& name, const bool masterTokenBound, const bool userIdTokenBound);

    /**
     * <p>Mark a primary service token for deletion, if it exists. This matches
     * the token name and whether or not it is bound to the master token or to
     * a user ID token. It does not require the token to be bound to the exact
     * same master token or user ID token that will be used in the message.</p>
     *
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     *
     * <p>This function is equivalent to calling
     * {@link #deletePrimaryServiceToken(String, boolean, boolean)}.</p>
     *
     * @param serviceToken the service token.
     * @return true if the service token exists and was marked for deletion.
     */
    bool deletePrimaryServiceToken(std::shared_ptr<tokens::ServiceToken> serviceToken);
    
    /**
     * <p>Mark a primary service token for deletion, if it exists, matching all
     * specified parameters. A false value for the master token bound or user
     * ID token bound parameters restricts deletion to tokens that are not
     * bound to a master token or not bound to a user ID token
     * respectively.</p>
     * 
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     * 
     * @param name service token name.
     * @param masterTokenBound true to exclude a master token bound service
     *        token. Must be true if {@code userIdTokenBound} is true.
     * @param userIdTokenBound true to exclude a user ID token bound service
     *        token.
     * @return true if the service token exists and was marked for deletion.
     */
    bool deletePrimaryServiceToken(const std::string& name, const bool masterTokenBound, const bool userIdTokenBound);
    
    /**
     * <p>Mark a peer service token for deletion, if it exists. This matches
     * the token name and whether or not it is bound to the master token or to
     * a user ID token. It does not require the token to be bound to the exact
     * same master token or user ID token that will be used in the message.</p>
     *
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     *
     * <p>This function is equivalent to calling
     * {@link #deletePeerServiceToken(String, boolean, boolean)}.</p>
     *
     * @param serviceToken the service token.
     * @return true if the service token exists and was marked for deletion.
     */
    bool deletePeerServiceToken(std::shared_ptr<tokens::ServiceToken> serviceToken);

    /**
     * <p>Mark a peer service token for deletion, if it exists, matching all
     * specified parameters. A false value for the master token bound or user
     * ID token bound parameters restricts deletion to tokens that are not
     * bound to a master token or not bound to a user ID token
     * respectively.</p>
     * 
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     * 
     * @param name service token name.
     * @param masterTokenBound true to exclude a master token bound service
     *        token. Must be true if {@code userIdTokenBound} is true.
     * @param userIdTokenBound true to exclude a user ID token bound service
     *        token.
     * @return true if the peer service token exists and was marked for
     *         deletion.
     */
    bool deletePeerServiceToken(const std::string& name, const bool masterTokenBound, const bool userIdTokenBound);

private:
    /** MSL context. */
    std::shared_ptr<util::MslContext> ctx_;
    /** Service token crypto contexts. */
    std::map<std::string,std::shared_ptr<crypto::ICryptoContext>> cryptoContexts_;
    /** Message builder for message being built. */
    std::shared_ptr<MessageBuilder> builder_;
};
    
}}} // namespace netflix::msl::msg

#endif
