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

#ifndef SRC_MSG_MESSAGEFACTORY_H_
#define SRC_MSG_MESSAGEFACTORY_H_

#include <io/MslEncoderFormat.h>
#include <MslError.h>
#include <msg/MessageBuilder.h>
#include <map>
#include <memory>
#include <set>
#include <string>

namespace netflix {
namespace msl {
namespace crypto { class ICryptoContext; }
namespace io { class InputStream; class OutputStream; }
namespace keyx { class KeyRequestData; }
namespace util { class MslContext; }
namespace msg {
class ErrorHeader; class MessageHeader;
class MessageInputStream; class MessageOutputStream;

/**
 * <p>A message factory is used to create message streams and builders.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MessageFactory
{
public:
	virtual ~MessageFactory() {}

    /**
     * <p>Construct a new message input stream. The header is parsed.</p>
     *
     * <p>If key request data is provided and a matching key response data is
     * found in the message header the key exchange will be performed to
     * process the message payloads.</p>
     *
     * <p>Service tokens will be decrypted and verified with the provided crypto
     * contexts identified by token name. A default crypto context may be
     * provided by using the empty string as the token name; if a token name is
     * not explcitly mapped onto a crypto context, the default crypto context
     * will be used.</p>
     *
     * @param ctx MSL context.
     * @param source MSL input stream.
     * @param keyRequestData key request data to use when processing key
     *        response data.
     * @param cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @throws IOException if there is a problem reading from the input stream.
     * @throws MslEncodingException if there is an error parsing the message.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header or creating the message payload crypto context.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be or if it has been revoked.
     * @throws MslUserIdTokenException if the user ID token has been revoked.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or key response data or the key exchange scheme is
     *         not supported.
     * @throws MslMessageException if the message does not contain an entity
     *         authentication data or a master token, the header data is
     *         missing or invalid, or the message ID is negative, or the
     *         message is not encrypted and contains user authentication data,
     *         or if the message master token is expired and the message is not
     *         renewable.
     * @throws MslException if the message does not contain an entity
     *         authentication data or a master token, or a token is improperly
     *         bound to another token.
     */
    virtual std::shared_ptr<MessageInputStream> createInputStream(
    		std::shared_ptr<util::MslContext> ctx,
			std::shared_ptr<io::InputStream> source,
			std::set<std::shared_ptr<keyx::KeyRequestData>> keyRequestData,
			std::map<std::string,std::shared_ptr<crypto::ICryptoContext>> cryptoContexts);

    /**
     * Construct a new error message output stream. The header is output
     * immediately by calling {@code #flush()} on the destination output
     * stream.
     *
     * @param ctx the MSL context.
     * @param destination MSL output stream.
     * @param header error header.
     * @param format the MSL encoder format.
     * @throws IOException if there is an error writing the header.
     */
    virtual std::shared_ptr<MessageOutputStream> createOutputStream(
    		std::shared_ptr<util::MslContext> ctx,
			std::shared_ptr<io::OutputStream> destination,
			std::shared_ptr<ErrorHeader> header,
			const io::MslEncoderFormat& format);

    /**
     * Construct a new message output stream. The header is output
     * immediately by calling {@code #flush()} on the destination output
     * stream. The most preferred compression algorithm and encoder format
     * supported by the local entity and message header will be used.
     *
     * @param ctx the MSL context.
     * @param destination MSL output stream.
     * @param header message header.
     * @param cryptoContext payload data crypto context.
     * @throws IOException if there is an error writing the header.
     */
    virtual std::shared_ptr<MessageOutputStream> createOutputStream(
    		std::shared_ptr<util::MslContext> ctx,
			std::shared_ptr<io::OutputStream> destination,
			std::shared_ptr<MessageHeader> header,
			std::shared_ptr<crypto::ICryptoContext> cryptoContext);

    /**
     * <p>Create a new error message in response to another message. If the message ID
     * of the request is not specified (i.e. unknown); then a random message ID will
     * be generated.</p>
     * 
     * @param ctx MSL context.
     * @param requestMessageId message ID of request. May be null.
     * @param error the MSL error.
     * @param userMessage localized user-consumable error message. May be null.
     * @return the error header.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     * @throws MslMessageException if no entity authentication data was
     *         returned by the MSL context.
     */
    virtual std::shared_ptr<ErrorHeader> createErrorResponse(
           std::shared_ptr<util::MslContext> ctx,
           int64_t requestMessageId,
           MslError error,
           std::string userMessage);

    /**
     * <p>Create a new message builder that will craft a new request message with the
     * specified message ID.</p>
     * 
     * @param ctx MSL context.
     * @param std::shared_ptr<tokens::MasterToken> master token. May be null unless a user ID token is
     *        provided.
     * @param std::shared_ptr<tokens::UserIdToken> user ID token. May be null.
     * @param messageId the message ID to use. Must be within range.
     * @return the message builder.
     * @throws MslException if a user ID token is not bound to its
     *         corresponding master token.
     */
    std::shared_ptr<MessageBuilder> createRequest(
            std::shared_ptr<util::MslContext> ctx,
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
     * @return the message builder.
     * @throws MslException if a user ID token is not bound to its
     *         corresponding master token.
     */
    std::shared_ptr<MessageBuilder> createRequest(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<tokens::MasterToken> masterToken,
            std::shared_ptr<tokens::UserIdToken> userIdToken);

    /**
     * Create a new message builder that will craft a new message in response
     * to another message. The constructed message may be used as a request.
     *
     * @param ctx MSL context.
     * @param requestHeader message header to respond to.
     * @return the message builder.
     * @throws MslMasterTokenException if the provided message's master token
     *         is not trusted.
     * @throws MslCryptoException if the crypto context from a key exchange
     *         cannot be created.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or the key response data cannot be created.
     * @throws MslUserAuthException if there is an error with the user
     *         authentication data or the user ID token cannot be created.
     * @throws MslException if a user ID token in the message header is not
     *         bound to its corresponding master token or there is an error
     *         creating or renewing the master token.
     */
    std::shared_ptr<MessageBuilder> createResponse(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageHeader> requestHeader);


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
    std::shared_ptr<MessageBuilder> createIdempotentResponse(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageHeader> requestHeader);

};

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_MESSAGEFACTORY_H_ */
