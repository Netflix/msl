/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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

#ifndef SRC_MSG_MESSAGESTREAMFACTORY_H_
#define SRC_MSG_MESSAGESTREAMFACTORY_H_

#include <io/MslEncoderFormat.h>
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
 * <p>A message stream factory is used to create message streams.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MessageStreamFactory
{
public:
	virtual ~MessageStreamFactory() {}

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
     * @throws MslEncodingException if there is an error parsing the message.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header or creating the message payload crypto context.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data.
     * @throws MslMessageException if the message master token is expired and
     *         the message is not renewable.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be or if it has been revoked.
     * @throws MslUserIdTokenException if the user ID token has been revoked.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or key response data or the key exchange scheme is
     *         not supported.
     * @throws MslMessageException if the message master token is expired and
     *         the message is not renewable.
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
};

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_MESSAGESTREAMFACTORY_H_ */
