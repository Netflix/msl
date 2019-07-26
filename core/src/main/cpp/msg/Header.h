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

#ifndef SRC_MSG_HEADER_H_
#define SRC_MSG_HEADER_H_

#include <io/MslEncodable.h>
#include <memory>
#include <map>

namespace netflix {
namespace msl {
namespace crypto { class ICryptoContext; }
namespace io { class MslObject; }
namespace util{ class MslContext; }
namespace msg {

/**
 * <p>A MSL header contains entity authentication data or a master token
 * identifying the message sender and data used to authenticate the header
 * data. Portions of the header may be encrypted.</p>
 *
 * <p>A message header is represented as
 * {@code
 * header = {
 *   "#mandatory" : [ "headerdata", "signature" ],
 *   "#conditions" : [ "entityauthdata xor mastertoken" ],
 *   "entityauthdata" : entityauthdata,
 *   "mastertoken" : mastertoken,
 *   "headerdata" : "base64",
 *   "signature" : "base64"
 * }} where:
 * <ul>
 * <li>{@code entityauthdata} is the entity authentication data (mutually exclusive with mastertoken)</li>
 * <li>{@code mastertoken} is the master token (mutually exclusive with entityauthdata)</li>
 * <li>{@code headerdata} is the Base64-encoded encrypted header data (headerdata)</li>
 * <li>{@code signature} is the Base64-encoded verification data of the header data</li>
 * </ul></p>
 *
 * <p>An error header is represented as
 * {@code
 * errorheader = {
 *   "#mandatory" : [ "entityauthdata", "errordata", "signature" ],
 *   "entityauthdata" : entityauthdata,
 *   "errordata" : "base64",
 *   "signature" : "base64"
 * }} where:
 * <ul>
 * <li>{@code entityauthdata} is the entity authentication data</li>
 * <li>{@code errordata} is the Base64-encoded encrypted error data (errordata)</li>
 * <li>{@code signature} is the Base64-encoded verification data of the error data</li>
 * </ul></p>
 */
class Header: public io::MslEncodable
{
public:
    /**
     * <p>Construct a new header from the provided MSL object.</p>
     *
     * <p>Headers are encrypted and signed. If a master token is found, it will
     * be used for this purpose. Otherwise the crypto context appropriate for
     * the entity authentication scheme will be used.</p>
     *
     * <p>For message headers the master token or entity authentication data
     * must be found. For error headers the entity authentication data must be
     * found.</p>
     *
     * <p>Service tokens will be decrypted and verified with the provided crypto
     * contexts identified by token name. A default crypto context may be
     * provided by using the empty string as the token name; if a token name is
     * not explcitly mapped onto a crypto context, the default crypto context
     * will be used.</p>
     *
     * @param ctx MSL context.
     * @param headerMo header MSL object.
     * @param cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @return the header.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the message.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslKeyExchangeException if unable to create the key request data
     *         or key response data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data.
     * @throws MslMessageException if the message does not contain an entity
     *         authentication data or a master token, the header data is
     *         missing or invalid, or the message ID is negative, or the
     *         message is not encrypted and contains user authentication data.
     * @throws MslException if the message does not contain an entity
     *         authentication data or a master token or a token is improperly
     *         bound to another token.
     */
     static std::shared_ptr<Header> parseHeader(std::shared_ptr<util::MslContext> ctx,
             std::shared_ptr<io::MslObject> headerMo,
             const std::map<std::string, std::shared_ptr<crypto::ICryptoContext>> cryptoContexts);

     /* (non-Javadoc)
      * @see java.lang.Object#equals(java.lang.Object)
      */
     virtual bool equals(std::shared_ptr<const Header> other) const = 0;

protected:
     virtual ~Header() {}
};

bool operator==(const Header& a, const Header& b);
inline bool operator!=(const Header& a, const Header& b) { return !(a == b); }

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_HEADER_H_ */
