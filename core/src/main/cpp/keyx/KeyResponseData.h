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

#ifndef SRC_KEYX_KEYRESPONSEDATA_H_
#define SRC_KEYX_KEYRESPONSEDATA_H_

#include <io/MslEncodable.h>
#include <keyx/KeyExchangeScheme.h>
#include <stdint.h>
#include <memory>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io { class MslObject; class MslEncoderFactory; class MslEncoderFormat; }
namespace tokens { class MasterToken; }
namespace util { class MslContext; }
namespace keyx {

/**
 * <p>Key response data contains all the data needed to facilitate a exchange of
 * session keys from the responder.</p>
 *
 * <p>Specific key exchange mechanisms should define their own key response data
 * types.</p>
 *
 * <p>Key response data is represented as
 * {@code
 * keyresponsedata = {
 *   "#mandatory" : [ "mastertoken", "scheme", "keydata" ],
 *   "mastertoken" : mastertoken,
 *   "scheme" : "string",
 *   "keydata" : object
 * }} where:
 * <ul>
 * <li>{@code mastertoken} is the master token associated with the session keys</li>
 * <li>{@code scheme} is the key exchange scheme</li>
 * <li>{@code keydata} is the scheme-specific key data</li>
 * </ul></p>
 */
class KeyResponseData: public io::MslEncodable
{
public:
    virtual ~KeyResponseData() {}

    /**
     * Construct a new key response data instance of the correct type from the
     * provided MSL object.
     *
     * @param ctx MSL context.
     * @param keyResponseDataMo the MSL object.
     * @return the key response data concrete instance.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslKeyExchangeException if unable to create the key response
     *         data.
     * @throws MslCryptoException if there is an error verifying the they key
     *         response data.
     * @throws MslException if the key response master token expiration
     *         timestamp occurs before the renewal window.
     */
    static std::shared_ptr<KeyResponseData> create(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<io::MslObject> keyResponseDataMo);

    /**
     * @return the master token.
     */
    std::shared_ptr<tokens::MasterToken> getMasterToken() const { return masterToken; }

    /**
     * @return the key exchange scheme.
     */
    KeyExchangeScheme getKeyExchangeScheme() const { return scheme; }

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    virtual bool equals(std::shared_ptr<const KeyResponseData> other) const;

    /**
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @return the key data MSL representation.
     * @throws MslEncoderException if there was an error constructing the MSL
     *         representation.
     */
    // FIXME: java code has this protected
    virtual std::shared_ptr<io::MslObject> getKeydata(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const = 0;

protected:
    /**
     * Create a new key response data object with the specified key exchange
     * scheme and associated master token.
     *
     * @param masterToken the master token.
     * @param scheme the key exchange scheme.
     */
    KeyResponseData(std::shared_ptr<tokens::MasterToken> masterToken, const KeyExchangeScheme& scheme);

private:
    KeyResponseData(); // not implemented
    /** Master token. */
    std::shared_ptr<tokens::MasterToken> masterToken;
    /** Key exchange scheme. */
    const KeyExchangeScheme scheme;

    friend std::ostream& operator<<(std::ostream& os, const KeyResponseData& data);
};

bool operator==(const KeyResponseData& a, const KeyResponseData& b);
inline bool operator!=(const KeyResponseData& a, const KeyResponseData& b) { return !(a == b); }

std::ostream& operator<<(std::ostream& os, const KeyResponseData& data);
std::ostream& operator<<(std::ostream& os, std::shared_ptr<KeyResponseData> data);

}}} // namespace netflix::msl::keyx

#endif /* SRC_KEYX_KEYRESPONSEDATA_H_ */
