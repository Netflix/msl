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

#ifndef SRC_KEYX_KEYREQUESTDATA_H_
#define SRC_KEYX_KEYREQUESTDATA_H_

#include <io/MslEncodable.h>
#include <keyx/KeyExchangeScheme.h>
#include <stdint.h>
#include <memory>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io { class MslObject; class MslEncoderFactory; class MslEncoderFormat; }
namespace util { class MslContext; }
namespace keyx {

/**
 * <p>Key request data contains all the data needed to facilitate a exchange of
 * session keys with the requesting entity.</p>
 *
 * <p>Specific key exchange mechanisms should define their own key request data
 * types.</p>
 *
 * <p>Key request data is represented as
 * {@code
 * keyrequestdata = {
 *   "#mandatory" : [ "scheme", "keydata" ],
 *   "scheme" : "string",
 *   "keydata" : object
 * }} where:
 * <ul>
 * <li>{@code scheme} is the key exchange scheme</li>
 * <li>{@code keydata} is the scheme-specific key data</li>
 * </ul></p>
 */
class KeyRequestData: public io::MslEncodable
{
public:
    virtual ~KeyRequestData() {}

    /**
     * Construct a new key request data instance of the correct type from the
     * provided MSL object.
     *
     * @param ctx MSL context.
     * @param keyRequestDataMo the MSL object.
     * @return the key request data concrete instance.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslCryptoException if there is an error verifying the key
     *         request data.
     * @throws MslEntityAuthException if the entity authentication data could
     *         not be created.
     * @throws MslKeyExchangeException if unable to create the key request
     *         data.
     */
    static std::shared_ptr<KeyRequestData> create(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<io::MslObject> keyRequestDataMo);

    /**
     * @return the key exchange scheme.
     */
    KeyExchangeScheme getKeyExchangeScheme() const { return scheme; }

    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    virtual std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    virtual bool equals(std::shared_ptr<const KeyRequestData> other) const;

protected:
    /**
     * Create a new key request data object with the specified key exchange
     * scheme.
     *
     * @param scheme the key exchange scheme.
     */
    KeyRequestData(const KeyExchangeScheme& scheme) : scheme(scheme) {}

    /**
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @return the key data MSL representation.
     * @throws MslEncoderException if there was an error constructing the MSL
     *         representation.
     */
    virtual std::shared_ptr<io::MslObject> getKeydata(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const = 0;

private:
    KeyRequestData(); // not implemented
    /** Key exchange scheme. */
    const KeyExchangeScheme scheme;

    friend std::ostream& operator<<(std::ostream& os, const KeyRequestData& data);
    // FIXME needs operator< for set
};

bool operator==(const KeyRequestData& a, const KeyRequestData& b);
inline bool operator!=(const KeyRequestData& a, const KeyRequestData& b) { return !(a == b); }

std::ostream& operator<<(std::ostream& os, const KeyRequestData& data);
std::ostream& operator<<(std::ostream& os, std::shared_ptr<KeyRequestData> data);

}}} // namespace netflix::msl::keyx

#endif /* SRC_KEYX_KEYREQUESTDATA_H_ */
