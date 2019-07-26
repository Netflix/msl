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

#ifndef SRC_MSG_MESSAGECAPABILITIES_H_
#define SRC_MSG_MESSAGECAPABILITIES_H_
#include <io/MslEncodable.h>
#include <io/MslEncoderFormat.h>
#include <MslConstants.h>
#include <set>
#include <sstream>
#include <vector>
#include <stdint.h>
#include <memory>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io { class MslObject; class MslEncoderFactory; class MslEncoderFormat; }
namespace msg {

/**
 * <p>The message capabilities identify the features supported by the message
 * sender.</p>
 *
 * <p>The message capabilities are represented as
 * {@code
 * capabilities = {
 *   "compressionalgos" : [ "string" enum(GZIP|LZW) ],
 *   "languages" : [ "string" ],
 *   "encoderformats" : [ "string" ],
 * }} where:
 * <ul>
 * <li>{@code compressionalgos} is the set of supported compression algorithms</li>
 * <li>{@code languages} is the preferred list of BCP-47 languages in descending order</li>
 * <li>{@code encoderformats} is the preferred list of MSL encoder formats</li>
 * </ul></p>
 */
class MessageCapabilities : public io::MslEncodable
{
public:
    /**
     * Computes and returns the intersection of two message capabilities.
     *
     * @param mc1 first message capabilities. May be {@code null}.
     * @param mc2 second message capabilities. May be {@code null}.
     * @return the intersection of message capabilities or {@code null} if one
     *         of the message capabilities is {@code null}.
     */
    static std::shared_ptr<MessageCapabilities> intersection(std::shared_ptr<MessageCapabilities> mc1,
            std::shared_ptr<MessageCapabilities> mc2);

    /**
     * Create a new message capabilities object with the specified supported
     * features.
     *
     * @param compressionAlgos supported payload compression algorithms. May be
     *        {@code null}.
     * @param languages preferred languages as BCP-47 codes in descending
     *        order. May be {@code null}.
     * @param encoderFormats supported encoder formats. May be {@code null}.
     */
    MessageCapabilities(
            const std::set<MslConstants::CompressionAlgorithm>& compressionAlgos,
            const std::vector<std::string>& languages,
            const std::set<io::MslEncoderFormat>& encoderFormats);

    /**
     * Construct a new message capabilities object from the provided MSL
     * object.
     *
     * @param capabilitiesMo the MSL object.
     * @throws MslEncodingException if there is an error parsing the data.
     */
    MessageCapabilities(std::shared_ptr<io::MslObject> capabilitiesMo);

    /**
     * @return the supported compression algorithms.
     */
    std::set<MslConstants::CompressionAlgorithm> getCompressionAlgorithms() const
        { return compressionAlgos_; }

    /**
     * @return the preferred languages as BCP-47 codes in descending order.
     */
    std::vector<std::string> getLanguages() const { return languages_; }

    /**
     * @return the supported encoder formats.
     */
    std::set<io::MslEncoderFormat> getEncoderFormats() const
        { return encoderFormats_; }

    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

    bool equals(std::shared_ptr<const MessageCapabilities> other) const;

private:
    /** Supported payload compression algorithms. */
    std::set<MslConstants::CompressionAlgorithm> compressionAlgos_;
    /** Preferred languages as BCP-47 codes in descending order. */
    std::vector<std::string> languages_;
    /** Supported encoder formats. */
    std::set<io::MslEncoderFormat> encoderFormats_;

    friend bool operator==(const MessageCapabilities& a, const MessageCapabilities& b);
};

bool operator==(const MessageCapabilities& a, const MessageCapabilities& b);
inline bool operator!=(const MessageCapabilities& a, const MessageCapabilities& b) { return !(a == b); }

}}} // netflix::msl::msg

#endif /* SRC_MSG_MESSAGECAPABILITIES_H_ */
