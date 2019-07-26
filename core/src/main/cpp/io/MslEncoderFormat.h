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

#ifndef SRC_IO_MSLENCODERFORMAT_H_
#define SRC_IO_MSLENCODERFORMAT_H_

#include <Macros.h>
#include <stdint.h>
#include <util/StaticMslMutex.h>
#include <iosfwd>
#include <string>
#include <map>
#include <vector>
#include <set>

namespace netflix
{
namespace msl
{
namespace io
{

/**
 * <p>MSL encoder formats.</p>
 *
 * <p>The format name is used to uniquely identify encoder formats.</p>
 */
class MslEncoderFormat
{
public:
    /** Invalid format. */
    static const MslEncoderFormat INVALID;
    /** UTF-8 JSON. */
    static const MslEncoderFormat JSON;

    MslEncoderFormat() : identifier_(0) {}

    /**
     * Define an encoder format with the specified name and byte stream
     * identifier.
     *
     * @param name the encoder format name.
     * @param identifier the byte stream identifier.
     */
    MslEncoderFormat(const std::string& name, uint8_t identifier);

    /**
     * @param name the encoder format name.
     * @return the encoder format identified by the specified name or
     *         INVALID if there is none.
     */
    static MslEncoderFormat getFormat(const std::string& name) {
        std::map<std::string, MslEncoderFormat>::const_iterator it =
                formatsByName_.find(name);
        return (it == formatsByName_.end()) ? INVALID : it->second;
    }

    /**
     * @param identifier the encoder format identifier.
     * @return the encoder format identified by the specified identifier or
     *         INVALID if there is none.
     */
    static MslEncoderFormat getFormat(uint8_t identifier) {
        std::map<uint8_t, MslEncoderFormat>::const_iterator it =
                formatsById_.find(identifier);
        return (it == formatsById_.end()) ? INVALID : it->second;
    }

    /**
     * @return all known encoder formats.
     */
    static std::set<MslEncoderFormat> values();

    /**
     * @return the format identifier.
     */
    std::string name() const { return name_; }
    std::string toString() const { return name(); }


    /**
     * @return the byte stream identifier.
     */
    uint8_t identifier() const { return identifier_; }

private:
    static util::StaticMslMutex mutex_;
    static std::map<std::string, MslEncoderFormat> formatsByName_;
    static std::map<uint8_t, MslEncoderFormat> formatsById_;
    mutable std::string name_;
    mutable uint8_t identifier_;

    friend bool operator==(const MslEncoderFormat& a, const MslEncoderFormat& b);
    friend bool operator<(const MslEncoderFormat& a, const MslEncoderFormat& b);
};

bool operator==(const MslEncoderFormat& a, const MslEncoderFormat& b);
bool operator!=(const MslEncoderFormat& a, const MslEncoderFormat& b);
bool operator<(const MslEncoderFormat& a, const MslEncoderFormat& b);
std::ostream & operator<<(std::ostream &os, const MslEncoderFormat& f);

} /* namespace io */
} /* namespace msl */
} /* namespace netflix */

#endif /* SRC_IO_MSLENCODERFORMAT_H_ */
