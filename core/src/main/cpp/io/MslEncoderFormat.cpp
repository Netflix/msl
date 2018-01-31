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

#include <io/MslEncoderFormat.h>

using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace io {

StaticMslMutex MslEncoderFormat::mutex_;
std::map<std::string, MslEncoderFormat> MslEncoderFormat::formatsByName_;
std::map<uint8_t, MslEncoderFormat> MslEncoderFormat::formatsById_;

const MslEncoderFormat MslEncoderFormat::INVALID("INVALID", 0);
const MslEncoderFormat MslEncoderFormat::JSON("JSON", (uint8_t)'{');

MslEncoderFormat::MslEncoderFormat(const std::string& name, uint8_t identifier)
{
    LockGuard lockGuard(mutex_);
    name_ = name;
    identifier_ = identifier;
    formatsByName_.insert(std::make_pair(name, *this));
    formatsById_.insert(std::make_pair(identifier, *this));
}

//static
std::set<MslEncoderFormat> MslEncoderFormat::values()
{
    LockGuard lockGuard(mutex_);
    std::set<MslEncoderFormat> v;
    for(std::map<uint8_t, MslEncoderFormat>::const_iterator it = formatsById_.begin();
            it != formatsById_.end(); ++it)
    {
        if (it->second != INVALID) // don't report INVALID value
            v.insert(it->second);
    }
    return v;
}

bool operator==(const MslEncoderFormat& a, const MslEncoderFormat& b)
{
    return (a.name_ == b.name_) && (a.identifier_ == b.identifier_);
}

bool operator!=(const MslEncoderFormat& a, const MslEncoderFormat& b)
{
    return !(a==b);
}

bool operator<(const MslEncoderFormat& a, const MslEncoderFormat& b)
{
    return a.name_ < b.name_;
}

std::ostream & operator<<(std::ostream &os, const MslEncoderFormat& f)
{
    return os << f.name();
}

}}} // namespace netflix::msl::io
