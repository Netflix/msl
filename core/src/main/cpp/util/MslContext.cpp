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

#include <util/MslContext.h>
#include <IllegalArgumentException.h>
#include <numerics/safe_math.h>
#include <util/StaticMslMutex.h>

using namespace std;
using base::internal::CheckedNumeric;

namespace netflix {
namespace msl {
namespace util {

namespace {

const int64_t MILLISECONDS_PER_SECOND = 1000;

StaticMslMutex staticMutex;

uint32_t nextId() {
    LockGuard lock(staticMutex);
    static CheckedNumeric<uint32_t> id = 0;
    if (!(id++.IsValid())) {
        assert(false);
    }
    return id.ValueOrDie();
}

} // namespace anonymous

// NOTE: Static initialization of MslContext::ReauthCode::ENTITY_REAUTH,
// MslContext::ReauthCode::ENTITYDATA_REAUTH, and MslContext::ReauthCode::INVALID
// is done in MslContants.cpp.

// static
const std::vector<MslContext::ReauthCode>& MslContext::ReauthCode::getValues() {
    static std::vector<MslContext::ReauthCode> gValues;
    if (gValues.empty()) {
        gValues.push_back(ENTITY_REAUTH);
        gValues.push_back(ENTITYDATA_REAUTH);
        gValues.push_back(INVALID);
    }
    return gValues;
}

// static
MslContext::ReauthCode MslContext::ReauthCode::valueOf(const MslConstants::ResponseCode& code)
{
    const std::vector<MslContext::ReauthCode>& values = getValues();
    std::vector<MslContext::ReauthCode>::const_iterator it;
    for (it = values.begin(); it != values.end(); ++it)
    {
        if (it->responseCode_ == code)
            return *it;
    }
    std::ostringstream sstream;
    sstream << "Unknown value " << code << ".";
    throw IllegalArgumentException(sstream.str());
}

MslContext::MslContext() : id_(nextId())
{
}

void MslContext::updateRemoteTime(shared_ptr<Date> time)
{
    const int64_t localSeconds = getTime() / MILLISECONDS_PER_SECOND;
    const int64_t remoteSeconds = time->getTime() / MILLISECONDS_PER_SECOND;
    offset_ = remoteSeconds - localSeconds;
    synced_ = true;
}

shared_ptr<Date> MslContext::getRemoteTime()
{
    if (!synced_) return shared_ptr<Date>();
    const int64_t localSeconds = getTime() / MILLISECONDS_PER_SECOND;
    const int64_t remoteSeconds = localSeconds + offset_;
    return make_shared<Date>(remoteSeconds * MILLISECONDS_PER_SECOND);
}

bool MslContext::equals(std::shared_ptr<const MslContext> other) const
{
    return id_ == other->id_;
}

}}} // namespace netflix::msl::util
