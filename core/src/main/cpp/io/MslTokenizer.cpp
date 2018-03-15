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

#include <io/MslObject.h>
#include <io/MslTokenizer.h>

using namespace std;

namespace netflix {
namespace msl {
namespace io {

bool MslTokenizer::more(int timeout)
{
    if (aborted_ || closed_)
        return false;
    if (next_)
        return true;
    next_ = nextObject(timeout);
    return (next_.get());
}

shared_ptr<MslObject> MslTokenizer::nextObject(int timeout)
{
    if (aborted_ || closed_)
        return shared_ptr<MslObject>();
    if (next_)
    {
        shared_ptr<MslObject> mo = next_;
        next_ = shared_ptr<MslObject>();
        return mo;
    }
    return next(timeout);
}

}}} // namespace netflix::msl::io
