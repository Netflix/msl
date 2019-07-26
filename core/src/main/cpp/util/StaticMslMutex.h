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

#ifndef SRC_UTIL_STATICMSLMUTEX_H_
#define SRC_UTIL_STATICMSLMUTEX_H_

#include <Macros.h>
#include <util/Mutex.h>

namespace netflix {
namespace msl {
namespace util {

// This special IMutex implementation uses the same underlying MslMutex for all
// instances. In typical use, this is a static member used to mutex-protect
// statically initialized members.
class StaticMslMutex : public IMutex
{
public:
    StaticMslMutex();
    virtual void lock() {mutex_->lock();}
    virtual void unlock() {mutex_->unlock();};
    virtual bool islocked() const {return mutex_->islocked();}
private:
    static void init();
private:
    static MslMutex * mutex_;
    DISALLOW_COPY_AND_ASSIGN(StaticMslMutex);
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_STATICMSLMUTEX_H_ */
