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

#include <assert.h>
#include <MslInternalException.h>
#include <util/Mutex.h>
#include <util/ScopedDisposer.h>

namespace netflix {
namespace msl {
namespace util {

MslMutex::MslMutex() : lockCount_(0)
{
    pthread_mutexattr_t attr;
    ScopedDisposer<pthread_mutexattr_t, int, pthread_mutexattr_destroy> attrDisposer(&attr);
    if (pthread_mutexattr_init(&attr) != 0)
        throw MslInternalException("Failed pthread_mutexattr_init");
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0)
        throw MslInternalException("Failed pthread_mutexattr_settype");
    if (pthread_mutex_init(&ptmutex_, &attr) != 0)
        throw MslInternalException("Failed pthread_mutex_init");
}

MslMutex::~MslMutex()
{
    assert(!islocked());
    // FIXME: more portable way to do unused?
    int ret __attribute__((unused)) = pthread_mutex_destroy(&ptmutex_);
    assert(ret == 0);
}

void MslMutex::lock()
{
    if (pthread_mutex_lock(&ptmutex_) != 0)
        throw MslInternalException("Failed pthread_mutex_lock");
    lockCount_++;
}

void MslMutex::unlock()
{
    if (!islocked())
        return;
    if (pthread_mutex_unlock(&ptmutex_) != 0)
        throw MslInternalException("Failed pthread_mutex_unlock");
    lockCount_--;
}

}}} // namespace netflix::msl::util

