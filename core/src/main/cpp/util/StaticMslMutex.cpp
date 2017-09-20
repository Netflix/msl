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

#include <pthread.h>
#include <util/StaticMslMutex.h>
#include <cstdlib>

namespace netflix {
namespace msl {
namespace util {

namespace {
pthread_once_t once = PTHREAD_ONCE_INIT;
void mutexOnce(pthread_once_t *once, void (*init)(void))
{
    if (pthread_once(once, init) != 0) {
        abort();
    }
}
}

MslMutex * StaticMslMutex::mutex_ = 0;

StaticMslMutex::StaticMslMutex()
{
    mutexOnce(&once, StaticMslMutex::init);
}

// static
void StaticMslMutex::init()
{
    if (!mutex_)
        mutex_ = new MslMutex();
}

}}} // namespace netflix::msl::util
