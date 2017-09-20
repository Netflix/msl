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

#ifndef SRC_UTIL_MUTEX_H_
#define SRC_UTIL_MUTEX_H_

#include <Macros.h>
#include <pthread.h>

namespace netflix {
namespace msl {
namespace util {

struct IMutex
{
    virtual ~IMutex() {};
    virtual void lock() = 0;
    virtual void unlock() = 0;
    virtual bool islocked() const = 0;
};

class MslMutex : public IMutex
{
public:
    MslMutex();
    ~MslMutex();
    virtual void lock();
    virtual void unlock();
    virtual bool islocked() const { return lockCount_ != 0; };
private:
    pthread_mutex_t ptmutex_;
    volatile int lockCount_;
    DISALLOW_COPY_AND_ASSIGN(MslMutex);
};

class LockGuard
{
public:
    explicit LockGuard(IMutex& mutex) : mutex(mutex) { mutex.lock(); }
    ~LockGuard() { mutex.unlock(); }
private:
    IMutex& mutex;
};

#define synchronized(mutex, op) \
do { \
    LockGuard lg(mutex); \
    op \
} while (0)

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_MUTEX_H_ */
