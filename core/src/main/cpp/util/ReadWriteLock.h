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

#ifndef SRC_UTIL_READWRITELOCK_H_
#define SRC_UTIL_READWRITELOCK_H_

#include <pthread.h>

namespace netflix {
namespace msl {
namespace util {

/**
 * <p>A read-write lock allows multiple readers to simultaneously acquire the
 * lock and a single writer to exclusively acquire the lock. A writer will
 * block until there are no readers and then acquire the lock. Readers will
 * block if there is a writer waiting to acquire the lock.</p>
 */
// C++11 does not support std::shared_mutex, which would be required to
// implement a read/write lock using the C++11 Threading Library. So short of
// moving to C++14 (which does have std::shared_mutex) or else using
// boost::shared_mutex, we use the old pthread rwlock implementation.
class ReadWriteLock
{
public:
    ReadWriteLock();
    ~ReadWriteLock();
    void readLock();
    void writeLock();
    void unlock();
private:
    pthread_rwlock_t lock_;
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_READWRITELOCK_H_ */
