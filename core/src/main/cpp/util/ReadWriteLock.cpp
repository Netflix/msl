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

#include <util/ReadWriteLock.h>

namespace netflix {
namespace msl {
namespace util {

ReadWriteLock::ReadWriteLock()
{
    pthread_rwlock_init(&lock_, nullptr);
}

ReadWriteLock::~ReadWriteLock()
{
    pthread_rwlock_destroy(&lock_);
}

void ReadWriteLock::readLock()
{
    pthread_rwlock_rdlock(&lock_);
}

void ReadWriteLock::writeLock()
{
    pthread_rwlock_wrlock(&lock_);
}

void ReadWriteLock::unlock()
{
    pthread_rwlock_unlock(&lock_);
}

}}} // namespace netflix::msl::util
