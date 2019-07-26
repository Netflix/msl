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

#ifndef SRC_UTIL_SCOPEDOPENSSL_H_
#define SRC_UTIL_SCOPEDOPENSSL_H_

#include <stddef.h>

namespace netflix {
namespace msl {
namespace util {

// A helper class that takes care of destroying objects when they go out of scope.
template <typename T, typename R, R (*destructor)(T*)>
class ScopedDisposer
{
public:
    ScopedDisposer() : ptr_(NULL) {}
    explicit ScopedDisposer(T* ptr) : ptr_(ptr) {}
    ~ScopedDisposer() {reset(NULL);}
    bool isEmpty() const {return !ptr_;}
    operator bool() const {return ptr_;}
    operator T*() const {return ptr_;}
    T* get() const {return ptr_;}
    T* release()
    {
        T* ptr = ptr_;
        ptr_ = NULL;
        return ptr;
    }
    void reset(T* ptr)
    {
        if (ptr != ptr_)
        {
            if (ptr_) (*destructor)(ptr_);
            ptr_ = ptr;
        }
    }
private:
    T* ptr_;
    ScopedDisposer(const ScopedDisposer&);
    void operator=(const ScopedDisposer&);
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_SCOPEDOPENSSL_H_ */
