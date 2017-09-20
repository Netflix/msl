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

#ifndef SRC_UTIL_CONCURRENTHASHMAP_H_
#define SRC_UTIL_CONCURRENTHASHMAP_H_

#include <tokens/MasterToken.h>
#include <util/BlockingQueue.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>
#include <algorithm>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace netflix {
namespace msl {
namespace util {

/**
 * A specialized thread-safe wrapper around an STL map, intended to emulate
 * java's ConcurrentHashMap, but only to the degree that MslControl requires.
 * Keys and values are stored as shared_ptr's. By default, key equality is
 * determined by delegating to KeyType::equals() via MslUtils::sharedPtrKeyEqual2,
 * but a custom predicate may also be provided.
 * This class requires C++11.
 */
template <typename KeyType, typename ValueType, typename Predicate = MslUtils::sharedPtrKeyEqual2<KeyType, ValueType>>
class ConcurrentHashMap
{
public:
    ~ConcurrentHashMap() { std::lock_guard<std::mutex> lock(mutex_); }
    ConcurrentHashMap() { std::lock_guard<std::mutex> lock(mutex_); }

    /**
     * If the specified key is not already associated with a value, associate it
     * with the given value.
     * This method is thread-safe.
     *
     * @param key key.
     * @param value value.
     * @return The value now associated with the key.
     */
    std::shared_ptr<ValueType> putIfAbsent(std::shared_ptr<KeyType> key, std::shared_ptr<ValueType> value)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = std::find_if(map_.begin(), map_.end(), Predicate(key));
        if (it == map_.end()) {
            map_.insert(make_pair(key, value));
            return std::shared_ptr<ValueType>(); // Java hash map returns null if the key was not there.
        } else {
            return it->second;
        }
    }

    /**
     * Returns the value to which the specified key is mapped, or an empty
     * shared_ptr<ValueType> if this map contains no mapping for the key.
     * This method is thread-safe.
     *
     * @param key key.
     * @return The value which maps to the key, else an empty shared_ptr<ValueType>.
     */
    std::shared_ptr<ValueType> get(std::shared_ptr<KeyType> key) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = std::find_if(map_.begin(), map_.end(), Predicate(key));
        return (it != map_.end()) ? it->second : std::shared_ptr<ValueType>();
    }

    /**
     * Removes the key (and its corresponding value) from this map. This method
     * does nothing if the key is not in the map.
     * This method is thread-safe.
     *
     * @param key key.
     * @return The value which maps to the key, else an empty shared_ptr<ValueType>.
     */
    std::shared_ptr<ValueType> remove(std::shared_ptr<KeyType> key)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = std::find_if(map_.begin(), map_.end(), Predicate(key));
        if (it == map_.end()) return std::shared_ptr<ValueType>();
        std::shared_ptr<ValueType> value = it->second;
        map_.erase(it);
        return value;
    }

    /**
     * Clear the map.
     * This method is thread-safe.
     */
    void clear()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        map_.clear();
    }

    size_t size() const { return map_.size(); }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::shared_ptr<KeyType>, std::shared_ptr<ValueType>> map_;
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_CONCURRENTHASHMAP_H_ */
