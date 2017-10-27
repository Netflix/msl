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

#ifndef SRC_UTIL_MSLUTILS_H_
#define SRC_UTIL_MSLUTILS_H_

#include <MslConstants.h>
#include <MslException.h>
#include <algorithm>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

namespace netflix {
namespace msl {

typedef std::vector<uint8_t> ByteArray;

namespace util {

class MslContext;

/**
 * Utility methods.
 */
namespace MslUtils {

/**
 * Throws the provided {@code MslException} after translating it to the proper
 * original type.
 */
void rethrow(const MslException& e);

/**
 * Throws the provided {@code MslException} after translating it to the proper
 * original type. If the provided exception is not a {@code MslException} then
 * this function simply returns.
 */
void rethrow(std::shared_ptr<IException> e);

// Functor used to find an entry in std::map that has shared_ptr's as keys. T is
// the type of the map. Dereferences the map key shared_ptr to identify a
// key match.
template<typename T>
struct sharedPtrKeyEqual : std::unary_function<typename T::value_type, bool>
{
	sharedPtrKeyEqual(const typename T::key_type& key) : key(key) {}
	bool operator()(const typename T::value_type& value) const { return *value.first == *key; }
	const typename T::key_type& key;
};

// Same as above, except the template parameters are the types of the key and
// value, not the map type.
// FIXME should do this via operator ==.
template<typename KeyType, typename ValueType>
struct sharedPtrKeyEqual2 : std::unary_function<std::pair<std::shared_ptr<KeyType>, std::shared_ptr<ValueType>>, bool>
{
    sharedPtrKeyEqual2(const std::shared_ptr<KeyType>& key) : key(key) {}
    bool operator()(const std::pair<std::shared_ptr<KeyType>, std::shared_ptr<ValueType>>& v) const { return v.first->equals(key); }
    const std::shared_ptr<KeyType>& key;
};

// Functor used to find an entry in std::set that has shared_ptr's as values.
// Derefs the shared_ptr to identify a match.
template<typename T>
struct sharedPtrEqual : std::unary_function<typename T::value_type, bool>
{
	sharedPtrEqual(const typename T::value_type& value) : value(value) {}
	bool operator()(const typename T::value_type& value) const { return *value == *this->value; }
	const typename T::value_type& value;
};

// Noop deleter for shared_ptr
template<typename T>
void nullDeleter(const T *) {}

// Compare two shared_ptrs of type T. First check pointer values against null,
// then pointers against each other, and finally delegate to T::operator==().
template <typename T>
bool sharedPtrCompare(const std::shared_ptr<T>& a, const std::shared_ptr<T>& b)
{
    if (!a && !b) return true;
    if (!a || !b) return false;
    if (a == b) return true;
    return *a == *b;
}

// Case-insensitive string compare.
bool insStringCompare(std::string const& a, std::string const& b);


/**
 * Returns a random number between zero and the maximum long value as
 * defined by {@link MslConstants#MAX_LONG_VALUE}, inclusive.
 *
 * @param ctx MSL context.
 * @return a random number between zero and the maximum long value,
 *         inclusive.
 */
int64_t getRandomLong(std::shared_ptr<MslContext> ctx);

} // namespace MslUtils

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_MSLUTILS_H_ */
