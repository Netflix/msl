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

#ifndef SRC_TOKENS_MSLUSER_H_
#define SRC_TOKENS_MSLUSER_H_
#include <string>
#include <memory>

namespace netflix {
namespace msl {
namespace tokens {

/**
 * <p>A MSL user. The {@link #equals(Object)} and {@link #getEncoded()} methods
 * must be implemented.</p>
 */
class MslUser
{
public:
    virtual ~MslUser() {}

    /*
     * <p>Returns a serialized data encoding of the MSL user. This is the value
     * that will be used by the MSL stack during transport and to reconstruct
     * the MSL user instance.</p>
     *
     * @return the MSL user encoding.
     */
    virtual std::string getEncoded() const = 0;

    /**
     * <p>Compares this object against the provided object. This method must
     * return true if the provided object is a {@code MslUser} referencing the
     * same MSL user.</p>
     *
     * @param obj the object with which to compare.
     * @return {@code true} if the object is a {@code MslUser} that references
     *         the same MSL user.
     * @see #hashCode()
     */
    virtual bool equals(std::shared_ptr<const MslUser> obj) const = 0;
};

bool operator==(const MslUser& a, const MslUser& b);
inline bool operator!=(const MslUser& a, const MslUser& b) { return !(a == b); }
inline bool operator<(const MslUser& a, const MslUser& b) { return a.getEncoded() < b.getEncoded(); }

}}} // namespace netflix::msl:tokens


#endif /* SRC_TOKENS_MSLUSER_H_ */
