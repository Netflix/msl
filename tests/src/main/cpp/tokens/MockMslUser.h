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

#ifndef TEST_TOKENS_MOCKMSLUSER_H_
#define TEST_TOKENS_MOCKMSLUSER_H_

#include <Macros.h>
#include <tokens/MslUser.h>
#include <IllegalArgumentException.h>
#include <string>
#include <sstream>
#include <memory>

namespace netflix {
namespace msl {
namespace tokens {

class MockMslUser : public netflix::msl::tokens::MslUser
{
public:
	virtual ~MockMslUser() {}

    /**
     * Create a new MSL user with the specified user ID.
     *
     * @param id MSL user ID.
     */
    MockMslUser(int64_t id) : id_(id) {}

    /**
     * Create a new MSL user from the serialized user data.
     *
     * @param userdata serialized user data.
     * @throws IllegalArgumentException if the user data is invalid.
     */
    MockMslUser(const std::string& idStr)
    {
        std::stringstream convert(idStr);
        if ( !(convert >> id_) ) {
        	std::stringstream ss;
        	ss << "Invalid user data serialization: " << idStr;
            throw IllegalArgumentException(ss.str());
        }
    }

    /**
     * @return the user ID.
     */
    int64_t getId() { return id_; }

    /** @inheritDoc */
    virtual std::string getEncoded() const
    {
        std::stringstream ss;
        ss << id_;
        return ss.str();
    }

    /** @inheritDoc */
    virtual bool equals(std::shared_ptr<const netflix::msl::tokens::MslUser> other) const
    {
    	if (!other) return false;
    	if (this == other.get()) return true;
    	if (!instanceof<const MockMslUser>(other)) return false;
    	std::shared_ptr<const MockMslUser> mmu = std::dynamic_pointer_cast<const MockMslUser>(other);
        return id_ == mmu->id_;
    }

private:
    int64_t id_;
};

}}} // namespace netflix::msl::tokens

#endif /* TEST_TOKENS_MOCKMSLUSER_H_ */
