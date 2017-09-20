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

#include <tokens/MslUser.h>
#include <util/MslUtils.h>

using namespace std;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace tokens {

bool operator==(const MslUser& a, const MslUser& b)
{
	shared_ptr<const MslUser> ap(&a, &MslUtils::nullDeleter<MslUser>);
	shared_ptr<const MslUser> bp(&b, &MslUtils::nullDeleter<MslUser>);
	return ap->equals(bp);
}

}}} // namespace netflix::msl:tokens
