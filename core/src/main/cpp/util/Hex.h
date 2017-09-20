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

#ifndef SRC_UTIL_HEX_H_
#define SRC_UTIL_HEX_H_

#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
namespace util {

typedef std::vector<uint8_t> ByteArray;

std::shared_ptr<ByteArray> fromHex(const std::string &in);
std::string toHex(std::shared_ptr<ByteArray> in);

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_HEX_H_ */
