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

#ifndef SRC_UTIL_DEBUG_H_
#define SRC_UTIL_DEBUG_H_

#include <ostream>

namespace netflix {
namespace msl {
namespace util {

class Debug
{
  public:
#ifdef DEBUG
    Debug(std::ostream& s) : stream(s) {}
    template<typename T> Debug& operator<<(const T& item)
    {
      stream << item;
      return *this;
    }
    Debug& operator<<(std::ostream& (*pf)(std::ostream&))
    {
      stream << pf;
      return *this;
    }
  private:
    std::ostream& stream;
#else
    Debug(std::ostream&) {}
    template<typename T> Debug& operator<<(const T&) { return *this; }
    Debug& operator<<(std::ostream& (*pf)(std::ostream&)) { (void)pf; return *this; }
#endif
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_DEBUG_H_ */
