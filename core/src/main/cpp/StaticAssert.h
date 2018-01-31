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

#ifndef SRC_STATICASSERT_H_
#define SRC_STATICASSERT_H_

namespace netflix {
namespace msl {

// This is a static assertion macro that should hold us over until we get real
// compiler-supported static assertions in C++0x.  This is similar to the Boost
// implementation.  It only has one caveat: the implementation depends on an
// enum that uses the current line number to prevent name collisions.  However,
// if one file includes another one that has a static assertion on the same
// line, then there will be a spurious compile error.  The solution to that
// problem is to move one of the static assertions down or up one line.  :)

// The 4.3 version of gcc supports C++0x static assertions natively, with the
// -std=c++0x option enabled.

// The generic assertion template:
template <bool assert> struct STATIC_ASSERTION;

// Partial specialization for true assertions:
template <> struct STATIC_ASSERTION<true> {
  static int const value = 1;
};

// Partial specialization for false assertions is intentionally missing.

// This is done so the line number can become part of the enum name:
#define ASSERTION_ENUM_NAME2(x) ASSERTION_ENUM_ ## x
#define ASSERTION_ENUM_NAME(x) ASSERTION_ENUM_NAME2(x)

// The useful assertion macro.  This is the external interface:
#define STATIC_ASSERT(x) enum { \
  ASSERTION_ENUM_NAME(__LINE__) = STATIC_ASSERTION<x>::value \
}

}} // namespace netflix::msl

#endif /* SRC_STATICASSERT_H_ */
