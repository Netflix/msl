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

#ifndef SRC_MACROS_H_
#define SRC_MACROS_H_

#include <memory>

template<typename Base, typename T>
inline bool instanceof(const T *ptr) {
    return dynamic_cast<const Base*>(ptr) != 0;
}

template<typename Base, typename T>
inline bool instanceof(std::shared_ptr<T> ptr) {
	return std::dynamic_pointer_cast<Base>(ptr) != 0;
}

// A macro to disallow the copy constructor and operator= functions
// This should be used in the private: declarations for a class
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&);               \
  void operator=(const TypeName&)

// A macro to disallow all the implicit constructors, namely the
// default constructor, copy constructor and operator= functions.
// This should be used in the private: declarations for a class
// that wants to prevent anyone from instantiating it.
#define DISALLOW_IMPLICIT_CONSTRUCTORS(TypeName) \
  TypeName();                           \
  DISALLOW_COPY_AND_ASSIGN(TypeName)

#endif /* SRC_MACROS_H_ */
