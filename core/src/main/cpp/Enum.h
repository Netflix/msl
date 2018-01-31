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

#ifndef SRC_ENUM_H_
#define SRC_ENUM_H_

#include <IllegalArgumentException.h>
#include <algorithm>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace netflix
{
namespace msl
{

/**
 * Emulates a Java enum
 */
template<typename T> class Enum
{
public:
    virtual ~Enum() {}
    Enum(int value, const std::string strValue)
        : value_(value), strValue_(strValue) {}

    /** Comparison operators let you compare instances which each other. */
    bool operator<(const T& rhs) const {
        return value_ < rhs.value_;
    }
    bool operator==(const T& rhs) const {
        return value_ == rhs.value_;
    }

    /** Java method equivalents */
    static T fromString(const std::string& strValue) {
        return find(CompareString(strValue));
    }
    static T valueOf(int value) {
        return find(CompareInt(value));
    }
    std::string name() const { return stringValue(); }
    std::string toString() const { return stringValue(); }

    /** Accessors for internal data */
    int value() const { return value_; }
    int intValue() const { return value_; }
    std::string stringValue() const { return strValue_; }

private:
    // Comparison functors as helpers for finding instances
    struct CompareInt : public std::unary_function<T, bool>
    {
      explicit CompareInt(int i) : i(i) {}
      inline bool operator()(const T& m) const {return m.value() == i;}
      inline int getVal() const {return i;}
    private:
      const int i;
    };
    struct CompareString : std::unary_function<T, bool>
    {
      explicit CompareString(const std::string& s) : s(s) {}
      inline bool operator()(const T& m) const {return m.stringValue() == s;}
      inline std::string getVal() const {return s;}
    private:
      const std::string s;
    };

    // Unified function to find an instance. Takes one of the comparison
    // functors above that specifies how instances are checked.
    template <typename UnaryFunctor>
    static T find(const UnaryFunctor& comparator)
    {
        const std::vector<T>& values = T::getValues();
        typename std::vector<T>::const_iterator it =
            std::find_if(values.begin(), values.end(), comparator);
        if (it == values.end())
        {
            std::ostringstream sstream;
            sstream << "Unknown value " << comparator.getVal() << ".";
            throw IllegalArgumentException(sstream.str());
        }
        return *it;
    }

private:
    int value_;
    std::string strValue_;
};

} /* namespace msl */
} /* namespace netflix */

#endif /* SRC_ENUM_H_ */
