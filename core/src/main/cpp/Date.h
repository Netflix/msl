/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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

#ifndef SRC_DATE_H_
#define SRC_DATE_H_

#include <assert.h>
#include <stdint.h>
#include <iosfwd>
#include <string>

namespace netflix {
namespace msl {

class Date;

inline bool operator==(const Date& a, const Date& b);
inline bool operator!=(const Date& a, const Date& b);
inline bool operator<(const Date& a, const Date& b);
inline bool operator>=(const Date& a, const Date& b);
inline bool operator>(const Date& a, const Date& b);
inline bool operator<=(const Date& a, const Date& b);

class Date
{
public:
    Date();
    Date(int64_t msSinceEpoch, bool isNull = false) : isNull_(isNull), msSinceEpoch_(msSinceEpoch) {}
    Date(const Date& rhs) : isNull_(rhs.isNull_), msSinceEpoch_(rhs.msSinceEpoch_) {}
    Date& operator=(const Date& rhs);
    static Date now();
    static Date null();
    bool isNull() const { return isNull_; }

    // -- Java method equivalents --

    //Tests if this date is after the specified date.
    bool after(const Date& when) const { return *this > when; }
    // Tests if this date is before the specified date.
    bool before(const Date& when) const { return *this < when; }
    // Return a copy of this object.
    Date clone() const { return *this; }
    // Compares two Dates for ordering.
    int compareTo(const Date& anotherDate) const;
    // Compares two dates for equality.
    bool equals(const Date& other) const { return other == *this; }
    // Returns the number of milliseconds since January 1, 1970, 00:00:00 GMT represented by this Date object.
    int64_t getTime() const { return msSinceEpoch_; }
    // Converts this Date object to a String of the form:
    std::string toString() const;

private:
    bool isNull_;
    int64_t msSinceEpoch_;
};

inline bool operator==(const Date& a, const Date& b)
{
    if (a.isNull() == b.isNull()) {
        return a.isNull() ? true : (a.getTime() == b.getTime());
    }
    return false;
}
inline bool operator!=(const Date& a, const Date& b) { return !(a==b); }
inline bool operator<(const Date& a, const Date& b) { assert(!a.isNull() && !b.isNull()); return a.getTime() < b.getTime(); }
inline bool operator>=(const Date& a, const Date& b) { return !(a < b); }
inline bool operator>(const Date& a, const Date& b) { assert(!a.isNull() && !b.isNull()); return a.getTime() > b.getTime(); }
inline bool operator<=(const Date& a, const Date& b) { return !(a > b); }
std::ostream & operator<<(std::ostream &os, const Date& p);

}} // namespace netflix::msl

#endif /* SRC_DATE_H_ */
