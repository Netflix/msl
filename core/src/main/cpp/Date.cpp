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

#include <assert.h>
#include <Date.h>
#include <sys/time.h>
#include <ctime>
#include <memory>
#include <sstream>

using namespace std;

namespace netflix {
namespace msl {

// static
shared_ptr<Date> Date::now()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    const int64_t msSinceEpoch = static_cast<int64_t>(static_cast<uint64_t>(tp.tv_sec) * 1000ull + static_cast<uint64_t>(tp.tv_usec) / 1000ull);
    return make_shared<Date>(msSinceEpoch);
}

// Return the value 0 if the argument Date is equal to this Date; a value less
// than 0 if this Date is before the Date argument; and a value greater than 0
// if this Date is after the Date argument.
int Date::compareTo(shared_ptr<Date> other) const
{
    if (this == other.get() || *this == *other) return 0;
    if (*this < *other) return -1;
    else return 1;
}

/*
    Converts this Date object to a String of the form:
        dow mon dd hh:mm:ss zzz yyyy
    where:
    dow is the day of the week (Sun, Mon, Tue, Wed, Thu, Fri, Sat).
    mon is the month (Jan, Feb, Mar, Apr, May, Jun, Jul, Aug, Sep, Oct, Nov, Dec).
    dd is the day of the month (01 through 31), as two decimal digits.
    hh is the hour of the day (00 through 23), as two decimal digits.
    mm is the minute within the hour (00 through 59), as two decimal digits.
    ss is the second within the minute (00 through 61, as two decimal digits.
    zzz is the time zone (and may reflect daylight saving time). Standard time zone
    abbreviations include those recognized by the method parse. If time zone
    information is not available, then zzz is empty - that is, it consists of no
    characters at all.
    yyyy is the year, as four decimal digits.
 */
string Date::toString() const
{
    const time_t secondsSinceEpoch = static_cast<time_t>(msSinceEpoch_ / 1000ll);
    const tm* const t = gmtime(&secondsSinceEpoch);
    string out(asctime(t));
    out.pop_back(); // strip trailing newline left by asctime
    out.insert(20, "GMT ");
    return out;
}

ostream& operator<<(ostream &os, const Date& date)
{
    os << date.toString();
    return os;
}

ostream& operator<<(ostream &os, std::shared_ptr<Date> date)
{
    os << date->toString();
    return os;
}

}} // namespace netflix::msl
