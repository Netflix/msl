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

#include <io/MslArray.h>
#include <io/MslEncodable.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <io/StringVisitor.h>
#include <ios>
#include <util/Base64.h>

using namespace std;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace io {

void StringVisitor::visit(const Null&)
{
    oss_ << "null";
}

void StringVisitor::visit(const string& x)
{
    oss_ << MslEncoderFactory::quote(x);
}

void StringVisitor::visit(int x)
{
    oss_ << x;
}

void StringVisitor::visit(unsigned x)
{
    oss_ << x;
}

void StringVisitor::visit(int64_t x)
{
    oss_ << x;
}

void StringVisitor::visit(uint64_t x)
{
    oss_ << x;
}

void StringVisitor::visit(double x)
{
    oss_ << x;
}

void StringVisitor::visit(bool x)
{
    oss_ << std::boolalpha << x;
}

void StringVisitor::visit(shared_ptr<ByteArray> x)
{
    oss_ << MslEncoderFactory::quote(*Base64::encode(x));
}

void StringVisitor::visit(shared_ptr<MslObject> x)
{
    oss_ << (x ? x->toString() : "null");
}

void StringVisitor::visit(shared_ptr<MslArray> x)
{
    oss_ << (x ? x->toString() : "null");
}

void StringVisitor::visit(shared_ptr<MslEncodable> x)
{
    oss_ << x.get();
}

std::string StringVisitor::getString() const
{
    return oss_.str();
}



}}} // namespace netflix::msl::io
