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
#include <io/MslVariant.h>

#include <io/MslArray.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <io/StringVisitor.h>
#include <util/Base64.h>
#include <string>

using namespace std;

namespace netflix {
namespace msl {
namespace io {

std::string Variant::toString() const
{
    StringVisitor visitor;
    accept(visitor);
    return visitor.getString();
}

void Variant::accept(VariantVisitor& visitor) const
{
    value_->accept(visitor);
}

bool operator==(const Variant& a, const Variant& b)
{
    // two Variants are equal if they both point to the same underlying data
    if (a.value_ == b.value_) // compare shared_ptr's
        return true;
    // two Variants are equal only if their types match
    if (a.getHashCode() != b.getHashCode())
        return false;
    // two Variants are equal only if their underlying data is equal
    return a.value_.get()->isEqual(b.value_.get());
}
bool operator!=(const Variant& a, const Variant& b) { return !(a==b); }

bool operator==(const Null&, const Null&) {return true;}

bool operator==(std::shared_ptr<ByteArray> a, std::shared_ptr<ByteArray> b)
{
    return *a == *b;
}

bool operator==(std::shared_ptr<MslObject> a, std::shared_ptr<MslObject> b)
{
    return *a == *b;
}

bool operator==(std::shared_ptr<MslArray> a, std::shared_ptr<MslArray> b)
{
    return *a == *b;
}

//bool operator==(std::shared_ptr<MslEncodable> a, std::shared_ptr<MslEncodable> b)
//{
//    return *a == *b;
//}

}}} // namespace netflix::msl::io
