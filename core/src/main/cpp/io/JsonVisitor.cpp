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

#include <io/JsonVisitor.h>
#include <io/MslArray.h>
#include <io/MslEncodable.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <util/Base64.h>
#include <assert.h>

using namespace std;

namespace netflix {
namespace msl {
namespace io {

void JsonVisitor::visit(const Null&)
{
    bool success; (void)success;
    success = writer_.Null();
}

void JsonVisitor::visit(const std::string& x)
{
    bool success; (void)success;
    success = writer_.String(x.c_str());
}

void JsonVisitor::visit(bool x)
{
    bool success; (void)success;
    success = writer_.Bool(x);
}

void JsonVisitor::visit(int32_t x)
{
    bool success; (void)success;
    success = writer_.Int(static_cast<int>(x));
}

void JsonVisitor::visit(int64_t x)
{
    bool success; (void)success;
    success = writer_.Int64(x);
}

void JsonVisitor::visit(double x)
{
    bool success; (void)success;
    success = writer_.Double(x);
}

void JsonVisitor::visit(shared_ptr<ByteArray> x)
{
    bool success; (void)success;
    std::shared_ptr<std::string> b64 = util::Base64::encode(x);
    success = writer_.String(b64->c_str());
}

void JsonVisitor::visit(shared_ptr<MslObject> x)
{
    bool success; (void)success;
    if (!x) {
        success = writer_.Null();
        assert(success);
        return;
    }
    success = writer_.StartObject();
    assert(success);
    std::vector<std::string> keys = x->getKeys();
    for (std::vector<std::string>::const_iterator it = keys.begin();
         it != keys.end();
         ++it)
    {
        const std::string& key = *it;
        success = writer_.Key(key.c_str());
        assert(success);
        const Variant value = x->get(key);
        value.accept(*this);  // recurse
    }
    success = writer_.EndObject();
    assert(success);
}

void JsonVisitor::visit(shared_ptr<MslArray> x)
{
    bool success; (void)success;
    if (!x) {
        success = writer_.Null();
        assert(success);
        return;
    }
    success = writer_.StartArray();
    assert(success);
    const std::vector<Variant> variants = x->getCollection();
    for (std::vector<Variant>::const_iterator it = variants.begin();
         it != variants.end();
         ++it)
    {
        it->accept(*this);  // recurse
    }
    success = writer_.EndArray();
    assert(success);
}

void JsonVisitor::visit(shared_ptr<MslEncodable> x)
{
    bool success; (void)success;
    if (!x) {
        success = writer_.Null();
        assert(success);
        return;
    }
    shared_ptr<ByteArray> ba = x->toMslEncoding(encoder_, MslEncoderFormat::JSON);
    success = writer_.RawValue(reinterpret_cast<const char *>(&(*ba)[0]), ba->size(), rapidjson::kObjectType);
    assert(success);
}

} /* namespace io */
} /* namespace msl */
} /* namespace netflix */
