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

#ifndef SRC_IO_JSONHANDLER_H_
#define SRC_IO_JSONHANDLER_H_

#include <io/MslVariant.h>
#include <io/MslArray.h>
#include <io/MslObject.h>
#include <rapidjson/rapidjson.h>
#include <stdint.h>
#include <memory>
#include <stack>
#include <string>

namespace netflix {
namespace msl {
namespace io {

class MslObject;
class MslArray;

/** Implementation of rapidjson handler to translate from DOM to MslObject/Array */
class JsonHandler
{
public:
    ~JsonHandler() {}
    JsonHandler(std::shared_ptr<MslObject> mo);
    JsonHandler(std::shared_ptr<MslArray> ma);
    bool StartObject();
    bool EndObject(rapidjson::SizeType memberCount);
    bool StartArray();
    bool EndArray(rapidjson::SizeType elementCount);
    bool Key(const char* str, rapidjson::SizeType length, bool copy);
    bool String(const char* str, rapidjson::SizeType length, bool copy);
    bool Null();
    bool Bool(bool b);
    bool Int(int i);
    bool Uint(unsigned u);
    bool Int64(int64_t i);
    bool Uint64(uint64_t u);
    bool Double(double d);
    bool RawNumber(const char* str, rapidjson::SizeType length, bool copy);
    bool Default();
private:
    JsonHandler(); // not implemented
    struct ObjectHolder
    {
        std::string name;
        Variant obj;
        ObjectHolder(); // not implemented
        ObjectHolder(const std::string& name, std::shared_ptr<MslObject> obj) : name(name), obj(VariantFactory::create<std::shared_ptr<MslObject>>(obj)) {}
        ObjectHolder(const std::string& name, std::shared_ptr<MslArray> obj) : name(name), obj(VariantFactory::create<std::shared_ptr<MslArray>>(obj)) {}
    };
    enum State {
        kFirst,
        kInObject,
        kInArray,
    };
    void setTopVal(const Variant& val);
    static const uint32_t MAX_DEPTH = 5;
    std::stack<ObjectHolder> stack_;
    ObjectHolder root_;
    State state_;
    std::string name_;
    uint32_t curDepth_;
    bool first_;
};

}}} // netflix::msl::io

#endif /* SRC_IO_JSONHANDLER_H_ */
