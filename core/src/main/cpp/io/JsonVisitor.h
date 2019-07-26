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

#ifndef SRC_IO_JSONVISITOR_H_
#define SRC_IO_JSONVISITOR_H_

#include <io/MslVariant.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <memory>

namespace netflix {
namespace msl {
namespace io {
class MslEncoderFactory;

class JsonVisitor : public VariantVisitor
{
public:
    virtual ~JsonVisitor() {}
    explicit JsonVisitor(std::shared_ptr<MslEncoderFactory> encoder,
            rapidjson::Writer<rapidjson::StringBuffer>& w)
    : encoder_(encoder), writer_(w) {}
    virtual void visit(const Null& x);
    virtual void visit(const std::string& x);
    virtual void visit(bool x);
    virtual void visit(int32_t x);
    virtual void visit(int64_t x);
    virtual void visit(double x);
    virtual void visit(std::shared_ptr<ByteArray> x);
    virtual void visit(std::shared_ptr<MslObject> x);
    virtual void visit(std::shared_ptr<MslArray> x);
    virtual void visit(std::shared_ptr<MslEncodable> x);
private:
    std::shared_ptr<MslEncoderFactory> encoder_;
    rapidjson::Writer<rapidjson::StringBuffer>& writer_;
};

}}} // namespace netflix::msl::io

#endif /* SRC_IO_JSONVISITOR_H_ */
