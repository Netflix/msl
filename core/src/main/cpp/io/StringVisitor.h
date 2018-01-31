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

#ifndef SRC_IO_STRINGVISITOR_H_
#define SRC_IO_STRINGVISITOR_H_

#include <io/MslVariant.h>
#include <sstream>

namespace netflix {
namespace msl {
namespace io {

class Null;
class MslObject;
class MslArray;
class MslEncodable;

class StringVisitor : public VariantVisitor
{
public:
    StringVisitor() {}
    virtual void visit(const Null&);
    virtual void visit(const std::string& x);
    virtual void visit(int x);
    virtual void visit(unsigned x);
    virtual void visit(int64_t x);
    virtual void visit(uint64_t x);
    virtual void visit(double x);
    virtual void visit(bool x);
    virtual void visit(std::shared_ptr<ByteArray> x);
    virtual void visit(std::shared_ptr<MslObject> x);
    virtual void visit(std::shared_ptr<MslArray> x);
    virtual void visit(std::shared_ptr<MslEncodable> x);
    std::string getString() const;
private:
    std::ostringstream oss_;
};


}}} // namespace netflix::msl::io


#endif /* SRC_IO_STRINGVISITOR_H_ */
