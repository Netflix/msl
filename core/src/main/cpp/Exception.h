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

#ifndef SRC_EXCEPTION_H_
#define SRC_EXCEPTION_H_

#include <memory>
#include <stdexcept>
#include <string>

namespace netflix
{
namespace msl
{

class IException
{
public:
    virtual std::shared_ptr<IException> clone() const = 0;
    virtual std::shared_ptr<IException> getCause() const = 0;
    virtual uint32_t getDepth() const = 0;
    virtual const char* what() const throw() = 0;
protected:
    virtual inline ~IException() {}
};

/**
 * Make a polymorphic copy of an IException
 *
 * @return shared_ptr to a copy of this
 */
#define DECLARE_EXCEPTION_CLONE(class_name) virtual inline std::shared_ptr<IException> clone() const \
{ \
    return std::shared_ptr<IException>(std::make_shared<class_name>(*this)); \
}

/**
 * Emulation of a Java Exception with nested cause.
 */
class Exception : public IException, public std::runtime_error
{
public:
    /**
     * Construct a new Exception from a std::exception.
     *
     * @param ex an exception instance from std::exception.
     */
    explicit Exception(const std::exception& ex);

    /**
     * Construct a new Exception with the specified message.
     *
     * @param details the details message.
     */
    explicit Exception(const std::string& details);

    /**
     * Construct a new Exception with the specified message and cause.
     *
     * @param details the details message.
     * @param cause the cause.
     */
    Exception(const std::string& details, const IException& cause);

    virtual inline ~Exception() throw() {}

    /**
     * Get the cause exception associated with this.
     *
     * @return shared_ptr to the nested exception, may be empty
     */
    virtual inline std::shared_ptr<IException> getCause() const { return cause_; }

    /**
     * Get depth of the exception chain. Minimum value is 1.
     *
     * @return depth of this exception chain
     */
    virtual uint32_t getDepth() const;

    virtual const char* what() const throw() { return std::runtime_error::what(); }

    DECLARE_EXCEPTION_CLONE(Exception);

protected:
     /** Nested cause exception **/
     std::shared_ptr<IException> cause_;

private:
    Exception();
};

} /* namespace msl */
} /* namespace netflix */

#endif /* SRC_EXCEPTION_H_ */
