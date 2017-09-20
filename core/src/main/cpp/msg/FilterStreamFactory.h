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

#ifndef SRC_MSG_FILTERSTREAMFACTORY_H_
#define SRC_MSG_FILTERSTREAMFACTORY_H_

#include <memory>

namespace netflix {
namespace msl {
namespace io { class InputStream; class OutputStream; }
namespace msg {

/**
 * A filter stream factory provides filter input stream and filter output
 * stream instances.
 *
 * Implementations must be thread-safe.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class FilterStreamFactory {
public:
	virtual ~FilterStreamFactory() {}

    /**
     * Return a new input stream that has the provided input stream as its
     * backing source. If no filtering is desired then the original input
     * stream must be returned.
     *
     * @param in the input stream to wrap.
     * @return a new filter input stream backed by the provided input stream or
     *         the original input stream..
     */
    virtual std::shared_ptr<io::InputStream> getInputStream(std::shared_ptr<io::InputStream> in) = 0;

    /**
     * Return a new output stream that has the provided output stream as its
     * backing destination. If no filtering is desired then the original output
     * stream must be returned.
     *
     * @param out the output stream to wrap.
     * @return a new filter output stream backed by the provided output stream
     *         or the original output stream.
     */
    virtual std::shared_ptr<io::OutputStream> getOutputStream(std::shared_ptr<io::OutputStream> out) = 0;
};

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_FILTERSTREAMFACTORY_H_ */
