/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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

#ifndef SRC_IO_URL_H_
#define SRC_IO_URL_H_

#include "InputStream.h"
#include "OutputStream.h"

namespace netflix {
namespace msl {
namespace io {

class Connection;

/**
 * The URL interface provides access to an input stream and output stream tied
 * to a specific URL.
 */
class Url
{
public:
    virtual ~Url() {};

    /**
     * Set the connection timeout for open and read operations.
     *
     * @param timeout connection timeout in milliseconds.
     */
    virtual void setTimeout(int64_t timeout) = 0;

    /**
     * Open a new connection to the target location.
     *
     * @return a {@link Connection} linking to the URL.
     * @throws IOException if an I/O exception occurs.
     */
    virtual std::shared_ptr<Connection> openConnection() = 0;
};

/**
 * The Connection interface represents a communication link between the
 * application and a URL.
 */
class Connection
{
public:
    virtual ~Connection() {};

    /**
     * <p>Returns an input stream that reads from this connection.</p>
     *
     * <p>Asking for the input stream must not prevent use of the output
     * stream, but reading from the input stream may prevent further
     * writing to the output stream.</p>
     *
     * <p>The returned input stream must support
     * {@link InputStream#mark(int)}, {@link InputStream#reset()}, and
     * {@link InputStream#skip(long)} if you wish to use it for more than
     * one MSL message.</p>
     *
     * @return an input stream that reads from this connection.
     * @throws IOException if an I/O error occurs while creating the input
     *         stream.
     */
    virtual std::shared_ptr<InputStream> getInputStream() = 0;

    /**
     * <p>Returns an output stream that writes to this connection.</p>
     *
     * <p>Asking for the output stream must not prevent use of the input
     * stream, but writing to the output stream may prevent further reading
     * from the input stream.</p>
     *
     * @return an output stream that writes to this connection.
     * @throws IOException if an I/O error occurs while creating the output
     *         stream.
     */
    virtual std::shared_ptr<OutputStream> getOutputStream() = 0;
};

}}} // namespace netflix::msl::io

#endif /* SRC_IO_URL_H_ */
