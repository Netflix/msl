/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.msg;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * A filter stream factory provides filter input stream and filter output
 * stream instances.
 * 
 * Implementations must be thread-safe.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface FilterStreamFactory {
    /**
     * Return a new input stream that has the provided input stream as its
     * backing source. If no filtering is desired then the original input
     * stream must be returned.
     * 
     * @param in the input stream to wrap.
     * @return a new filter input stream backed by the provided input stream or
     *         the original input stream..
     */
    public InputStream getInputStream(final InputStream in);
    
    /**
     * Return a new output stream that has the provided output stream as its
     * backing destination. If no filtering is desired then the original output
     * stream must be returned.
     * 
     * @param out the output stream to wrap.
     * @return a new filter output stream backed by the provided output stream
     *         or the original output stream.
     */
    public OutputStream getOutputStream(final OutputStream out);
}
