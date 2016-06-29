/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.util;

import javax.xml.bind.DatatypeConverter;

import com.netflix.msl.util.Base64.Base64Impl;

/**
 * <p>Base64 encoder/decoder implementation that uses the JAXB {@link DatatypeConverter}
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class Base64Jaxb implements Base64Impl {
    /* (non-Javadoc)
     * @see com.netflix.msl.util.Base64.Base64Impl#encode(byte[])
     */
    @Override
    public String encode(final byte[] b) {
        return DatatypeConverter.printBase64Binary(b);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.Base64.Base64Impl#decode(java.lang.String)
     */
    @Override
    public byte[] decode(final String s) {
        if (!Base64.isValidBase64(s))
            throw new IllegalArgumentException("Invalid Base64 encoded string: " + s);
        return DatatypeConverter.parseBase64Binary(s);
    }
}
