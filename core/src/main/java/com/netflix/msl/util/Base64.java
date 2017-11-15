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

import java.util.regex.Pattern;

/**
 * <p>Base64 encoder/decoder. Can be configured with a backing
 * implementation.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class Base64 {
    /** Whitespace regular expression. */
    private static final String WHITESPACE_REGEX = "\\s";
    /** Base64 validation regular expression. */
    private static final Pattern BASE64_PATTERN = Pattern.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$");

    /**
     * <p>Validates that a string is a valid Base64 encoding. This uses a
     * regular expression to perform the check. The empty string is also
     * considered valid. All whitespace is ignored.</p>
     *
     * @param s the string to validate.
     * @return true if the string is a valid Base64 encoding.
     */
    public static boolean isValidBase64(final String s) {
        final String sanitized = s.replaceAll(WHITESPACE_REGEX, "");
        return BASE64_PATTERN.matcher(sanitized).matches();
    }

    /**
     * <p>A Base64 encoder/decoder implementation. Implementations must be
     * thread-safe.</p>
     */
    public static interface Base64Impl {
        /**
         * <p>Base64 encodes binary data.</p>
         *
         * @param b the binary data.
         * @return the Base64-encoded binary data.
         */
        public String encode(final byte[] b);

        /**
         * <p>Decodes a Base64-encoded string into its binary form.</p>
         *
         * @param s the Base64-encoded string.
         * @return the binary data.
         * @throws IllegalArgumentException if the argument is not a valid
         *         Base64-encoded string. The empty string is considered valid.
         * @see Base64#isValidBase64(String)
         */
        public byte[] decode(final String s);
    }

    /**
     * Set the backing implementation.
     *
     * @param impl the backing implementation.
     * @throws NullPointerException if the implementation is {@code null}.
     */
    public static void setImpl(final Base64Impl impl) {
        if (impl == null)
            throw new NullPointerException("Base64 implementation cannot be null.");
        Base64.impl = impl;
    }

    /**
     * <p>Base64 encodes binary data.</p>
     *
     * @param b the binary data.
     * @return the Base64-encoded binary data.
     */
    public static String encode(final byte[] b) {
        return impl.encode(b);
    }

    /**
     * <p>Decodes a Base64-encoded string into its binary form.</p>
     *
     * @param s the Base64-encoded string.
     * @return the binary data.
     * @throws IllegalArgumentException if the argument is not a valid Base64-
     *         encoded string.
     */
    public static byte[] decode(final String s) {
        // Delegate validation of the argument to the implementation.
        return impl.decode(s);
    }

    /** The backing implementation. */
    private static Base64Impl impl = new Base64Secure();
}
