/**
 * Copyright (c) 2015-2018 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.util.Base64;

/**
 * <p>An abstract factory class for producing {@link MslTokenizer},
 * {@link MslObject}, and {@link MslArray} instances of various encoder
 * formats.</p>
 *
 * <p>A concrete implementations must identify its supported and preferred
 * encoder formats and provide implementations for encoding and decoding those
 * formats.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class MslEncoderFactory {
    /**
     * <p>Escape and quote a string for print purposes.</p>
     *
     * <p>This is based on the org.json {@code MslObject.quote()} code.</p>
     *
     * @param string the string to quote. May be {@code null}.
     * @return the quoted string.
     */
    static String quote(final String string) {
        final StringBuilder sb = new StringBuilder();

        // Return "" for null or zero-length string.
        if (string == null || string.length() == 0) {
            sb.append("\"\"");
            return sb.toString();
        }

        char c = 0;
        final int len = string.length();

        sb.append('"');
        for (int i = 0; i < len; i += 1) {
            final char b = c;
            c = string.charAt(i);
            switch (c) {
                case '\\':
                case '"':
                    sb.append('\\');
                    sb.append(c);
                    break;
                case '/':
                    if (b == '<') {
                        sb.append('\\');
                    }
                    sb.append(c);
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                default:
                    if (c < ' ' || (c >= '\u0080' && c < '\u00a0')
                        || (c >= '\u2000' && c < '\u2100'))
                    {
                        sb.append("\\u");
                        final String hhhh = Integer.toHexString(c);
                        sb.append("0000", 0, 4 - hhhh.length());
                        sb.append(hhhh);
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /**
     * <p>Convert a value to a string for print purposes.</p>
     *
     * <p>This is based on the org.json {@code MslObject.writeValue()} code.</p>
     *
     * @param value the value to convert to a string. May be {@code null}.
     * @return the string.
     */
    @SuppressWarnings("unchecked")
    static String stringify(final Object value) {
        if (value == null || value.equals(null)) {
            return "null";
        } else if (value instanceof MslObject || value instanceof MslArray) {
            return value.toString();
        } else if (value instanceof Map) {
            return new MslObject((Map<?,?>)value).toString();
        } else if (value instanceof Collection) {
            return new MslArray((Collection<Object>)value).toString();
        } else if (value instanceof Object[]) {
            return new MslArray((Object[])value).toString();
        } else if (value instanceof Number || value instanceof Boolean) {
            return value.toString();
        } else if (value instanceof byte[]) {
            return Base64.encode((byte[])value);
        } else {
            return quote(value.toString());
        }
    }

    /**
     * Returns the most preferred encoder format from the provided set of
     * formats.
     *
     * @param formats the set of formats to choose from. May be {@code null} or
     *        empty.
     * @return the preferred format from the provided set or the default format
     *         if format set is {@code null} or empty.
     */
    public abstract MslEncoderFormat getPreferredFormat(final Set<MslEncoderFormat> formats);

    /**
     * Create a new {@link MslTokenizer}. The encoder format will be
     * determined by inspecting the byte stream identifier located in the first
     * byte.
     *
     * @param source the binary data to tokenize.
     * @return the {@link MslTokenizer}.
     * @throws IOException if there is a problem reading the byte stream
     *         identifier.
     * @throws MslEncoderException if the encoder format is not recognized or
     *         is not supported.
     */
    public MslTokenizer createTokenizer(final InputStream source) throws IOException, MslEncoderException {
        // Read the byte stream identifier (and only the identifier).
        final InputStream bufferedSource = source.markSupported() ? source : new UnsynchronizedBufferedInputStream(source);
        bufferedSource.mark(1);
        final byte id = (byte)bufferedSource.read();
        if (id == -1)
            throw new MslEncoderException("End of stream reached when attempting to read the byte stream identifier.");

        // Identify the encoder format.
        final MslEncoderFormat format = MslEncoderFormat.getFormat(id);
        if (format == null)
            throw new MslEncoderException("Unidentified encoder format ID: (byte)" + id + ".");

        // Reset the input stream and return the tokenizer.
        bufferedSource.reset();
        return generateTokenizer(bufferedSource, format);
    }

    /**
     * Create a new {@link MslTokenizer} of the specified encoder format.
     *
     * @param source the binary data to tokenize.
     * @param format the encoder format.
     * @return the {@link MslTokenizer}.
     * @throws MslEncoderException if the encoder format is not supported.
     */
    protected abstract MslTokenizer generateTokenizer(final InputStream source, final MslEncoderFormat format) throws MslEncoderException;

    /**
     * Create a new {@link MslObject}.
     *
     * @return the {@link MslObject}.
     */
    public MslObject createObject() {
        return createObject(null);
    }

    /**
     * Create a new {@link MslObject} populated with the provided map.
     *
     * @param map the map of name/value pairs. This must be a map of
     *        {@code String}s onto {@code Object}s. May be {@code null}.
     * @return the {@link MslObject}.
     * @throws IllegalArgumentException if one of the values is of an
     *         unsupported type.
     */
    public MslObject createObject(final Map<String,Object> map) {
        return new MslObject(map);
    }

    /**
     * Identify the encoder format of the {@link MslObject} of the encoded
     * data. The format will be identified by inspecting the byte stream
     * identifier located in the first byte.
     *
     * @param encoding the encoded data.
     * @return the encoder format.
     * @throws MslEncoderException if the encoder format cannot be identified
     *         or there is an error parsing the encoder format ID.
     */
    public MslEncoderFormat parseFormat(final byte[] encoding) throws MslEncoderException {
        // Fail if the encoding is too short.
        if (encoding.length < 1)
            throw new MslEncoderException("No encoding identifier found.");

        // Identify the encoder format.
        final byte id = encoding[0];
        final MslEncoderFormat format = MslEncoderFormat.getFormat(id);
        if (format == null)
            throw new MslEncoderException("Unidentified encoder format ID: (byte)" + id + ".");
        return format;
    }

    /**
     * Parse a {@link MslObject} from encoded data. The encoder format will be
     * determined by inspecting the byte stream identifier located in the first
     * byte.
     *
     * @param encoding the encoded data to parse.
     * @return the {@link MslObject}.
     * @throws MslEncoderException if the encoder format is not supported or
     *         there is an error parsing the encoded data.
     */
    public abstract MslObject parseObject(final byte[] encoding) throws MslEncoderException;

    /**
     * Encode a {@link MslObject} into the specified encoder format.
     *
     * @param object the {@link MslObject} to encode.
     * @param format the encoder format.
     * @return the encoded data.
     * @throws MslEncoderException if the encoder format is not supported or
     *         there is an error encoding the object.
     */
    public abstract byte[] encodeObject(final MslObject object, final MslEncoderFormat format) throws MslEncoderException;

    /**
     * Create a new {@link MslArray}.
     *
     * @return the {@link MslArray}.
     */
    public MslArray createArray() {
        return createArray(null);
    }

    /**
     * Create a new {@link MslArray} populated with the provided values.
     *
     * @param collection the collection of values. May be {@code null}.
     * @return the {@link MslArray}.
     * @throws IllegalArgumentException if one of the values is of an
     *         unsupported type.
     */
    public MslArray createArray(final Collection<?> collection) {
        return new MslArray(collection);
    }
}
