/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;

import org.json.JSONException;

import com.netflix.msl.util.MslContext;

/**
 * MSL encoder utility functions.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslEncoderUtils {
    /** Encoding charset. */
    private static final Charset UTF_8 = Charset.forName("UTF-8");
    /** Base64 characters. */
    private static final char CHAR_PLUS = '+';
    private static final char CHAR_MINUS = '-';
    private static final char CHAR_SLASH = '/';
    private static final char CHAR_UNDERSCORE = '_';
    private static final char CHAR_EQUALS = '=';
    
    /**
     * URL-safe Base64 encode data as UTF-8 without padding characters.
     * 
     * @param s the value to Base64 encode.
     * @return the Base64 encoded data.
     */
    public static String b64urlEncode(final String s) {
        final byte[] data = s.getBytes(UTF_8);
        return MslEncoderUtils.b64urlEncode(data);
        
    }
    /**
     * URL-safe Base64 encode data without padding characters.
     * 
     * @param data the value to Base64 encode.
     * @return the Base64 encoded data.
     */
    public static String b64urlEncode(final byte[] data) {
        // Perform a standard Base64 encode.
        final String padded = DatatypeConverter.printBase64Binary(data);
        
        // Replace standard characters with URL-safe characters.
        final String modified = padded.replace(CHAR_PLUS, CHAR_MINUS).replace(CHAR_SLASH, CHAR_UNDERSCORE);

        // Remove padding.
        final int padIndex = modified.indexOf(CHAR_EQUALS);
        return (padIndex != -1) ? modified.substring(0, padIndex) : modified;
    }
    
    /**
     * URL-safe Base64 decode data that has no padding characters.
     * 
     * @param data the Base64 encoded data.
     * @return the decoded data or {@code null} if there is an error decoding.
     */
    public static byte[] b64urlDecode(final String data) {
        // Replace URL-safe characters with standard characters.
        final String modified = data.replace(CHAR_MINUS, CHAR_PLUS).replace(CHAR_UNDERSCORE, CHAR_SLASH);

        // Pad if necessary, then decode.
        try {
            final int toPad = 4 - (modified.length() % 4);
            if (toPad == 0 || toPad == 4)
                return DatatypeConverter.parseBase64Binary(modified);
            final StringBuilder padded = new StringBuilder(modified);
            for (int i = 0; i < toPad; ++i)
                padded.append(CHAR_EQUALS);
            return DatatypeConverter.parseBase64Binary(padded.toString());
        } catch (final IllegalArgumentException e) {
            return null;
        }
    }
    
    /**
     * URL-safe Base64 decode data as UTF-8 that has no padding characters. 
     * 
     * @param data the Base64 encoded data.
     * @return the decoded data as a UTF-8 string.
     */
    public static String b64urlDecodeToString(final String data) {
        return new String(b64urlDecode(data), UTF_8);
    }
    
    /**
     * Create a JSON array from a collection of objects that are either one of
     * the accepted types: <code>Boolean</code>, <code>Byte[]</code>,
     * <code>JSONArray</code>, <code>MslObject</code>, <code>Number</code>,
     * <code>String</code>, or the <code>MslObject.NULL object</code> or turn
     * any <code>JSONString</code> into a <code>MslObject</code>.
     * 
     * @param c a collection of JSON-compatible objects.
     * @throws JSONException if a <code>JSONString</code> cannot be encoded
     *         properly or an unsupported object is encountered.
     */
//    @SuppressWarnings("rawtypes")
//    public static JSONArray createArray(final Collection<?> c) throws JSONException {
//        final JSONArray array = new JSONArray();
//        for (final Object o : c) {
//            if (o instanceof Boolean ||
//                o instanceof JSONArray ||
//                o instanceof MslObject ||
//                o instanceof Number ||
//                o instanceof String ||
//                o == MslObject.NULL)
//            {
//                array.put(o);
//            } else if (o instanceof JSONString) {
//                final JSONString js = (JSONString)o;
//                final MslObject mo = encoder.toObject(js);
//                array.put(mo);
//            } else if (o instanceof Enum) {
//                array.put(((Enum)o).name());
//            } else {
//                throw new JSONException("Class " + o.getClass().getName() + " is not JSON-compatible.");
//            }
//        }
//        return array;
//    }
    
    /**
     * Create a MSL array from a collection of objects that are either one of
     * the accepted types: <code>Boolean</code>, <code>Byte[]</code>,
     * <code>MslArray</code>, <code>MslObject</code>, <code>Number</code>,
     * <code>String</code>, <code>null</code>, or turn any
     * <code>MslEncodable</code> into a <code>MslObject</code>.
     * 
     * @param c a collection of MSL encoding-compatible objects.
     * @throws MslEncoderException if a <code>MslEncodable</code> cannot be
     *         encoded properly or an unsupported object is encountered.
     */
    public static MslArray createArray(final MslContext ctx, final Collection<?> c) throws MslEncoderException {
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        final MslArray array = encoder.createArray();
        for (final Object o : c) {
            if (o instanceof byte[] ||
                o instanceof Boolean ||
                o instanceof MslArray ||
                o instanceof MslObject ||
                o instanceof Number ||
                o instanceof String ||
                o == null)
            {
                array.put(-1, o);
            } else if (o instanceof MslEncodable) {
                final MslEncodable me = (MslEncodable)o;
                final byte[] encode = me.toMslEncoding(encoder, MslEncoderFormat.JSON);
                final MslObject mo = encoder.parseObject(encode);
                array.put(-1, mo);
            } else if (o instanceof Enum) {
                array.put(-1, ((Enum<?>)o).name());
            } else {
                throw new MslEncoderException("Class " + o.getClass().getName() + " is not MSL encoding-compatible.");
            }
        }
        return array;
    }
    
    /**
     * Performs a deep comparison of two JSON objects.
     * 
     * @param js1 first JSON object string representation.
     * @param js2 second JSON object string representation.
     * @return true if the strings are equivalent JSON objects or arrays.
     * @throws JSONException if there is an error parsing the JSON.
     * @see JsonUtils#equals(MslObject, MslObject)
     */
//    public static boolean objectEquals(final String js1, final String js2) throws JSONException {
//        final MslObject o1 = new MslObject(js1);
//        final MslObject o2 = new MslObject(js2);
//        return JsonUtils.equals(o1, o2);
//    }
    
    /**
     * Performs a deep comparison of two MSL objects.
     * 
     * @param ctx MSL context.
     * @param me1 first MSL object encoded representation.
     * @param me2 second JSON object encoded representation.
     * @return true if the encodings are equivalent MSL objects.
     * @throws MslEncoderException if there is an error parsing the data.
     * @see MslEncoderUtils#equals(MslObject, MslObject)
     */
    public static boolean objectEquals(final MslContext ctx, final byte[] me1, final byte[] me2) throws MslEncoderException {
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        final MslObject o1 = encoder.parseObject(me1);
        final MslObject o2 = encoder.parseObject(me2);
        return MslEncoderUtils.equals(o1, o2);
    }
    
    /**
     * Performs a deep comparison of two JSON objects for equivalence. JSON
     * objects are equivalent if they have the same name/value pairs. Also, two
     * JSON object references are considered equal if both are null.
     * 
     * @param mo1 first JSON object.
     * @param mo2 second JSON object.
     * @return true if the JSON objects are equivalent.
     * @throws JSONException if there is an error parsing the JSON.
     */
//    public static boolean equals(final MslObject mo1, final MslObject mo2) throws JSONException {
//        // Equal if both null or the same object.
//        if (mo1 == mo2)
//            return true;
//        // Not equal if only one of them is null.
//        if (mo1 == null || mo2 == null)
//            return false;
//        
//        // Check the children names. If there are no names, the JSON object is
//        // empty.
//        final String[] names1 = MslObject.getNames(mo1);
//        final String[] names2 = MslObject.getNames(mo2);
//        // Equal if both null or the same object.
//        if (names1 == names2)
//            return true;
//        // Not equal if only one of them is null or of different length.
//        if (names1 == null || names2 == null || names1.length != names2.length)
//            return false;
//        
//        // Duplicate names are not allowed since that isn't valid JSON.
//        final Set<String> namesSet1 = new HashSet<String>(Arrays.asList(names1));
//        final Set<String> namesSet2 = new HashSet<String>(Arrays.asList(names2));
//        if (namesSet1.size() != names1.length || namesSet1.size() != names2.length)
//            return false;
//        if (!namesSet1.equals(namesSet2))
//            return false;
//        
//        // Bail on the first child element whose values are not equal.
//        for (final String name : names1) {
//            final Object o1 = mo1.get(name);
//            final Object o2 = mo2.get(name);
//            // Equal if both null or the same object.
//            if (o1 == o2) continue;
//            // Not equal if only one of them is null.
//            if (o1 == null || o2 == null)
//                return false;
//            if (o1.getClass() != o2.getClass())
//                return false;
//            if (o1 instanceof MslObject) {
//                if (!JsonUtils.equals((MslObject)o1, (MslObject)o2))
//                    return false;
//            } else if (o1 instanceof JSONArray) {
//                if (!JsonUtils.equals((JSONArray)o1, (JSONArray)o2))
//                    return false;
//            } else {
//                if (!o1.equals(o2))
//                    return false;
//            }
//        }
//        
//        // All name/value pairs are equal.
//        return true;
//    }
    
    /**
     * Performs a deep comparison of two MSL objects for equivalence. MSL
     * objects are equivalent if they have the same name/value pairs. Also, two
     * MSL object references are considered equal if both are null.
     * 
     * @param mo1 first MSL object.
     * @param mo2 second MSL object.
     * @return true if the MSL objects are equivalent.
     * @throws MslEncoderException if there is an error parsing the data.
     */
    public static boolean equals(final MslObject mo1, final MslObject mo2) throws MslEncoderException {
        // Equal if both null or the same object.
        if (mo1 == mo2)
            return true;
        // Not equal if only one of them is null.
        if (mo1 == null || mo2 == null)
            return false;
        
        // Check the children names. If there are no names, the MSL object is
        // empty.
        final Set<String> names1 = mo1.getKeys();
        final Set<String> names2 = mo2.getKeys();
        // Equal if both null or the same object.
        if (names1 == names2)
            return true;
        // Not equal if only one of them is null or of different length.
        if (names1 == null || names2 == null || names1.size() != names2.size())
            return false;
        // Not equal if the sets are not equal
        if (!names1.equals(names2))
            return false;
        
        // Bail on the first child element whose values are not equal.
        for (final String name : names1) {
            final Object o1 = mo1.get(name);
            final Object o2 = mo2.get(name);
            // Equal if both null or the same object.
            if (o1 == o2) continue;
            // Not equal if only one of them is null.
            if (o1 == null || o2 == null)
                return false;
            // byte[] may be represented differently, so we have to compare by
            // accessing directly. This isn't perfect but works for now.
            if (o1 instanceof byte[] || o2 instanceof byte[]) {
                final byte[] b1 = mo1.getBytes(name);
                final byte[] b2 = mo2.getBytes(name);
                if (!Arrays.equals(b1, b2))
                    return false;
            } else if (o1 instanceof MslObject && o2 instanceof MslObject) {
                if (!MslEncoderUtils.equals((MslObject)o1, (MslObject)o2))
                    return false;
            } else if (o1 instanceof MslArray && o2 instanceof MslArray) {
                if (!MslEncoderUtils.equals((MslArray)o1, (MslArray)o2))
                    return false;
            } else {
                if (o1.getClass() != o2.getClass())
                    return false;
                if (!o1.equals(o2))
                    return false;
            }
        }
        
        // All name/value pairs are equal.
        return true;
    }
    
    /**
     * Performs a deep comparison of two JSON arrays for equality. Two JSON
     * arrays are considered equal if both arrays contain the same number of
     * elements, and all corresponding pairs of elements in the two arrays are
     * equal. In other words, two JSON arrays are equal if they contain the
     * same elements in the same order. Also, two JSON array references are
     * considered equal if both are null.
     * 
     * @param ja1 first JSON array. May be null.
     * @param ja2 second JSON array. May be null.
     * @return true if the JSON arrays are equal.
     * @throws MslEncoderException if there is an error parsing the data.
     */
//    public static boolean equals(final JSONArray ja1, final JSONArray ja2) throws JSONException {
//        // Equal if both null or the same object.
//        if (ja1 == ja2)
//            return true;
//        // Not equal if only one of them is null or of different length.
//        if (ja1 == null || ja2 == null || ja1.length() != ja2.length())
//            return false;
//        
//        // Bail on the first elements whose values are not equal.
//        for (int i = 0; i < ja1.length(); ++i) {
//            final Object o1 = ja1.get(i);
//            final Object o2 = ja2.get(i);
//            // Equal if both null or the same object.
//            if (o1 == o2) continue;
//            // Not equal if only one of them is null.
//            if (o1 == null || o2 == null)
//                return false;
//            if (o1.getClass() != o2.getClass())
//                return false;
//            if (o1 instanceof MslObject) {
//                if (!JsonUtils.equals((MslObject)o1, (MslObject)o2))
//                    return false;
//            } else if (o1 instanceof JSONArray) {
//                if (!JsonUtils.equals((JSONArray)o1, (JSONArray)o2))
//                    return false;
//            } else {
//                if (!o1.equals(o2))
//                    return false;
//            }
//        }
//        
//        // All values are equal.
//        return true;
//    }
    
    /**
     * Performs a deep comparison of two MSL arrays for equality. Two MSL
     * arrays are considered equal if both arrays contain the same number of
     * elements, and all corresponding pairs of elements in the two arrays are
     * equal. In other words, two MSL arrays are equal if they contain the
     * same elements in the same order. Also, two MSL array references are
     * considered equal if both are null.
     * 
     * @param ja1 first MSL array. May be null.
     * @param ja2 second MSL array. May be null.
     * @return true if the MSL arrays are equal.
     * @throws JSONException if there is an error parsing the MSL.
     */
    public static boolean equals(final MslArray ma1, final MslArray ma2) throws MslEncoderException {
        // Equal if both null or the same object.
        if (ma1 == ma2)
            return true;
        // Not equal if only one of them is null or of different length.
        if (ma1 == null || ma2 == null || ma1.size() != ma2.size())
            return false;
        
        // Bail on the first elements whose values are not equal.
        for (int i = 0; i < ma1.size(); ++i) {
            final Object o1 = ma1.opt(i);
            final Object o2 = ma2.opt(i);
            // Equal if both null or the same object.
            if (o1 == o2) continue;
            // Not equal if only one of them is null.
            if (o1 == null || o2 == null)
                return false;
            // byte[] may be represented differently, so we have to compare by
            // accessing directly. This isn't perfect but works for now.
            if (o1 instanceof byte[] || o2 instanceof byte[]) {
                final byte[] b1 = ma1.getBytes(i);
                final byte[] b2 = ma2.getBytes(i);
                if (!Arrays.equals(b1, b2))
                    return false;
            } else if (o1 instanceof MslObject && o2 instanceof MslObject) {
                if (!MslEncoderUtils.equals((MslObject)o1, (MslObject)o2))
                    return false;
            } else if (o1 instanceof MslArray && o2 instanceof MslArray) {
                if (!MslEncoderUtils.equals((MslArray)o1, (MslArray)o2))
                    return false;
            } else {
                if (o1.getClass() != o2.getClass())
                    return false;
                if (!o1.equals(o2))
                    return false;
            }
        }
        
        // All values are equal.
        return true;
    }

    /**
     * Performs a shallow comparison of two JSON arrays for set equality. Two
     * JSON arrays are considered set-equal if both arrays contain the same
     * number of elements and all elements found in one array are also found in
     * the other. In other words, two JSON arrays are set-equal if they contain
     * the same elements in the any order. Also, two JSON array references are
     * considered set-equal if both are null.
     * 
     * @param ja1 first JSON array. May be null.
     * @param ja2 second JSON array. May be null.
     * @return true if the JSON arrays are set-equal.
     * @throws JSONException if there is an error parsing the JSON.
     */
//    public static boolean equalSets(final JSONArray ja1, final JSONArray ja2) throws JSONException {
//        // Equal if both null or the same object.
//        if (ja1 == ja2)
//            return true;
//        // Not equal if only one of them is null or of different length.
//        if (ja1 == null || ja2 == null || ja1.length() != ja2.length())
//            return false;
//        
//        // Compare as sets.
//        final Set<Object> s1 = new HashSet<Object>();
//        final Set<Object> s2 = new HashSet<Object>();
//        for (int i = 0; i < ja1.length(); ++i) {
//            s1.add(ja1.get(i));
//            s2.add(ja2.get(i));
//        }
//        return s1.equals(s2);
//    }
    
    /**
     * Performs a shallow comparison of two MSL arrays for set equality. Two
     * MSL arrays are considered set-equal if both arrays contain the same
     * number of elements and all elements found in one array are also found in
     * the other. In other words, two MSL arrays are set-equal if they contain
     * the same elements in the any order. Also, two MSL array references are
     * considered set-equal if both are null.
     * 
     * @param ja1 first MSL array. May be {@code null}.
     * @param ja2 second MSL array. May be {@code null}.
     * @return true if the MSL arrays are set-equal.
     * @throws MslEncoderException if there is an error parsing the data.
     */
    public static boolean equalSets(final MslArray ma1, final MslArray ma2) throws MslEncoderException {
        // Equal if both null or the same object.
        if (ma1 == ma2)
            return true;
        // Not equal if only one of them is null or of different length.
        if (ma1 == null || ma2 == null || ma1.size() != ma2.size())
            return false;
        
        // Compare as sets.
        final Set<Object> s1 = new HashSet<Object>();
        final Set<Object> s2 = new HashSet<Object>();
        for (int i = 0; i < ma1.size(); ++i) {
            s1.add(ma1.opt(i));
            s2.add(ma2.opt(i));
        }
        return s1.equals(s2);
    }
}
