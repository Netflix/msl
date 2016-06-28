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
package com.netflix.msl.util;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;

/**
 * JSON processing utility functions.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class JsonUtils {
    /** Encoding charset. */
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
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
        return JsonUtils.b64urlEncode(data);
        
    }
    /**
     * URL-safe Base64 encode data without padding characters.
     * 
     * @param data the value to Base64 encode.
     * @return the Base64 encoded data.
     */
    public static String b64urlEncode(final byte[] data) {
        // Perform a standard Base64 encode.
        final String padded = Base64.encode(data);
        
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
                return Base64.decode(modified);
            final StringBuilder padded = new StringBuilder(modified);
            for (int i = 0; i < toPad; ++i)
                padded.append(CHAR_EQUALS);
            return Base64.decode(padded.toString());
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
     * the accepted types: <code>Boolean</code>, <code>JSONArray</code>,
     * <code>JSONObject</code>, <code>Number</code>, <code>String</code>, or
     * the <code>JSONObject.NULL object</code> or turn any
     * <code>JSONString</code> into a <code>JSONObject</code>.
     * 
     * @param c a collection of JSON-compatible objects.
     * @throws JSONException if a <code>JSONString</code> cannot be encoded
     *         properly or an unsupported object is encountered.
     */
    @SuppressWarnings("rawtypes")
    public static JSONArray createArray(final Collection<?> c) throws JSONException {
        final JSONArray array = new JSONArray();
        for (final Object o : c) {
            if (o instanceof Boolean ||
                o instanceof JSONArray ||
                o instanceof JSONObject ||
                o instanceof Number ||
                o instanceof String ||
                o == JSONObject.NULL)
            {
                array.put(o);
            } else if (o instanceof JSONString) {
                final JSONString js = (JSONString)o;
                final JSONObject jo = new JSONObject(js.toJSONString());
                array.put(jo);
            } else if (o instanceof Enum) {
                array.put(((Enum)o).name());
            } else {
                throw new JSONException("Class " + o.getClass().getName() + " is not JSON-compatible.");
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
     * @see JsonUtils#equals(JSONObject, JSONObject)
     */
    public static boolean objectEquals(final String js1, final String js2) throws JSONException {
        final JSONObject o1 = new JSONObject(js1);
        final JSONObject o2 = new JSONObject(js2);
        return JsonUtils.equals(o1, o2);
    }
    
    /**
     * Performs a deep comparison of two JSON objects for equivalence. JSON
     * objects are equivalent if they have the same name/value pairs. Also, two
     * JSON object references are considered equal if both are null.
     * 
     * @param jo1 first JSON object.
     * @param jo2 second JSON object.
     * @return true if the JSON objects are equivalent.
     * @throws JSONException if there is an error parsing the JSON.
     */
    public static boolean equals(final JSONObject jo1, final JSONObject jo2) throws JSONException {
        // Equal if both null or the same object.
        if (jo1 == jo2)
            return true;
        // Not equal if only one of them is null.
        if (jo1 == null || jo2 == null)
            return false;
        
        // Check the children names. If there are no names, the JSON object is
        // empty.
        final String[] names1 = JSONObject.getNames(jo1);
        final String[] names2 = JSONObject.getNames(jo2);
        // Equal if both null or the same object.
        if (names1 == names2)
            return true;
        // Not equal if only one of them is null or of different length.
        if (names1 == null || names2 == null || names1.length != names2.length)
            return false;
        
        // Duplicate names are not allowed since that isn't valid JSON.
        final Set<String> namesSet1 = new HashSet<String>(Arrays.asList(names1));
        final Set<String> namesSet2 = new HashSet<String>(Arrays.asList(names2));
        if (namesSet1.size() != names1.length || namesSet1.size() != names2.length)
            return false;
        if (!namesSet1.equals(namesSet2))
            return false;
        
        // Bail on the first child element whose values are not equal.
        for (final String name : names1) {
            final Object o1 = jo1.get(name);
            final Object o2 = jo2.get(name);
            // Equal if both null or the same object.
            if (o1 == o2) continue;
            // Not equal if only one of them is null.
            if (o1 == null || o2 == null)
                return false;
            if (o1.getClass() != o2.getClass())
                return false;
            if (o1 instanceof JSONObject) {
                if (!JsonUtils.equals((JSONObject)o1, (JSONObject)o2))
                    return false;
            } else if (o1 instanceof JSONArray) {
                if (!JsonUtils.equals((JSONArray)o1, (JSONArray)o2))
                    return false;
            } else {
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
     * @throws JSONException if there is an error parsing the JSON.
     */
    public static boolean equals(final JSONArray ja1, final JSONArray ja2) throws JSONException {
        // Equal if both null or the same object.
        if (ja1 == ja2)
            return true;
        // Not equal if only one of them is null or of different length.
        if (ja1 == null || ja2 == null || ja1.length() != ja2.length())
            return false;
        
        // Bail on the first elements whose values are not equal.
        for (int i = 0; i < ja1.length(); ++i) {
            final Object o1 = ja1.get(i);
            final Object o2 = ja2.get(i);
            // Equal if both null or the same object.
            if (o1 == o2) continue;
            // Not equal if only one of them is null.
            if (o1 == null || o2 == null)
                return false;
            if (o1.getClass() != o2.getClass())
                return false;
            if (o1 instanceof JSONObject) {
                if (!JsonUtils.equals((JSONObject)o1, (JSONObject)o2))
                    return false;
            } else if (o1 instanceof JSONArray) {
                if (!JsonUtils.equals((JSONArray)o1, (JSONArray)o2))
                    return false;
            } else {
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
    public static boolean equalSets(final JSONArray ja1, final JSONArray ja2) throws JSONException {
        // Equal if both null or the same object.
        if (ja1 == ja2)
            return true;
        // Not equal if only one of them is null or of different length.
        if (ja1 == null || ja2 == null || ja1.length() != ja2.length())
            return false;
        
        // Compare as sets.
        final Set<Object> s1 = new HashSet<Object>();
        final Set<Object> s2 = new HashSet<Object>();
        for (int i = 0; i < ja1.length(); ++i) {
            s1.add(ja1.get(i));
            s2.add(ja2.get(i));
        }
        return s1.equals(s2);
    }
    
    /**
     * Merge two JSON objects into a single JSON object. If the same key is
     * found in both objects, the second object's value is used. The values are
     * copied by reference so this is a shallow copy.
     * 
     * @param jo1 first JSON object. May be null.
     * @param jo2 second JSON object. May be null.
     * @return the merged JSON object or null if both arguments are null.
     */
    public static JSONObject merge(final JSONObject jo1, final JSONObject jo2) {
        // Return null if both objects are null.
        if (jo1 == null && jo2 == null)
            return null;
        
        // Make a copy of the first object, or create an empty object.
        final JSONObject jo = (jo1 != null)
            ? new JSONObject(jo1, JSONObject.getNames(jo1))
            : new JSONObject();
        
        // If the second object is null, we're done and just return the copy.
        if (jo2 == null)
            return jo;
        
        // Copy the contents of the second object into the final object.
        for (final String key : JSONObject.getNames(jo2))
            jo.put(key, jo2.get(key));
        return jo;
    }
}
