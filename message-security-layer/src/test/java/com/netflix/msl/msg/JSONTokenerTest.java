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
package com.netflix.msl.msg;

import static org.junit.Assert.*;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.junit.Test;

/**
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class JSONTokenerTest {
    private static final String mobjs = "{ \"name1\" : \"firstobj\" } { \"name2\" : \"secondobj\" }";
    
    @Test
    public void multipleObjects() throws JSONException {
        final JSONTokener tokener = new JSONTokener(mobjs);
        
        assertTrue("No objects found", tokener.more());
        
        final Object first = tokener.nextValue();
        assertTrue("First object not JSONObject", first instanceof JSONObject);
        final JSONObject firstJo = (JSONObject)first;
        assertTrue("First object missing name", firstJo.has("name1"));
        assertEquals("firstobj", firstJo.getString("name1"));
        System.out.println(firstJo.toString());
        
        assertTrue("No more objects found", tokener.more());
        
        final Object second = tokener.nextValue();
        assertTrue("Second object not JSONObject", second instanceof JSONObject);
        final JSONObject secondJo = (JSONObject)second;
        assertTrue("Second object missing name", secondJo.has("name2"));
        assertEquals("secondobj", secondJo.getString("name2"));
        System.out.println(secondJo.toString());
    }
}
