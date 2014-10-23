/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.client.configuration.keyx;

import com.netflix.msl.keyx.KeyExchangeScheme;

/**
 * User: skommidi
 * Date: 9/2/14
 */
public class TestKeyExchangeScheme extends KeyExchangeScheme {

    public static final KeyExchangeScheme NULL_KEYX_SCHEME = new TestKeyExchangeScheme("NULL_KEYX_SCHEME");

    /**
     * Define a key exchange scheme with the specified name.
     *
     * @param name the key exchange scheme name.
     */
    protected TestKeyExchangeScheme(String name) {
        super(name);
    }
}
