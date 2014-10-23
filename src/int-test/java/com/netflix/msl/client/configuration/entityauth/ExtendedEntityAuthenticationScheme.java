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
package com.netflix.msl.client.configuration.entityauth;

import com.netflix.msl.entityauth.EntityAuthenticationScheme;

/**
 * User: skommidi
 * Date: 7/29/14
 */
public class ExtendedEntityAuthenticationScheme extends EntityAuthenticationScheme {
    /**
     * Define an entity authentication scheme with the specified name and
     * cryptographic properties.
     *
     * @param name     the entity authentication scheme name.
     * @param encrypts true if the scheme encrypts message data.
     * @param protects true if the scheme protects message integrity.
     */
    protected ExtendedEntityAuthenticationScheme(String name, boolean encrypts, boolean protects) {
        super(name, encrypts, protects);
    }
}
