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
package kancolle.entityauth;

import com.netflix.msl.entityauth.EntityAuthenticationScheme;

/**
 * <p>KanColle entity authentication schemes.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KanColleEntityAuthenticationScheme extends EntityAuthenticationScheme {
    /** Kanmusu entity authentication scheme. */
    public static final EntityAuthenticationScheme KANMUSU = new KanColleEntityAuthenticationScheme("KANMUSU", true, true);
    /** Naval port entity authentication scheme. */
    public static final EntityAuthenticationScheme NAVAL_PORT = new KanColleEntityAuthenticationScheme("NAVAL_PORT", true, true);

    /**
     * Define a KanColle entity authentication scheme with the specified name.
     * 
     * @param name the entity authentication scheme name.
     * @param encrypts true if the scheme encrypts message data.
     * @param protects true if the scheme protects message integrity.
     */
    protected KanColleEntityAuthenticationScheme(final String name, final boolean encrypts, final boolean protects) {
        super(name, encrypts, protects);
    }
}
