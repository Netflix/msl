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
package kancolle.userauth;

import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * <p>KanColle user authentication schemes.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KanColleUserAuthenticationScheme extends UserAuthenticationScheme {
    /** Officer entity authentication scheme. */
    public static final UserAuthenticationScheme OFFICER = new KanColleUserAuthenticationScheme("OFFICER");
    
    /**
     * Define a KanColle user authentication scheme with the specified name.
     * 
     * @param name the user authentication scheme name.
     */
    protected KanColleUserAuthenticationScheme(final String name) {
        super(name);
    }
}
