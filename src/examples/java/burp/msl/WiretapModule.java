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
package burp.msl;

import java.util.HashSet;
import java.util.Set;

import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.entityauth.MockRsaAuthenticationFactory;
import com.netflix.msl.entityauth.MockX509AuthenticationFactory;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationFactory;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MockAuthenticationUtils;

/**
 * User: skommidi
 * Date: 9/22/14
 */
public class WiretapModule {
    public Set<EntityAuthenticationFactory> provideEntityAuthFactories() {
        final AuthenticationUtils authutils = new MockAuthenticationUtils();

        final Set<EntityAuthenticationFactory> factories = new HashSet<EntityAuthenticationFactory>();
        factories.add(new UnauthenticatedAuthenticationFactory(authutils));
        factories.add(new MockPresharedAuthenticationFactory());
        factories.add(new MockRsaAuthenticationFactory());
        factories.add(new MockX509AuthenticationFactory());
        return factories;
    }

    public Set<UserAuthenticationFactory> provideUserAuthFactories() {
        final Set<UserAuthenticationFactory> factories = new HashSet<UserAuthenticationFactory>();
        factories.add(new MockEmailPasswordAuthenticationFactory());
        return factories;
    }
}
