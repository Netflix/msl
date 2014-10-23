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
