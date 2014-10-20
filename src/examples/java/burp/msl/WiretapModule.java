package burp.msl;

import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.inject.name.Named;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.entityauth.MockRsaAuthenticationFactory;
import com.netflix.msl.entityauth.MockX509AuthenticationFactory;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationFactory;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MockAuthenticationUtils;

import java.util.HashSet;
import java.util.Set;

/**
 * User: skommidi
 * Date: 9/22/14
 */
public class WiretapModule extends AbstractModule {
    @Override
    protected void configure() {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    @Provides @Named("MslContextEntityAuthFactories")
    Set<EntityAuthenticationFactory> provideEntityAuthFactories() {
        final AuthenticationUtils authutils = new MockAuthenticationUtils();

        final Set<EntityAuthenticationFactory> factories = new HashSet<EntityAuthenticationFactory>();
        factories.add(new UnauthenticatedAuthenticationFactory(authutils));
        factories.add(new MockPresharedAuthenticationFactory());
        factories.add(new MockRsaAuthenticationFactory());
        factories.add(new MockX509AuthenticationFactory());
        return factories;
    }

    @Provides @Named("MslContextUserAuthFactories")
    Set<UserAuthenticationFactory> userAuthFactories() {
        final Set<UserAuthenticationFactory> factories = new HashSet<UserAuthenticationFactory>();
        factories.add(new MockEmailPasswordAuthenticationFactory());
        return factories;
    }
}
