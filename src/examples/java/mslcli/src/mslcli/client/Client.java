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

package mslcli.client;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;

import mslcli.client.msg.ClientRequestMessageContext;
import mslcli.client.util.ClientMslContext;

import mslcli.common.util.SharedUtil;

import static mslcli.common.Constants.*;

public final class Client {
    // Add BouncyCastle provider.
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Specify remote URL");
            System.exit(1);
        }
        final URL remoteUrl = new URL(args[0]);

        final Client client = new Client();
        String msg;
        while (!"quit".equalsIgnoreCase(msg = SharedUtil.readInput())) {
            final byte[] response = client.sendRequest(msg.getBytes(), remoteUrl);
            System.out.println("\nResponse: " + new String(response));
        }
    }

    public Client() {
        // Create the MSL control.
        //
        // Since this is an example process all requests on the calling thread.
        this.mslCtrl = new MslControl(0);
        this.mslCtrl.setFilterFactory(new ConsoleFilterStreamFactory());

        /* Initialize MSL store.
         */
        final MslStore mslStore = SharedUtil.getClientMslStore();

        // Create the pre-shared key store.
        final PresharedKeyStore presharedKeyStore = SharedUtil.getPresharedKeyStore();

        // Create the RSA key store
        final RsaStore rsaStore = SharedUtil.getRsaStore();

        // Create the email/password store.
        final EmailPasswordStore emailPasswordStore = SharedUtil.getEmailPasswordStore();

        // Set up the MSL context
        this.mslCtx = new ClientMslContext(CLIENT_ID, presharedKeyStore, rsaStore, emailPasswordStore, mslStore);

        // Initialize UserAuthenticationData
        this.userAuthData = new EmailPasswordAuthenticationData(CLIENT_USER_EMAIL, CLIENT_USER_PASSWORD);
    }

    public byte[] sendRequest(byte[] request, URL remoteUrl) throws ExecutionException, IOException, InterruptedException {
        final boolean isEncrypted = true;
        final boolean isIntegrityProtected = true;
        final boolean isNonReplayable = false;
        final Set<KeyRequestData> keyRequestDataSet = new HashSet<KeyRequestData>();
        keyRequestDataSet.add(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK));

        final MessageContext msgCtx = new ClientRequestMessageContext(
            mslCtx,
            isEncrypted,
            isIntegrityProtected,
            isNonReplayable,
            CLIENT_USER_ID,
            userAuthData,
            keyRequestDataSet,
            request
            );

        final Future<MslChannel> f = mslCtrl.request(mslCtx, msgCtx, remoteUrl, TIMEOUT_MS);
        final MslChannel ch;
        ch = f.get();
        if (ch == null)
            return null;

        return SharedUtil.readIntoArray(ch.input);
    }

    /** MSL context */
    private final MslContext mslCtx;
    /** MSL control */
    private final MslControl mslCtrl;
    /** User Authentication Data */
    private final UserAuthenticationData userAuthData;
}
