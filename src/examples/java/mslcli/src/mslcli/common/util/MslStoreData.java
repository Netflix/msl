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

package mslcli.common.util;

import org.json.*;

import java.io.*;
import java.lang.reflect.*;
import java.util.*;

import javax.crypto.SecretKey;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.tokens.ServiceToken;

import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.SimpleMslStore;

/**
 * <p>The class for serializing SImpleMslStore. Because of using reflection, this code must keep in-sync with SimpleMslStore changes</p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class MslStoreData implements Serializable {

    /**
     * Create serializable MslStoreData from non-serializable MslStore, assuming it's SimpleMslStore
     * @param MslStore  SimpleMslStore instance
     */
    @SuppressWarnings("unchecked")
    private MslStoreData(final SimpleMslStore mslStore) {
        if (mslStore == null)
            throw new IllegalArgumentException("NULL MslStore");

        // extract all master tokens with crypto contexts
        final Map<MasterToken,ICryptoContext> cryptoContexts = (Map<MasterToken,ICryptoContext>)getFieldValue(mslStore, "cryptoContexts");
        for (Map.Entry<MasterToken,ICryptoContext> e : cryptoContexts.entrySet()) {
            this.cryptoContextData.put(new MasterTokenData(e.getKey()), new CryptoContextData(e.getValue()));
        }

        // extract all user id tokens
        final Map<String,UserIdToken> userIdTokens = new HashMap<String,UserIdToken>((Map<String,UserIdToken>)getFieldValue(mslStore, "userIdTokens"));
        for (Map.Entry<String,UserIdToken> e : userIdTokens.entrySet()) {
            this.userIdTokenData.put(e.getKey(), new UserIdTokenData(e.getValue()));
        }

        // extract all service tokens
        final Set<ServiceToken> serviceTokens = new HashSet<ServiceToken>();
        {
            final Set<ServiceToken> unboundServiceTokens = (Set<ServiceToken>)getFieldValue(mslStore, "unboundServiceTokens");
            serviceTokens.addAll(unboundServiceTokens);

            final Map<Long,Set<ServiceToken>> mtServiceTokens = (Map<Long,Set<ServiceToken>>)getFieldValue(mslStore, "mtServiceTokens");
            for (Set<ServiceToken> sts : mtServiceTokens.values()) {
                serviceTokens.addAll(sts);
            }

            final Map<Long,Set<ServiceToken>> uitServiceTokens = (Map<Long,Set<ServiceToken>>)getFieldValue(mslStore, "uitServiceTokens");
            for (Set<ServiceToken> sts : uitServiceTokens.values()) {
                serviceTokens.addAll(sts);
            }
        }
        for (ServiceToken st : serviceTokens) {
            this.serviceTokenData.add(new ServiceTokenData(st));
        }
    }

    public static byte[] serialize(final SimpleMslStore ms) throws IOException {
        final MslStoreData msd = new MslStoreData(ms);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream oos = null;
        try {
            oos = new ObjectOutputStream(out);
            oos.writeObject(msd);
            return out.toByteArray();
        } finally {
            if (oos != null) try { oos.close(); } catch (Exception ignore) { }
        }
    }

    public static SimpleMslStore deserialize(final byte[] blob, final MslContext mslCtx) throws IOException, MslEncodingException, MslException {
        final MslStoreData msd;
        final ByteArrayInputStream in = new ByteArrayInputStream(blob);
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(in);
            msd = (MslStoreData)ois.readObject();
        } catch (ClassNotFoundException e) {
            throw new IOException("SimpleMslStore unmarshalling error", e);
        } finally {
            if (ois != null) try { ois.close(); } catch (Exception ignore) { }
        }

        final SimpleMslStore mslStore = new SimpleMslStore();

        final Map<Long,MasterToken> mtokens = new HashMap<Long,MasterToken>();
        for (Map.Entry<MasterTokenData,CryptoContextData> e : msd.cryptoContextData.entrySet()) {
            final MasterToken mt = e.getKey().get(mslCtx);
            mslStore.setCryptoContext(mt, e.getValue().get(mslCtx, mt));
            mtokens.put(mt.getSerialNumber(), mt);
        }

        final Map<Long,UserIdToken> uitokens = new HashMap<Long,UserIdToken>();
        for (Map.Entry<String,UserIdTokenData> e : msd.userIdTokenData.entrySet()) {
            final UserIdTokenData uitd = e.getValue();
            final UserIdToken uit = uitd.get(mslCtx, mtokens.get(uitd.mtSerialNumber));
            mslStore.addUserIdToken(e.getKey(), uit);
            uitokens.put(uit.getSerialNumber(), uit);
        }

        final Set<ServiceToken> stokens = new HashSet<ServiceToken>();
        for (ServiceTokenData std : msd.serviceTokenData) {
            stokens.add(std.get(mslCtx, mtokens.get(std.mtSerialNumber), uitokens.get(std.uitSerialNumber)));
        }
        mslStore.addServiceTokens(stokens);

        return mslStore;
    }

    private static Object getFieldValue(final Object o, final String name) {
        final Field f;
        try {
            f = o.getClass().getDeclaredField(name);
        } catch (Exception e) {
            throw new IllegalArgumentException(String.format("Class %s has no field %s", o.getClass().getName(), name), e);
        }
        f.setAccessible(true);
        try {
            return f.get(o);
        } catch (Exception e) {
            throw new IllegalArgumentException(String.format("Class %s field %s - cannot access value", o.getClass().getName(), name), e);
        }
    }

    private final Map<MasterTokenData,CryptoContextData> cryptoContextData = new HashMap<MasterTokenData,CryptoContextData>();
    private final Map<String,UserIdTokenData> userIdTokenData = new HashMap<String,UserIdTokenData>();
    private final Set<ServiceTokenData> serviceTokenData = new HashSet<ServiceTokenData>();

    private static final class MasterTokenData implements Serializable {
        MasterTokenData(final MasterToken mt) {
            this.s = mt.toJSONString();
        }
        MasterToken get(final MslContext ctx) throws MslEncodingException, MslException, MslCryptoException {
            return new MasterToken(ctx, new JSONObject(s));
        }
        private final String s;
    }

    private static final class UserIdTokenData implements Serializable {
        UserIdTokenData(final UserIdToken uit) {
            this.s = uit.toJSONString();
            this.mtSerialNumber = uit.getMasterTokenSerialNumber();
        }
        UserIdToken get(final MslContext ctx, final MasterToken mt) throws MslEncodingException, MslException, MslCryptoException {
            return new UserIdToken(ctx, new JSONObject(s), mt);
        }
        private final String s;
        private final long mtSerialNumber;
    }

    private static final class ServiceTokenData implements Serializable {
        ServiceTokenData(final ServiceToken st) {
            this.s = st.toJSONString();
            this.mtSerialNumber = st.getMasterTokenSerialNumber();
            this.uitSerialNumber = st.getUserIdTokenSerialNumber();
        }
        ServiceToken get(final MslContext ctx, final MasterToken mt, final UserIdToken uit) throws MslEncodingException, MslException, MslCryptoException {
            return new ServiceToken(ctx, new JSONObject(s), mt, uit, (ICryptoContext)null);
        }
        private final String s;
        private final long mtSerialNumber;
        private final long uitSerialNumber;
    }

    private static final class CryptoContextData implements Serializable {
        private static final String ID_FIELD = "id";
        private static final String ENC_FIELD = "encryptionKey";
        private static final String SIG_FIELD = "signatureKey";
        private static final String WRAP_FIELD = "wrappingKey";

        CryptoContextData(final ICryptoContext ctx) {
            if (!(ctx instanceof SessionCryptoContext))
                throw new IllegalArgumentException(String.format("CryptoContext[%s] - required %s", ctx.getClass().getName(), SessionCryptoContext.class.getName()));
            try {
                final Map<String,Field> fields = getAllInstanceFields(ctx.getClass());
                Field f = fields.get(ID_FIELD);
                if (f == null)
                    throw new RuntimeException(String.format("%s: field \"%s\" missing", ctx.getClass().getName(), ID_FIELD));
                id = (String)f.get(ctx);

                f = fields.get(ENC_FIELD);
                if (f == null)
                    throw new RuntimeException(String.format("%s: field \"%s\" missing", ctx.getClass().getName(), ENC_FIELD));
                this.encKey = (SecretKey)f.get(ctx);

                f = fields.get(SIG_FIELD);
                if (f == null)
                    throw new RuntimeException(String.format("%s: field \"%s\" missing", ctx.getClass().getName(), SIG_FIELD));
                this.hmacKey = (SecretKey)f.get(ctx);

                f = fields.get(WRAP_FIELD);
                if (f == null)
                    throw new RuntimeException(String.format("%s: field \"%s\" missing", ctx.getClass().getName(), WRAP_FIELD));
                this.wrapKey = (SecretKey)f.get(ctx);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(String.format("CryptoContext[%s]: Cannot Access Some Fields", ctx.getClass().getName()));
            }
        }

        ICryptoContext get(final MslContext mctx, final MasterToken mt) {
            final String suffix = "_" + mt.getSequenceNumber();
            if (!id.endsWith(suffix)) {
                System.out.println(String.format("Internal Error: Unexpected Crypto Context ID %s, should end with %s", id, suffix));
                throw new IllegalArgumentException(String.format("Internal Error: Unexpected Crypto Context ID %s, should end with %s", id, suffix));
            }
            final String id_without_suffix = id.substring(0, id.length() - suffix.length());
            return new SessionCryptoContext(mctx, mt, id_without_suffix, encKey, hmacKey);
        }

        private final String id;
        private final SecretKey encKey;
        private final SecretKey hmacKey;
        private final SecretKey wrapKey;
    }

    /*
     * return all non-static non-transient fields of a given class and make them accessible
     */
    private static Map<String,Field> getAllInstanceFields(Class cls) {
        final Map<String,Field> fields = new HashMap<String,Field>();
        for ( ; cls.getSuperclass() != null; cls = cls.getSuperclass()) {
            for (final Field f : cls.getDeclaredFields()) {
                if (Modifier.isStatic(f.getModifiers()) || Modifier.isTransient(f.getModifiers())) {
                    continue;
                }
                f.setAccessible(true);
                fields.put(f.getName(),f);
            }
        }
        return fields;
    }
}
