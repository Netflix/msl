/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.SimpleMslStore;

/**
 * <p>
 * The class for serializing SimpleMslStore. Because of using reflection, this code is pretty brittle and
 * must keep in-sync with SimpleMslStore changes.
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class MslStoreData implements Serializable {
        /** for proper serialization */
    private static final long serialVersionUID = 5207304253726353139L;

    /*
     * SimpleMslStore fields that need to be accessed for serialization.
     * To be kept in-sync with SimpleMslStore code
     */
    /** SimpleMslStore field */
    private static final String MS_CRYPTO_CONTEXT_FIELD = "cryptoContexts";
    /** SimpleMslStore field */
    private static final String MS_UID_TOKENS_FIELD     = "userIdTokens";
    /** SimpleMslStore field */
    private static final String MS_UNB_SVC_TOKENS_FIELD = "unboundServiceTokens";
    /** SimpleMslStore field */
    private static final String MS_MT_SVC_TOKENS_FIELD  = "mtServiceTokens";
    /** SimpleMslStore field */
    private static final String MS_UIT_SVC_TOKENS_FIELD = "uitServiceTokens";
    /** SimpleMslStore field */
    private static final String MS_NON_REPLAY_IDS_FIELD = "nonReplayableIds";

    /**
     * Create serializable MslStoreData from non-serializable SimpleMslStore
     * @param ctx       MSL context
     * @param mslStore  SimpleMslStore instance
     * @throws MslEncoderException 
     */
    @SuppressWarnings("unchecked")
    private MslStoreData(final MslContext ctx, final SimpleMslStore mslStore) throws MslEncoderException {
        if (mslStore == null)
            throw new IllegalArgumentException("NULL MslStore");

        // extract all master tokens with crypto contexts
        final Map<MasterToken,ICryptoContext> cryptoContexts = (Map<MasterToken,ICryptoContext>)getFieldValue(mslStore, MS_CRYPTO_CONTEXT_FIELD);
        for (final Map.Entry<MasterToken,ICryptoContext> e : cryptoContexts.entrySet()) {
            this.cryptoContextData.put(new MasterTokenData(ctx, e.getKey()), new CryptoContextData(e.getValue()));
        }

        // extract all user id tokens
        final Map<String,UserIdToken> userIdTokens = new HashMap<String,UserIdToken>((Map<String,UserIdToken>)getFieldValue(mslStore, MS_UID_TOKENS_FIELD));
        for (final Map.Entry<String,UserIdToken> e : userIdTokens.entrySet()) {
            this.userIdTokenData.put(e.getKey(), new UserIdTokenData(ctx, e.getValue()));
        }

        // extract all service tokens
        final Set<ServiceToken> serviceTokens = new HashSet<ServiceToken>();
        {
            final Set<ServiceToken> unboundServiceTokens = (Set<ServiceToken>)getFieldValue(mslStore, MS_UNB_SVC_TOKENS_FIELD);
            serviceTokens.addAll(unboundServiceTokens);

            final Map<Long,Set<ServiceToken>> mtServiceTokens = (Map<Long,Set<ServiceToken>>)getFieldValue(mslStore, MS_MT_SVC_TOKENS_FIELD);
            for (final Set<ServiceToken> sts : mtServiceTokens.values()) {
                serviceTokens.addAll(sts);
            }

            final Map<Long,Set<ServiceToken>> uitServiceTokens = (Map<Long,Set<ServiceToken>>)getFieldValue(mslStore, MS_UIT_SVC_TOKENS_FIELD);
            for (final Set<ServiceToken> sts : uitServiceTokens.values()) {
                serviceTokens.addAll(sts);
            }
        }
        for (final ServiceToken st : serviceTokens) {
            this.serviceTokenData.add(new ServiceTokenData(ctx, st));
        }

        // extract non-replayable id's
        this.nonReplayableIds = (Map<Long,Long>)getFieldValue(mslStore, MS_NON_REPLAY_IDS_FIELD);
    }

    /**
     * SimpleMslStore serializer
     *
     * @param ms SimpleMslStore instance
     * @return blob serialized SimpleMslStore instance
     * @throws IOException
     * @throws MslEncoderException 
     */
    public static byte[] serialize(final SimpleMslStore ms, final MslContext ctx) throws IOException, MslEncoderException {
        final MslStoreData msd = new MslStoreData(ctx, ms);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream oos = null;
        try {
            oos = new ObjectOutputStream(out);
            oos.writeObject(msd);
            return out.toByteArray();
        } finally {
            if (oos != null) try { oos.close(); } catch (final Exception ignore) { }
        }
    }

    /**
     * SimpleMslStore deserializer
     *
     * @param blob serialized SimpleMslStore
     * @param mslCtx MslContext instance
     * @return deserialized SimpleMslStore instance
     * @throws IOException
     * @throws MslEncodingException
     * @throws MslException
     * @throws MslEncoderException 
     */
    public static SimpleMslStore deserialize(final byte[] blob, final MslContext mslCtx)
        throws IOException, MslEncodingException, MslException, MslEncoderException
    {
        final MslStoreData msd;
        final ByteArrayInputStream in = new ByteArrayInputStream(blob);
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(in);
            msd = (MslStoreData)ois.readObject();
        } catch (final ClassNotFoundException e) {
            throw new IOException("SimpleMslStore unmarshalling error", e);
        } finally {
            if (ois != null) try { ois.close(); } catch (final Exception ignore) { }
        }

        final SimpleMslStore mslStore = new SimpleMslStore();

        final Map<Long,MasterToken> mtokens = new HashMap<Long,MasterToken>();
        for (final Map.Entry<MasterTokenData,CryptoContextData> e : msd.cryptoContextData.entrySet()) {
            final MasterToken mt = e.getKey().get(mslCtx);
            mslStore.setCryptoContext(mt, e.getValue().get(mslCtx, mt));
            mtokens.put(mt.getSerialNumber(), mt);
        }

        final Map<Long,UserIdToken> uitokens = new HashMap<Long,UserIdToken>();
        for (final Map.Entry<String,UserIdTokenData> e : msd.userIdTokenData.entrySet()) {
            final UserIdTokenData uitd = e.getValue();
            final UserIdToken uit = uitd.get(mslCtx, mtokens.get(uitd.mtSerialNumber));
            mslStore.addUserIdToken(e.getKey(), uit);
            uitokens.put(uit.getSerialNumber(), uit);
        }

        final Set<ServiceToken> stokens = new HashSet<ServiceToken>();
        for (final ServiceTokenData std : msd.serviceTokenData) {
            stokens.add(std.get(mslCtx, mtokens.get(std.mtSerialNumber), uitokens.get(std.uitSerialNumber)));
        }
        mslStore.addServiceTokens(stokens);

        setFieldValue(mslStore, MS_NON_REPLAY_IDS_FIELD, msd.nonReplayableIds);

        return mslStore;
    }

    /** Map of serializable master tokens onto serializable crypto contexts */
    private final Map<MasterTokenData,CryptoContextData> cryptoContextData = new HashMap<MasterTokenData,CryptoContextData>();
    /** Map of user IDs onto serializable user id tokens */
    private final Map<String,UserIdTokenData> userIdTokenData = new HashMap<String,UserIdTokenData>();
    /** Set of serializable service tokens */
    private final Set<ServiceTokenData> serviceTokenData = new HashSet<ServiceTokenData>();
    /** Map of master token serial numbers onto non-replayable IDs. */
    private final Map<Long,Long> nonReplayableIds;

    /**
     * serializable wrapper class for MasterToken
     */
    private static final class MasterTokenData implements Serializable {
        /** for proper serialization */
        private static final long serialVersionUID = -4900828984126453948L;
        /**
         * @param ctx MslContext
         * @param mt master token
         * @throws MslEncoderException 
         */
        MasterTokenData(final MslContext ctx, final MasterToken mt) throws MslEncoderException {
            final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
            this.s = mt.toMslEncoding(encoder, MslEncoderFormat.JSON);
        }
        /**
         * @param ctx MslContext
         * @return re-created master token
         * @throws MslEncodingException
         * @throws MslException
         * @throws MslCryptoException
         * @throws MslEncoderException 
         */
        MasterToken get(final MslContext ctx) throws MslEncodingException, MslException, MslCryptoException, MslEncoderException {
            final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
            final MslObject mo = encoder.parseObject(s);
            return new MasterToken(ctx, mo);
        }
        /** serialized master token */
        private final byte[] s;
    }

    /**
     * serializable wrapper class for UserIdToken
     */
    private static final class UserIdTokenData implements Serializable {
        /** for proper serialization */
        private static final long serialVersionUID = -5191856143592904675L;
        /**
         * @param ctx MslContext
         * @param uit user id token
         * @throws MslEncoderException 
         */
        UserIdTokenData(final MslContext ctx, final UserIdToken uit) throws MslEncoderException {
            final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
            this.s = uit.toMslEncoding(encoder, MslEncoderFormat.JSON);
            this.mtSerialNumber = uit.getMasterTokenSerialNumber();
        }
        /**
         * @param ctx MslContext
         * @param mt master token
         * @return re-created user id token
         * @throws MslEncodingException
         * @throws MslException
         * @throws MslCryptoException
         * @throws MslEncoderException 
         */
        UserIdToken get(final MslContext ctx, final MasterToken mt) throws MslEncodingException, MslException, MslCryptoException, MslEncoderException {
            final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
            final MslObject mo = encoder.parseObject(s);
            return new UserIdToken(ctx, mo, mt);
        }
        /** serialized user id token */
        private final byte[] s;
        /** master token serial number */
        private final long mtSerialNumber;
    }

    /**
     * serializable wrapper class for ServiceToken
     */
    private static final class ServiceTokenData implements Serializable {
        /** for proper serialization */
        private static final long serialVersionUID = -2854005430616613106L;
        /**
         * @param ctx MslContext
         * @param st service token
         * @throws MslEncoderException 
         */
        ServiceTokenData(final MslContext ctx, final ServiceToken st) throws MslEncoderException {
            final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
            this.s = st.toMslEncoding(encoder, MslEncoderFormat.JSON);
            this.mtSerialNumber = st.getMasterTokenSerialNumber();
            this.uitSerialNumber = st.getUserIdTokenSerialNumber();
        }
        /**
         * @param ctx MslContext
         * @param mt master token
         * @param uit user id token
         * @return re-created service token
         * @throws MslEncodingException
         * @throws MslException
         * @throws MslCryptoException
         * @throws MslEncoderException 
         */
        ServiceToken get(final MslContext ctx, final MasterToken mt, final UserIdToken uit)
            throws MslEncodingException, MslException, MslCryptoException, MslEncoderException
        {
            final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
            final MslObject mo = encoder.parseObject(s);
            return new ServiceToken(ctx, mo, mt, uit, (ICryptoContext)null);
        }
        /** serialized service token */
        private final byte[] s;
        /** master token serial number */
        private final long mtSerialNumber;
        /** user id token serial number */
        private final long uitSerialNumber;
    }

    /**
     * serializable wrapper class for SessionCryptoContext
     */
    private static final class CryptoContextData implements Serializable {
        /** for proper serialization */
        private static final long serialVersionUID = -4094166271048593127L;
        /** SessionEncryptionContext field name */
        private static final String ID_FIELD = "id";
        /** SessionEncryptionContext field name */
        private static final String ENC_FIELD = "encryptionKey";
        /** SessionEncryptionContext field name */
        private static final String SIG_FIELD = "signatureKey";
        /** SessionEncryptionContext field name */
        private static final String WRAP_FIELD = "wrappingKey";

        /**
         * @param ctx crypto context that must be of SessionCryptoContext type
         */
        CryptoContextData(final ICryptoContext ctx) {
            if (!(ctx instanceof SessionCryptoContext))
                throw new IllegalArgumentException(String.format("CryptoContext[%s] - required %s",
                    ctx.getClass().getName(), SessionCryptoContext.class.getName()));
            this.id      = (String)   getFieldValue(ctx, ID_FIELD  );
            this.encKey  = (SecretKey)getFieldValue(ctx, ENC_FIELD );
            this.hmacKey = (SecretKey)getFieldValue(ctx, SIG_FIELD );
            this.wrapKey = (SecretKey)getFieldValue(ctx, WRAP_FIELD);
        }

        /**
         * @param mctx MslContext
         * @param mt master token
         * @return recreated crypto context
         */
        ICryptoContext get(final MslContext mctx, final MasterToken mt) {
            final String suffix = "_" + mt.getSequenceNumber();
            if (!id.endsWith(suffix)) {
                throw new IllegalArgumentException(String.format("Internal Error: Unexpected Crypto Context ID %s, should end with %s", id, suffix));
            }
            final String id_without_suffix = id.substring(0, id.length() - suffix.length());
            return new SessionCryptoContext(mctx, mt, id_without_suffix, encKey, hmacKey);
        }

        /** crypto context id */
        private final String id;
        /** crypto context encryption key */
        private final SecretKey encKey;
        /** crypto context hmac key */
        private final SecretKey hmacKey;
        /** crypto context wrapping key */
        private final SecretKey wrapKey;
    }

   /* ********************************
    * Java reflection helper methods *
    **********************************/

    /**
     * get the value of the field with the given name for a given object
     *
     * @param o object
     * @param name name of the field of this object
     * @return value of the field with the given name of this object
     */
    private static Object getFieldValue(final Object o, final String name) {
        if (o == null)
            throw new IllegalArgumentException("NULL object");
        if (name == null)
            throw new IllegalArgumentException("NULL field name");

        final Field f = getField(o, name);
        try {
            return f.get(o);
        } catch (final IllegalAccessException e) {
            throw new IllegalArgumentException(String.format("Class %s field %s - cannot get value", o.getClass().getName(), name), e);
        }
    }

    /**
     * set the value of the field with the given name for a given object
     *
     * @param o object
     * @param name name of the field of this object
     * @param value value to assign to the given field of the given object
     */
    private static void setFieldValue(final Object o, final String name, final Object value) {
        if (o == null)
            throw new IllegalArgumentException("NULL object");
        if (name == null)
            throw new IllegalArgumentException("NULL field name");
        if (value == null)
            throw new IllegalArgumentException("NULL field value");
        final Field f = getField(o, name);
        try {
            f.set(o, value);
        } catch (final IllegalAccessException e) {
            throw new IllegalArgumentException(String.format("Class %s field %s - cannot set value", o.getClass().getName(), name), e);
        }
    }

    /**
     * Return the field with the given name of a given class (search superclasses as well)
     * and make it accessible for get and set
     *
     * @param o object
     * @param name name of the field of this object
     * @return field with the given name, made accessible for get/set operations
     */
    private static Field getField(final Object o, final String name) {
        if (o == null)
            throw new IllegalArgumentException("NULL object");
        if (name == null)
            throw new IllegalArgumentException("NULL field name");
        Class<? extends Object> cls = o.getClass();
        for ( ; cls.getSuperclass() != null; cls = cls.getSuperclass()) {
            for (final Field f : cls.getDeclaredFields()) {
                if (Modifier.isStatic(f.getModifiers()) || Modifier.isTransient(f.getModifiers())) {
                    continue;
                }
                if (name.equals(f.getName())) {
                    f.setAccessible(true);
                    return f;
                }
            }
        }
        throw new IllegalArgumentException(String.format("Class %s: no field %s found", o.getClass().getName(), name));
    }
}
