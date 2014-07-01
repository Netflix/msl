/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.JsonWebKey.Algorithm;
import com.netflix.msl.crypto.JsonWebKey.KeyOp;
import com.netflix.msl.crypto.JsonWebKey.Type;
import com.netflix.msl.crypto.JsonWebKey.Usage;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.JsonUtils;

/**
 * JSON web key unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class JsonWebKeyTest {
    /** JSON key key type. */
    private static final String KEY_TYPE = "kty";
    /** JSON key usage. */
    private static final String KEY_USAGE = "use";
    /** JSON key key operations. */
    private static final String KEY_KEY_OPS = "key_ops";
    /** JSON key algorithm. */
    private static final String KEY_ALGORITHM = "alg";
    /** JSON key extractable. */
    private static final String KEY_EXTRACTABLE = "extractable";
    /** JSON key key ID. */
    private static final String KEY_KEY_ID = "kid";
    
    // RSA keys.
    /** JSON key modulus. */
    private static final String KEY_MODULUS = "n";
    /** JSON key public exponent. */
    private static final String KEY_PUBLIC_EXPONENT = "e";
    /** JSON key private exponent. */
    private static final String KEY_PRIVATE_EXPONENT = "d";
    
    // Symmetric keys.
    /** JSON key key. */
    private static final String KEY_KEY = "k";
    
    // Key operations.
    /** Encrypt/decrypt key operations. */
    private static final Set<KeyOp> ENCRYPT_DECRYPT = new HashSet<KeyOp>(Arrays.asList(KeyOp.encrypt, KeyOp.decrypt));
    /** Wrap/unwrap key operations. */
    private static final Set<KeyOp> WRAP_UNWRAP = new HashSet<KeyOp>(Arrays.asList(KeyOp.wrapKey, KeyOp.unwrapKey));
    /** Sign/verify key operations. */
    private static final Set<KeyOp> SIGN_VERIFY = new HashSet<KeyOp>(Arrays.asList(KeyOp.sign, KeyOp.verify));
    
    // Expected key operations JSON arrays.
    /** Sign/verify. */
    private static final JSONArray JA_SIGN_VERIFY = new JSONArray(Arrays.asList(KeyOp.sign.name(), KeyOp.verify.name()));
    /** Encrypt/decrypt. */
    private static final JSONArray JA_ENCRYPT_DECRYPT = new JSONArray(Arrays.asList(KeyOp.encrypt.name(), KeyOp.verify.name()));
    /** Wrap/unwrap. */
    private static final JSONArray JA_WRAP_UNWRAP = new JSONArray(Arrays.asList(KeyOp.wrapKey.name(), KeyOp.unwrapKey.name()));
    
    /** Null usage. */
    private static final Usage NULL_USAGE = null;
    /** Null key operations. */
    private static final Set<KeyOp> NULL_KEYOPS = null;
    
    /**
     * Returns the big integer in big-endian format without any leading sign
     * bits.
     * 
     * @param bi the big integer.
     * @return the big integer in big-endian form.
     */
    private static byte[] bi2bytes(final BigInteger bi) {
        final byte[] bib = bi.toByteArray();
        final int len = (int)Math.ceil((double)bi.bitLength() / Byte.SIZE);
        return Arrays.copyOfRange(bib, bib.length - len, bib.length);
    }
    
    private static final boolean EXTRACTABLE = true;
    private static final String KEY_ID = "kid";
    private static RSAPublicKey PUBLIC_KEY;
    private static RSAPrivateKey PRIVATE_KEY;
    private static SecretKey SECRET_KEY;
    
    private static final Random random = new Random();
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        
        final KeyPairGenerator keypairGenerator = KeyPairGenerator.getInstance("RSA");
        keypairGenerator.initialize(512);
        final KeyPair keypair = keypairGenerator.generateKeyPair();
        PRIVATE_KEY = (RSAPrivateKey)keypair.getPrivate();
        PUBLIC_KEY = (RSAPublicKey)keypair.getPublic();
        
        final byte[] keydata = new byte[16];
        random.nextBytes(keydata);
        SECRET_KEY = new SecretKeySpec(keydata, JcaAlgorithm.AES);
    }
    
    @Test
    public void rsaUsageCtor() throws MslCryptoException, MslEncodingException, JSONException {
        final JsonWebKey jwk = new JsonWebKey(Usage.sig, Algorithm.RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
        assertEquals(EXTRACTABLE, jwk.isExtractable());
        assertEquals(Algorithm.RSA1_5, jwk.getAlgorithm());
        assertEquals(KEY_ID, jwk.getId());
        final KeyPair keypair = jwk.getRsaKeyPair();
        assertNotNull(keypair);
        final RSAPublicKey pubkey = (RSAPublicKey)keypair.getPublic();
        assertEquals(PUBLIC_KEY.getModulus(), pubkey.getModulus());
        assertEquals(PUBLIC_KEY.getPublicExponent(), pubkey.getPublicExponent());
        final RSAPrivateKey privkey = (RSAPrivateKey)keypair.getPrivate();
        assertEquals(PRIVATE_KEY.getModulus(), privkey.getModulus());
        assertEquals(PRIVATE_KEY.getPrivateExponent(), privkey.getPrivateExponent());
        assertNull(jwk.getSecretKey());
        assertEquals(Type.rsa, jwk.getType());
        assertEquals(Usage.sig, jwk.getUsage());
        assertNull(jwk.getKeyOps());
        final String json = jwk.toJSONString();
        assertNotNull(json);
        
        final JsonWebKey joJwk = new JsonWebKey(new JSONObject(json));
        assertEquals(jwk.isExtractable(), joJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), joJwk.getAlgorithm());
        assertEquals(jwk.getId(), joJwk.getId());
        final KeyPair joKeypair = joJwk.getRsaKeyPair();
        assertNotNull(joKeypair);
        final RSAPublicKey joPubkey = (RSAPublicKey)joKeypair.getPublic();
        assertEquals(pubkey.getModulus(), joPubkey.getModulus());
        assertEquals(pubkey.getPublicExponent(), joPubkey.getPublicExponent());
        final RSAPrivateKey joPrivkey = (RSAPrivateKey)joKeypair.getPrivate();
        assertEquals(privkey.getModulus(), joPrivkey.getModulus());
        assertEquals(privkey.getPrivateExponent(), joPrivkey.getPrivateExponent());
        assertNull(joJwk.getSecretKey());
        assertEquals(jwk.getType(), joJwk.getType());
        assertEquals(jwk.getUsage(), joJwk.getUsage());
        assertEquals(jwk.getKeyOps(), joJwk.getKeyOps());
        final String joJson = joJwk.toJSONString();
        assertNotNull(joJson);
        assertEquals(json, joJson);
    }
    
    @Test
    public void rsaKeyOpsCtor() throws MslCryptoException, MslEncodingException, JSONException {
        final JsonWebKey jwk = new JsonWebKey(SIGN_VERIFY, Algorithm.RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
        assertEquals(EXTRACTABLE, jwk.isExtractable());
        assertEquals(Algorithm.RSA1_5, jwk.getAlgorithm());
        assertEquals(KEY_ID, jwk.getId());
        final KeyPair keypair = jwk.getRsaKeyPair();
        assertNotNull(keypair);
        final RSAPublicKey pubkey = (RSAPublicKey)keypair.getPublic();
        assertEquals(PUBLIC_KEY.getModulus(), pubkey.getModulus());
        assertEquals(PUBLIC_KEY.getPublicExponent(), pubkey.getPublicExponent());
        final RSAPrivateKey privkey = (RSAPrivateKey)keypair.getPrivate();
        assertEquals(PRIVATE_KEY.getModulus(), privkey.getModulus());
        assertEquals(PRIVATE_KEY.getPrivateExponent(), privkey.getPrivateExponent());
        assertNull(jwk.getSecretKey());
        assertEquals(Type.rsa, jwk.getType());
        assertNull(jwk.getUsage());
        assertEquals(SIGN_VERIFY, jwk.getKeyOps());
        final String json = jwk.toJSONString();
        assertNotNull(json);
        
        final JsonWebKey joJwk = new JsonWebKey(new JSONObject(json));
        assertEquals(jwk.isExtractable(), joJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), joJwk.getAlgorithm());
        assertEquals(jwk.getId(), joJwk.getId());
        final KeyPair joKeypair = joJwk.getRsaKeyPair();
        assertNotNull(joKeypair);
        final RSAPublicKey joPubkey = (RSAPublicKey)joKeypair.getPublic();
        assertEquals(pubkey.getModulus(), joPubkey.getModulus());
        assertEquals(pubkey.getPublicExponent(), joPubkey.getPublicExponent());
        final RSAPrivateKey joPrivkey = (RSAPrivateKey)joKeypair.getPrivate();
        assertEquals(privkey.getModulus(), joPrivkey.getModulus());
        assertEquals(privkey.getPrivateExponent(), joPrivkey.getPrivateExponent());
        assertNull(joJwk.getSecretKey());
        assertEquals(jwk.getType(), joJwk.getType());
        assertEquals(jwk.getUsage(), joJwk.getUsage());
        assertEquals(jwk.getKeyOps(), joJwk.getKeyOps());
        final String joJson = joJwk.toJSONString();
        assertNotNull(joJson);
        // This test will not always pass since the key operations are
        // unordered.
        //assertEquals(json, joJson);
    }
    
    @Test
    public void rsaUsageJson() throws JSONException {
        final JsonWebKey jwk = new JsonWebKey(Usage.sig, Algorithm.RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        assertEquals(EXTRACTABLE, jo.optBoolean(KEY_EXTRACTABLE));
        assertEquals(Algorithm.RSA1_5.name(), jo.getString(KEY_ALGORITHM));
        assertEquals(KEY_ID, jo.getString(KEY_KEY_ID));
        assertEquals(Type.rsa.name(), jo.getString(KEY_TYPE));
        assertEquals(Usage.sig.name(), jo.getString(KEY_USAGE));
        assertFalse(jo.has(KEY_KEY_OPS));
        
        final String modulus = JsonUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
        final String pubexp = JsonUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getPublicExponent()));
        final String privexp = JsonUtils.b64urlEncode(bi2bytes(PRIVATE_KEY.getPrivateExponent()));
        
        assertEquals(modulus, jo.getString(KEY_MODULUS));
        assertEquals(pubexp, jo.getString(KEY_PUBLIC_EXPONENT));
        assertEquals(privexp, jo.getString(KEY_PRIVATE_EXPONENT));
        
        assertFalse(jo.has(KEY_KEY));
    }
    
    @Test
    public void rsaKeyOpsJson() throws JSONException {
        final JsonWebKey jwk = new JsonWebKey(SIGN_VERIFY, Algorithm.RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        assertEquals(EXTRACTABLE, jo.optBoolean(KEY_EXTRACTABLE));
        assertEquals(Algorithm.RSA1_5.name(), jo.getString(KEY_ALGORITHM));
        assertEquals(KEY_ID, jo.getString(KEY_KEY_ID));
        assertEquals(Type.rsa.name(), jo.getString(KEY_TYPE));
        assertFalse(jo.has(KEY_USAGE));
        assertTrue(JsonUtils.equalSets(JA_SIGN_VERIFY, jo.getJSONArray(KEY_KEY_OPS)));
        
        final String modulus = JsonUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
        final String pubexp = JsonUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getPublicExponent()));
        final String privexp = JsonUtils.b64urlEncode(bi2bytes(PRIVATE_KEY.getPrivateExponent()));
        
        assertEquals(modulus, jo.getString(KEY_MODULUS));
        assertEquals(pubexp, jo.getString(KEY_PUBLIC_EXPONENT));
        assertEquals(privexp, jo.getString(KEY_PRIVATE_EXPONENT));
        
        assertFalse(jo.has(KEY_KEY));
    }
    
    @Test
    public void rsaNullCtorPublic() throws MslCryptoException, MslEncodingException, JSONException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, null);
        assertFalse(jwk.isExtractable());
        assertNull(jwk.getAlgorithm());
        assertNull(jwk.getId());
        final KeyPair keypair = jwk.getRsaKeyPair();
        assertNotNull(keypair);
        final RSAPublicKey pubkey = (RSAPublicKey)keypair.getPublic();
        assertEquals(PUBLIC_KEY.getModulus(), pubkey.getModulus());
        assertEquals(PUBLIC_KEY.getPublicExponent(), pubkey.getPublicExponent());
        final RSAPrivateKey privkey = (RSAPrivateKey)keypair.getPrivate();
        assertNull(privkey);
        assertNull(jwk.getSecretKey());
        assertEquals(Type.rsa, jwk.getType());
        assertNull(jwk.getUsage());
        assertNull(jwk.getKeyOps());
        final String json = jwk.toJSONString();
        assertNotNull(json);
        
        final JsonWebKey joJwk = new JsonWebKey(new JSONObject(json));
        assertEquals(jwk.isExtractable(), joJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), joJwk.getAlgorithm());
        assertEquals(jwk.getId(), joJwk.getId());
        final KeyPair joKeypair = joJwk.getRsaKeyPair();
        assertNotNull(joKeypair);
        final RSAPublicKey joPubkey = (RSAPublicKey)joKeypair.getPublic();
        assertEquals(pubkey.getModulus(), joPubkey.getModulus());
        assertEquals(pubkey.getPublicExponent(), joPubkey.getPublicExponent());
        final RSAPrivateKey joPrivkey = (RSAPrivateKey)joKeypair.getPrivate();
        assertNull(joPrivkey);
        assertNull(joJwk.getSecretKey());
        assertEquals(jwk.getType(), joJwk.getType());
        assertEquals(jwk.getUsage(), joJwk.getUsage());
        assertEquals(jwk.getKeyOps(), joJwk.getKeyOps());
        final String joJson = joJwk.toJSONString();
        assertNotNull(joJson);
        assertEquals(json, joJson);
    }
    
    @Test
    public void rsaNullCtorPrivate() throws MslCryptoException, MslEncodingException, JSONException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, null, PRIVATE_KEY);
        assertFalse(jwk.isExtractable());
        assertNull(jwk.getAlgorithm());
        assertNull(jwk.getId());
        final KeyPair keypair = jwk.getRsaKeyPair();
        assertNotNull(keypair);
        final RSAPublicKey pubkey = (RSAPublicKey)keypair.getPublic();
        assertNull(pubkey);
        final RSAPrivateKey privkey = (RSAPrivateKey)keypair.getPrivate();
        assertEquals(PRIVATE_KEY.getModulus(), privkey.getModulus());
        assertEquals(PRIVATE_KEY.getPrivateExponent(), privkey.getPrivateExponent());
        assertNull(jwk.getSecretKey());
        assertEquals(Type.rsa, jwk.getType());
        assertNull(jwk.getUsage());
        assertNull(jwk.getKeyOps());
        final String json = jwk.toJSONString();
        assertNotNull(json);
        
        final JsonWebKey joJwk = new JsonWebKey(new JSONObject(json));
        assertEquals(jwk.isExtractable(), joJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), joJwk.getAlgorithm());
        assertEquals(jwk.getId(), joJwk.getId());
        final KeyPair joKeypair = joJwk.getRsaKeyPair();
        assertNotNull(joKeypair);
        final RSAPublicKey joPubkey = (RSAPublicKey)joKeypair.getPublic();
        assertNull(joPubkey);
        final RSAPrivateKey joPrivkey = (RSAPrivateKey)joKeypair.getPrivate();
        assertEquals(privkey.getModulus(), joPrivkey.getModulus());
        assertEquals(privkey.getPrivateExponent(), joPrivkey.getPrivateExponent());
        assertNull(joJwk.getSecretKey());
        assertEquals(jwk.getType(), joJwk.getType());
        assertEquals(jwk.getUsage(), joJwk.getUsage());
        assertEquals(jwk.getKeyOps(), joJwk.getKeyOps());
        final String joJson = joJwk.toJSONString();
        assertNotNull(joJson);
        assertEquals(json, joJson);
    }
    
    @Test
    public void rsaNullJsonPublic() throws JSONException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, null);
        final String json = jwk.toJSONString();
        final JSONObject jo = new JSONObject(json);
        
        assertFalse(jo.getBoolean(KEY_EXTRACTABLE));
        assertFalse(jo.has(KEY_ALGORITHM));
        assertFalse(jo.has(KEY_KEY_ID));
        assertEquals(Type.rsa.name(), jo.getString(KEY_TYPE));
        assertFalse(jo.has(KEY_USAGE));
        assertFalse(jo.has(KEY_KEY_OPS));
        
        final String modulus = JsonUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
        final String pubexp = JsonUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getPublicExponent()));
        
        assertEquals(modulus, jo.getString(KEY_MODULUS));
        assertEquals(pubexp, jo.getString(KEY_PUBLIC_EXPONENT));
        assertFalse(jo.has(KEY_PRIVATE_EXPONENT));

        assertFalse(jo.has(KEY_KEY));
    }
    
    @Test
    public void rsaNullJsonPrivate() throws JSONException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, null, PRIVATE_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        assertFalse(jo.getBoolean(KEY_EXTRACTABLE));
        assertFalse(jo.has(KEY_ALGORITHM));
        assertFalse(jo.has(KEY_KEY_ID));
        assertEquals(Type.rsa.name(), jo.getString(KEY_TYPE));
        assertFalse(jo.has(KEY_USAGE));
        assertFalse(jo.has(KEY_KEY_OPS));
        
        final String modulus = JsonUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
        final String privexp = JsonUtils.b64urlEncode(bi2bytes(PRIVATE_KEY.getPrivateExponent()));
        
        assertEquals(modulus, jo.getString(KEY_MODULUS));
        assertFalse(jo.has(KEY_PUBLIC_EXPONENT));
        assertEquals(privexp, jo.getString(KEY_PRIVATE_EXPONENT));

        assertFalse(jo.has(KEY_KEY));
    }
    
    @Test(expected = MslInternalException.class)
    public void rsaCtorNullKeys() {
        new JsonWebKey(NULL_USAGE, null, false, null, null, null);
    }
    
    @Test(expected = MslInternalException.class)
    public void rsaCtorMismatchedAlgorithm() {
        new JsonWebKey(NULL_USAGE, Algorithm.A128CBC, false, null, PUBLIC_KEY, PRIVATE_KEY);
    }
    
    @Test
    public void octUsageCtor() throws MslCryptoException, MslEncodingException, JSONException {
        final JsonWebKey jwk = new JsonWebKey(Usage.enc, Algorithm.A128CBC, EXTRACTABLE, KEY_ID, SECRET_KEY);
        assertEquals(EXTRACTABLE, jwk.isExtractable());
        assertEquals(Algorithm.A128CBC, jwk.getAlgorithm());
        assertEquals(KEY_ID, jwk.getId());
        assertNull(jwk.getRsaKeyPair());
        assertArrayEquals(SECRET_KEY.getEncoded(), jwk.getSecretKey().getEncoded());
        assertEquals(Type.oct, jwk.getType());
        assertEquals(Usage.enc, jwk.getUsage());
        assertNull(jwk.getKeyOps());
        final String json = jwk.toJSONString();
        assertNotNull(json);
        
        final JsonWebKey joJwk = new JsonWebKey(new JSONObject(json));
        assertEquals(jwk.isExtractable(), joJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), joJwk.getAlgorithm());
        assertEquals(jwk.getId(), joJwk.getId());
        assertNull(joJwk.getRsaKeyPair());
        assertArrayEquals(jwk.getSecretKey().getEncoded(), joJwk.getSecretKey().getEncoded());
        assertEquals(jwk.getType(), joJwk.getType());
        assertEquals(jwk.getUsage(), joJwk.getUsage());
        assertEquals(jwk.getKeyOps(), joJwk.getKeyOps());
        final String joJson = joJwk.toJSONString();
        assertNotNull(joJson);
        assertEquals(json, joJson);
    }
    
    @Test
    public void octKeyOpsCtor() throws MslCryptoException, MslEncodingException, JSONException {
        final JsonWebKey jwk = new JsonWebKey(ENCRYPT_DECRYPT, Algorithm.A128CBC, EXTRACTABLE, KEY_ID, SECRET_KEY);
        assertEquals(EXTRACTABLE, jwk.isExtractable());
        assertEquals(Algorithm.A128CBC, jwk.getAlgorithm());
        assertEquals(KEY_ID, jwk.getId());
        assertNull(jwk.getRsaKeyPair());
        assertArrayEquals(SECRET_KEY.getEncoded(), jwk.getSecretKey().getEncoded());
        assertEquals(Type.oct, jwk.getType());
        assertNull(jwk.getUsage());
        assertEquals(ENCRYPT_DECRYPT, jwk.getKeyOps());
        final String json = jwk.toJSONString();
        assertNotNull(json);
        
        final JsonWebKey joJwk = new JsonWebKey(new JSONObject(json));
        assertEquals(jwk.isExtractable(), joJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), joJwk.getAlgorithm());
        assertEquals(jwk.getId(), joJwk.getId());
        assertNull(joJwk.getRsaKeyPair());
        assertArrayEquals(jwk.getSecretKey().getEncoded(), joJwk.getSecretKey().getEncoded());
        assertEquals(jwk.getType(), joJwk.getType());
        assertEquals(jwk.getUsage(), joJwk.getUsage());
        assertEquals(jwk.getKeyOps(), joJwk.getKeyOps());
        final String joJson = joJwk.toJSONString();
        assertNotNull(joJson);
        // This test will not always pass since the key operations are
        // unordered.
        //assertEquals(json, joJson);
    }
    
    @Test
    public void octUsageJson() throws JSONException {
        final JsonWebKey jwk = new JsonWebKey(Usage.wrap, Algorithm.A128KW, EXTRACTABLE, KEY_ID, SECRET_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        assertEquals(EXTRACTABLE, jo.optBoolean(KEY_EXTRACTABLE));
        assertEquals(Algorithm.A128KW.name(), jo.getString(KEY_ALGORITHM));
        assertEquals(KEY_ID, jo.getString(KEY_KEY_ID));
        assertEquals(Type.oct.name(), jo.getString(KEY_TYPE));
        assertEquals(Usage.wrap.name(), jo.getString(KEY_USAGE));
        assertFalse(jo.has(KEY_KEY_OPS));
        
        assertFalse(jo.has(KEY_MODULUS));
        assertFalse(jo.has(KEY_PUBLIC_EXPONENT));
        assertFalse(jo.has(KEY_PRIVATE_EXPONENT));
        
        final String key = JsonUtils.b64urlEncode(SECRET_KEY.getEncoded());
        
        assertEquals(key, jo.getString(KEY_KEY));
    }
    
    @Test
    public void octKeyOpsJson() throws JSONException {
        final JsonWebKey jwk = new JsonWebKey(WRAP_UNWRAP, Algorithm.A128KW, EXTRACTABLE, KEY_ID, SECRET_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        assertEquals(EXTRACTABLE, jo.optBoolean(KEY_EXTRACTABLE));
        assertEquals(Algorithm.A128KW.name(), jo.getString(KEY_ALGORITHM));
        assertEquals(KEY_ID, jo.getString(KEY_KEY_ID));
        assertEquals(Type.oct.name(), jo.getString(KEY_TYPE));
        assertFalse(jo.has(KEY_USAGE));
        assertTrue(JsonUtils.equalSets(JA_WRAP_UNWRAP, jo.getJSONArray(KEY_KEY_OPS)));
        
        assertFalse(jo.has(KEY_MODULUS));
        assertFalse(jo.has(KEY_PUBLIC_EXPONENT));
        assertFalse(jo.has(KEY_PRIVATE_EXPONENT));
        
        final String key = JsonUtils.b64urlEncode(SECRET_KEY.getEncoded());
        
        assertEquals(key, jo.getString(KEY_KEY));
    }
    
    @Test
    public void octNullCtor() throws MslCryptoException, MslEncodingException, JSONException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        assertFalse(jwk.isExtractable());
        assertNull(jwk.getAlgorithm());
        assertNull(jwk.getId());
        assertNull(jwk.getRsaKeyPair());
        assertArrayEquals(SECRET_KEY.getEncoded(), jwk.getSecretKey().getEncoded());
        assertEquals(Type.oct, jwk.getType());
        assertNull(jwk.getUsage());
        assertNull(jwk.getKeyOps());
        final String json = jwk.toJSONString();
        assertNotNull(json);
        
        final JsonWebKey joJwk = new JsonWebKey(new JSONObject(json));
        assertEquals(jwk.isExtractable(), joJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), joJwk.getAlgorithm());
        assertEquals(jwk.getId(), joJwk.getId());
        assertNull(joJwk.getRsaKeyPair());
        assertArrayEquals(jwk.getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded(), joJwk.getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded());
        assertEquals(jwk.getType(), joJwk.getType());
        assertEquals(jwk.getUsage(), joJwk.getUsage());
        assertEquals(jwk.getKeyOps(), joJwk.getKeyOps());
        final String joJson = joJwk.toJSONString();
        assertNotNull(joJson);
        assertEquals(json, joJson);
    }
    
    @Test
    public void octNullJson() throws JSONException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        assertFalse(jo.getBoolean(KEY_EXTRACTABLE));
        assertFalse(jo.has(KEY_ALGORITHM));
        assertFalse(jo.has(KEY_KEY_ID));
        assertEquals(Type.oct.name(), jo.getString(KEY_TYPE));
        assertFalse(jo.has(KEY_USAGE));
        assertFalse(jo.has(KEY_KEY_OPS));
        
        assertFalse(jo.has(KEY_MODULUS));
        assertFalse(jo.has(KEY_PUBLIC_EXPONENT));
        assertFalse(jo.has(KEY_PRIVATE_EXPONENT));
        
        final String key = JsonUtils.b64urlEncode(SECRET_KEY.getEncoded());
        
        assertEquals(key, jo.getString(KEY_KEY));
    }
    
    public void usageOnly() throws JSONException, MslCryptoException, MslEncodingException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.put(KEY_USAGE, Usage.enc.name());
        
        final JsonWebKey joJwk = new JsonWebKey(jo);
        assertEquals(Usage.enc, joJwk.getUsage());
        assertNull(joJwk.getKeyOps());
    }
    
    public void keyOpsOnly() throws JSONException, MslCryptoException, MslEncodingException {
        final JsonWebKey jwk = new JsonWebKey(NULL_KEYOPS, null, false, null, SECRET_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.put(KEY_KEY_OPS, JA_ENCRYPT_DECRYPT);
        
        final JsonWebKey joJwk = new JsonWebKey(jo);
        assertNull(joJwk.getUsage());
        assertEquals(new HashSet<KeyOp>(Arrays.asList(KeyOp.encrypt, KeyOp.decrypt)), joJwk.getKeyOps());
    }
    
    @Test(expected = MslInternalException.class)
    public void octCtorMismatchedAlgo() {
        new JsonWebKey(NULL_USAGE, Algorithm.RSA1_5, false, null, SECRET_KEY);
    }
    
    @Test
    public void missingType() throws JSONException, MslCryptoException, MslEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.remove(KEY_TYPE);
        
        new JsonWebKey(jo);
    }
    
    @Test
    public void invalidType() throws MslCryptoException, MslEncodingException, JSONException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_JWK_TYPE);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.put(KEY_TYPE, "x");
        
        new JsonWebKey(jo);
    }
    
    @Test
    public void invalidUsage() throws MslCryptoException, MslEncodingException, JSONException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_JWK_USAGE);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.put(KEY_USAGE, "x");
        
        new JsonWebKey(jo);
    }
    
    @Test
    public void invalidKeyOp() throws JSONException, MslCryptoException, MslEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_JWK_KEYOP);

        final JsonWebKey jwk = new JsonWebKey(NULL_KEYOPS, null, false, null, SECRET_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.put(KEY_KEY_OPS, new JSONArray(Arrays.asList(KeyOp.encrypt.name(), "x", KeyOp.decrypt.name())));
        
        new JsonWebKey(jo);
    }
    
    @Test
    public void invalidAlgorithm() throws MslCryptoException, MslEncodingException, JSONException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_JWK_ALGORITHM);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.put(KEY_ALGORITHM, "x");
        
        new JsonWebKey(jo);
    }
    
    @Test
    public void missingExtractable() throws JSONException, MslCryptoException, MslEncodingException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final String json = jwk.toJSONString();
        final JSONObject jo = new JSONObject(json);
        
        assertNotNull(jo.remove(KEY_EXTRACTABLE));
        
        final JsonWebKey joJwk = new JsonWebKey(jo);
        assertEquals(jwk.isExtractable(), joJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), joJwk.getAlgorithm());
        assertEquals(jwk.getId(), joJwk.getId());
        assertNull(joJwk.getRsaKeyPair());
        assertArrayEquals(jwk.getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded(), joJwk.getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded());
        assertEquals(jwk.getType(), joJwk.getType());
        assertEquals(jwk.getUsage(), joJwk.getUsage());
        final String joJson = joJwk.toJSONString();
        assertNotNull(joJson);
        assertEquals(json, joJson);
    }
        
    @Test
    public void invalidExtractable() throws MslEncodingException, JSONException, MslCryptoException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.put(KEY_EXTRACTABLE, "x");
        
        new JsonWebKey(jo);
    }
    
    @Test
    public void missingKey() throws MslCryptoException, MslEncodingException, JSONException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.remove(KEY_KEY);
        
        new JsonWebKey(jo);
    }
    
    @Test
    public void emptyKey() throws MslCryptoException, MslEncodingException, JSONException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.put(KEY_KEY, "");
        
        new JsonWebKey(jo);
    }
    
    @Test
    public void missingModulus() throws MslCryptoException, MslEncodingException, JSONException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.remove(KEY_MODULUS);
        
        new JsonWebKey(jo);
    }
    
    @Test
    public void emptyModulus() throws MslCryptoException, MslEncodingException, JSONException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.put(KEY_MODULUS, "");
        
        new JsonWebKey(jo);
    }
    
    @Test
    public void missingExponents() throws MslCryptoException, MslEncodingException, JSONException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.remove(KEY_PUBLIC_EXPONENT);
        jo.remove(KEY_PRIVATE_EXPONENT);
        
        new JsonWebKey(jo);
    }
    
    @Test
    public void emptyPublicExponent() throws MslCryptoException, MslEncodingException, JSONException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.put(KEY_PUBLIC_EXPONENT, "");
        
        new JsonWebKey(jo);
    }

    // This unit test no longer passes because
    // DatatypeConverter.parseBase64Binary() does not error when given invalid
    // Base64 encoded data.
    @Ignore
    @Test
    public void invalidPublicExpontent() throws MslCryptoException, MslEncodingException, JSONException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.put(KEY_PUBLIC_EXPONENT, "x");
        
        new JsonWebKey(jo);
    }
    
    @Test
    public void emptyPrivateExponent() throws MslCryptoException, MslEncodingException, JSONException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.put(KEY_PRIVATE_EXPONENT, "");
        
        new JsonWebKey(jo);
    }
    
    // This unit test no longer passes because
    // DatatypeConverter.parseBase64Binary() does not error when given invalid
    // Base64 encoded data.
    @Ignore
    @Test
    public void invalidPrivateExponent() throws MslCryptoException, MslEncodingException, JSONException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final JSONObject jo = new JSONObject(jwk.toJSONString());
        
        jo.put(KEY_PRIVATE_EXPONENT, "x");
        
        new JsonWebKey(jo);
    }
}
