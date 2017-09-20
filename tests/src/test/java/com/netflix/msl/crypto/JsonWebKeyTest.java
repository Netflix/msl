/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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
import org.junit.AfterClass;
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
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslArray;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

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
    
    // Expected key operations MSL arrays.
    /** Sign/verify. */
    private static final MslArray MA_SIGN_VERIFY = new MslArray(Arrays.asList(KeyOp.sign.name(), KeyOp.verify.name()).toArray());
    /** Encrypt/decrypt. */
    private static final MslArray MA_ENCRYPT_DECRYPT = new MslArray(Arrays.asList(KeyOp.encrypt.name(), KeyOp.verify.name()).toArray());
    /** Wrap/unwrap. */
    private static final MslArray MA_WRAP_UNWRAP = new MslArray(Arrays.asList(KeyOp.wrapKey.name(), KeyOp.unwrapKey.name()).toArray());
    
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
    
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Encoder format. */
    private static MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws NoSuchAlgorithmException, MslEncodingException, MslCryptoException {
        Security.addProvider(new BouncyCastleProvider());
        
        final MslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
        
        final KeyPairGenerator keypairGenerator = KeyPairGenerator.getInstance("RSA");
        keypairGenerator.initialize(512);
        final KeyPair keypair = keypairGenerator.generateKeyPair();
        PRIVATE_KEY = (RSAPrivateKey)keypair.getPrivate();
        PUBLIC_KEY = (RSAPublicKey)keypair.getPublic();
        
        final byte[] keydata = new byte[16];
        random.nextBytes(keydata);
        SECRET_KEY = new SecretKeySpec(keydata, JcaAlgorithm.AES);
    }
    
    @AfterClass
    public static void teardown() {
        encoder = null;
    }
    
    @Test
    public void rsaUsageCtor() throws MslCryptoException, MslEncodingException, MslEncoderException {
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
        final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
        assertEquals(jwk.isExtractable(), moJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
        assertEquals(jwk.getId(), moJwk.getId());
        final KeyPair moKeypair = moJwk.getRsaKeyPair();
        assertNotNull(moKeypair);
        final RSAPublicKey moPubkey = (RSAPublicKey)moKeypair.getPublic();
        assertEquals(pubkey.getModulus(), moPubkey.getModulus());
        assertEquals(pubkey.getPublicExponent(), moPubkey.getPublicExponent());
        final RSAPrivateKey moPrivkey = (RSAPrivateKey)moKeypair.getPrivate();
        assertEquals(privkey.getModulus(), moPrivkey.getModulus());
        assertEquals(privkey.getPrivateExponent(), moPrivkey.getPrivateExponent());
        assertNull(moJwk.getSecretKey());
        assertEquals(jwk.getType(), moJwk.getType());
        assertEquals(jwk.getUsage(), moJwk.getUsage());
        assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
        final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void rsaKeyOpsCtor() throws MslCryptoException, MslEncodingException, MslEncoderException {
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
        final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
        assertEquals(jwk.isExtractable(), moJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
        assertEquals(jwk.getId(), moJwk.getId());
        final KeyPair moKeypair = moJwk.getRsaKeyPair();
        assertNotNull(moKeypair);
        final RSAPublicKey moPubkey = (RSAPublicKey)moKeypair.getPublic();
        assertEquals(pubkey.getModulus(), moPubkey.getModulus());
        assertEquals(pubkey.getPublicExponent(), moPubkey.getPublicExponent());
        final RSAPrivateKey moPrivkey = (RSAPrivateKey)moKeypair.getPrivate();
        assertEquals(privkey.getModulus(), moPrivkey.getModulus());
        assertEquals(privkey.getPrivateExponent(), moPrivkey.getPrivateExponent());
        assertNull(moJwk.getSecretKey());
        assertEquals(jwk.getType(), moJwk.getType());
        assertEquals(jwk.getUsage(), moJwk.getUsage());
        assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
        final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        // This test will not always pass since the key operations are
        // unordered.
        //assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void rsaUsageJson() throws MslEncoderException {
        final JsonWebKey jwk = new JsonWebKey(Usage.sig, Algorithm.RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        assertEquals(EXTRACTABLE, mo.optBoolean(KEY_EXTRACTABLE));
        assertEquals(Algorithm.RSA1_5.name(), mo.getString(KEY_ALGORITHM));
        assertEquals(KEY_ID, mo.getString(KEY_KEY_ID));
        assertEquals(Type.rsa.name(), mo.getString(KEY_TYPE));
        assertEquals(Usage.sig.name(), mo.getString(KEY_USAGE));
        assertFalse(mo.has(KEY_KEY_OPS));
        
        final String modulus = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
        final String pubexp = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getPublicExponent()));
        final String privexp = MslEncoderUtils.b64urlEncode(bi2bytes(PRIVATE_KEY.getPrivateExponent()));
        
        assertEquals(modulus, mo.getString(KEY_MODULUS));
        assertEquals(pubexp, mo.getString(KEY_PUBLIC_EXPONENT));
        assertEquals(privexp, mo.getString(KEY_PRIVATE_EXPONENT));
        
        assertFalse(mo.has(KEY_KEY));
    }
    
    @Test
    public void rsaKeyOpsJson() throws MslEncoderException {
        final JsonWebKey jwk = new JsonWebKey(SIGN_VERIFY, Algorithm.RSA1_5, EXTRACTABLE, KEY_ID, PUBLIC_KEY, PRIVATE_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        assertEquals(EXTRACTABLE, mo.optBoolean(KEY_EXTRACTABLE));
        assertEquals(Algorithm.RSA1_5.name(), mo.getString(KEY_ALGORITHM));
        assertEquals(KEY_ID, mo.getString(KEY_KEY_ID));
        assertEquals(Type.rsa.name(), mo.getString(KEY_TYPE));
        assertFalse(mo.has(KEY_USAGE));
        assertTrue(MslEncoderUtils.equalSets(MA_SIGN_VERIFY, mo.getMslArray(KEY_KEY_OPS)));
        
        final String modulus = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
        final String pubexp = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getPublicExponent()));
        final String privexp = MslEncoderUtils.b64urlEncode(bi2bytes(PRIVATE_KEY.getPrivateExponent()));
        
        assertEquals(modulus, mo.getString(KEY_MODULUS));
        assertEquals(pubexp, mo.getString(KEY_PUBLIC_EXPONENT));
        assertEquals(privexp, mo.getString(KEY_PRIVATE_EXPONENT));
        
        assertFalse(mo.has(KEY_KEY));
    }
    
    @Test
    public void rsaNullCtorPublic() throws MslCryptoException, MslEncodingException, MslEncoderException {
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
        final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
        assertEquals(jwk.isExtractable(), moJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
        assertEquals(jwk.getId(), moJwk.getId());
        final KeyPair moKeypair = moJwk.getRsaKeyPair();
        assertNotNull(moKeypair);
        final RSAPublicKey moPubkey = (RSAPublicKey)moKeypair.getPublic();
        assertEquals(pubkey.getModulus(), moPubkey.getModulus());
        assertEquals(pubkey.getPublicExponent(), moPubkey.getPublicExponent());
        final RSAPrivateKey moPrivkey = (RSAPrivateKey)moKeypair.getPrivate();
        assertNull(moPrivkey);
        assertNull(moJwk.getSecretKey());
        assertEquals(jwk.getType(), moJwk.getType());
        assertEquals(jwk.getUsage(), moJwk.getUsage());
        assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
        final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void rsaNullCtorPrivate() throws MslCryptoException, MslEncodingException, MslEncoderException {
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
        final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
        assertEquals(jwk.isExtractable(), moJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
        assertEquals(jwk.getId(), moJwk.getId());
        final KeyPair moKeypair = moJwk.getRsaKeyPair();
        assertNotNull(moKeypair);
        final RSAPublicKey moPubkey = (RSAPublicKey)moKeypair.getPublic();
        assertNull(moPubkey);
        final RSAPrivateKey moPrivkey = (RSAPrivateKey)moKeypair.getPrivate();
        assertEquals(privkey.getModulus(), moPrivkey.getModulus());
        assertEquals(privkey.getPrivateExponent(), moPrivkey.getPrivateExponent());
        assertNull(moJwk.getSecretKey());
        assertEquals(jwk.getType(), moJwk.getType());
        assertEquals(jwk.getUsage(), moJwk.getUsage());
        assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
        final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void rsaNullJsonPublic() throws MslEncoderException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, null);
        final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        assertFalse(mo.getBoolean(KEY_EXTRACTABLE));
        assertFalse(mo.has(KEY_ALGORITHM));
        assertFalse(mo.has(KEY_KEY_ID));
        assertEquals(Type.rsa.name(), mo.getString(KEY_TYPE));
        assertFalse(mo.has(KEY_USAGE));
        assertFalse(mo.has(KEY_KEY_OPS));
        
        final String modulus = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
        final String pubexp = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getPublicExponent()));
        
        assertEquals(modulus, mo.getString(KEY_MODULUS));
        assertEquals(pubexp, mo.getString(KEY_PUBLIC_EXPONENT));
        assertFalse(mo.has(KEY_PRIVATE_EXPONENT));

        assertFalse(mo.has(KEY_KEY));
    }
    
    @Test
    public void rsaNullJsonPrivate() throws MslEncoderException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, null, PRIVATE_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        assertFalse(mo.getBoolean(KEY_EXTRACTABLE));
        assertFalse(mo.has(KEY_ALGORITHM));
        assertFalse(mo.has(KEY_KEY_ID));
        assertEquals(Type.rsa.name(), mo.getString(KEY_TYPE));
        assertFalse(mo.has(KEY_USAGE));
        assertFalse(mo.has(KEY_KEY_OPS));
        
        final String modulus = MslEncoderUtils.b64urlEncode(bi2bytes(PUBLIC_KEY.getModulus()));
        final String privexp = MslEncoderUtils.b64urlEncode(bi2bytes(PRIVATE_KEY.getPrivateExponent()));
        
        assertEquals(modulus, mo.getString(KEY_MODULUS));
        assertFalse(mo.has(KEY_PUBLIC_EXPONENT));
        assertEquals(privexp, mo.getString(KEY_PRIVATE_EXPONENT));

        assertFalse(mo.has(KEY_KEY));
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
    public void octUsageCtor() throws MslCryptoException, MslEncodingException, MslEncoderException {
        final JsonWebKey jwk = new JsonWebKey(Usage.enc, Algorithm.A128CBC, EXTRACTABLE, KEY_ID, SECRET_KEY);
        assertEquals(EXTRACTABLE, jwk.isExtractable());
        assertEquals(Algorithm.A128CBC, jwk.getAlgorithm());
        assertEquals(KEY_ID, jwk.getId());
        assertNull(jwk.getRsaKeyPair());
        assertArrayEquals(SECRET_KEY.getEncoded(), jwk.getSecretKey().getEncoded());
        assertEquals(Type.oct, jwk.getType());
        assertEquals(Usage.enc, jwk.getUsage());
        assertNull(jwk.getKeyOps());
        final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
        assertEquals(jwk.isExtractable(), moJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
        assertEquals(jwk.getId(), moJwk.getId());
        assertNull(moJwk.getRsaKeyPair());
        assertArrayEquals(jwk.getSecretKey().getEncoded(), moJwk.getSecretKey().getEncoded());
        assertEquals(jwk.getType(), moJwk.getType());
        assertEquals(jwk.getUsage(), moJwk.getUsage());
        assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
        final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void octKeyOpsCtor() throws MslCryptoException, MslEncodingException, MslEncoderException {
        final JsonWebKey jwk = new JsonWebKey(ENCRYPT_DECRYPT, Algorithm.A128CBC, EXTRACTABLE, KEY_ID, SECRET_KEY);
        assertEquals(EXTRACTABLE, jwk.isExtractable());
        assertEquals(Algorithm.A128CBC, jwk.getAlgorithm());
        assertEquals(KEY_ID, jwk.getId());
        assertNull(jwk.getRsaKeyPair());
        assertArrayEquals(SECRET_KEY.getEncoded(), jwk.getSecretKey().getEncoded());
        assertEquals(Type.oct, jwk.getType());
        assertNull(jwk.getUsage());
        assertEquals(ENCRYPT_DECRYPT, jwk.getKeyOps());
        final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
        assertEquals(jwk.isExtractable(), moJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
        assertEquals(jwk.getId(), moJwk.getId());
        assertNull(moJwk.getRsaKeyPair());
        assertArrayEquals(jwk.getSecretKey().getEncoded(), moJwk.getSecretKey().getEncoded());
        assertEquals(jwk.getType(), moJwk.getType());
        assertEquals(jwk.getUsage(), moJwk.getUsage());
        assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
        final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        // This test will not always pass since the key operations are
        // unordered.
        //assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void octUsageJson() throws MslEncoderException {
        final JsonWebKey jwk = new JsonWebKey(Usage.wrap, Algorithm.A128KW, EXTRACTABLE, KEY_ID, SECRET_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        assertEquals(EXTRACTABLE, mo.optBoolean(KEY_EXTRACTABLE));
        assertEquals(Algorithm.A128KW.name(), mo.getString(KEY_ALGORITHM));
        assertEquals(KEY_ID, mo.getString(KEY_KEY_ID));
        assertEquals(Type.oct.name(), mo.getString(KEY_TYPE));
        assertEquals(Usage.wrap.name(), mo.getString(KEY_USAGE));
        assertFalse(mo.has(KEY_KEY_OPS));
        
        assertFalse(mo.has(KEY_MODULUS));
        assertFalse(mo.has(KEY_PUBLIC_EXPONENT));
        assertFalse(mo.has(KEY_PRIVATE_EXPONENT));
        
        final String key = MslEncoderUtils.b64urlEncode(SECRET_KEY.getEncoded());
        
        assertEquals(key, mo.getString(KEY_KEY));
    }
    
    @Test
    public void octKeyOpsJson() throws MslEncoderException {
        final JsonWebKey jwk = new JsonWebKey(WRAP_UNWRAP, Algorithm.A128KW, EXTRACTABLE, KEY_ID, SECRET_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        assertEquals(EXTRACTABLE, mo.optBoolean(KEY_EXTRACTABLE));
        assertEquals(Algorithm.A128KW.name(), mo.getString(KEY_ALGORITHM));
        assertEquals(KEY_ID, mo.getString(KEY_KEY_ID));
        assertEquals(Type.oct.name(), mo.getString(KEY_TYPE));
        assertFalse(mo.has(KEY_USAGE));
        assertTrue(MslEncoderUtils.equalSets(MA_WRAP_UNWRAP, mo.getMslArray(KEY_KEY_OPS)));
        
        assertFalse(mo.has(KEY_MODULUS));
        assertFalse(mo.has(KEY_PUBLIC_EXPONENT));
        assertFalse(mo.has(KEY_PRIVATE_EXPONENT));
        
        final String key = MslEncoderUtils.b64urlEncode(SECRET_KEY.getEncoded());
        
        assertEquals(key, mo.getString(KEY_KEY));
    }
    
    @Test
    public void octNullCtor() throws MslCryptoException, MslEncodingException, MslEncoderException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        assertFalse(jwk.isExtractable());
        assertNull(jwk.getAlgorithm());
        assertNull(jwk.getId());
        assertNull(jwk.getRsaKeyPair());
        assertArrayEquals(SECRET_KEY.getEncoded(), jwk.getSecretKey().getEncoded());
        assertEquals(Type.oct, jwk.getType());
        assertNull(jwk.getUsage());
        assertNull(jwk.getKeyOps());
        final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final JsonWebKey moJwk = new JsonWebKey(encoder.parseObject(encode));
        assertEquals(jwk.isExtractable(), moJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
        assertEquals(jwk.getId(), moJwk.getId());
        assertNull(moJwk.getRsaKeyPair());
        assertArrayEquals(jwk.getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded(), moJwk.getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded());
        assertEquals(jwk.getType(), moJwk.getType());
        assertEquals(jwk.getUsage(), moJwk.getUsage());
        assertEquals(jwk.getKeyOps(), moJwk.getKeyOps());
        final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void octNullJson() throws MslEncoderException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        assertFalse(mo.getBoolean(KEY_EXTRACTABLE));
        assertFalse(mo.has(KEY_ALGORITHM));
        assertFalse(mo.has(KEY_KEY_ID));
        assertEquals(Type.oct.name(), mo.getString(KEY_TYPE));
        assertFalse(mo.has(KEY_USAGE));
        assertFalse(mo.has(KEY_KEY_OPS));
        
        assertFalse(mo.has(KEY_MODULUS));
        assertFalse(mo.has(KEY_PUBLIC_EXPONENT));
        assertFalse(mo.has(KEY_PRIVATE_EXPONENT));
        
        final String key = MslEncoderUtils.b64urlEncode(SECRET_KEY.getEncoded());
        
        assertEquals(key, mo.getString(KEY_KEY));
    }
    
    public void usageOnly() throws MslEncoderException, MslCryptoException, MslEncodingException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.put(KEY_USAGE, Usage.enc.name());
        
        final JsonWebKey moJwk = new JsonWebKey(mo);
        assertEquals(Usage.enc, moJwk.getUsage());
        assertNull(moJwk.getKeyOps());
    }
    
    public void keyOpsOnly() throws MslEncoderException, MslCryptoException, MslEncodingException {
        final JsonWebKey jwk = new JsonWebKey(NULL_KEYOPS, null, false, null, SECRET_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.put(KEY_KEY_OPS, MA_ENCRYPT_DECRYPT);
        
        final JsonWebKey moJwk = new JsonWebKey(mo);
        assertNull(moJwk.getUsage());
        assertEquals(new HashSet<KeyOp>(Arrays.asList(KeyOp.encrypt, KeyOp.decrypt)), moJwk.getKeyOps());
    }
    
    @Test(expected = MslInternalException.class)
    public void octCtorMismatchedAlgo() {
        new JsonWebKey(NULL_USAGE, Algorithm.RSA1_5, false, null, SECRET_KEY);
    }
    
    @Test
    public void missingType() throws MslEncoderException, MslCryptoException, MslEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.remove(KEY_TYPE);
        
        new JsonWebKey(mo);
    }
    
    @Test
    public void invalidType() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_JWK_TYPE);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.put(KEY_TYPE, "x");
        
        new JsonWebKey(mo);
    }
    
    @Test
    public void invalidUsage() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_JWK_USAGE);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.put(KEY_USAGE, "x");
        
        new JsonWebKey(mo);
    }
    
    @Test
    public void invalidKeyOp() throws MslEncoderException, MslCryptoException, MslEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_JWK_KEYOP);

        final JsonWebKey jwk = new JsonWebKey(NULL_KEYOPS, null, false, null, SECRET_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.put(KEY_KEY_OPS, new JSONArray(Arrays.asList(KeyOp.encrypt.name(), "x", KeyOp.decrypt.name()).toArray()));
        
        new JsonWebKey(mo);
    }
    
    @Test
    public void invalidAlgorithm() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_JWK_ALGORITHM);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.put(KEY_ALGORITHM, "x");
        
        new JsonWebKey(mo);
    }
    
    @Test
    public void missingExtractable() throws MslEncoderException, MslCryptoException, MslEncodingException {
        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final byte[] encode = jwk.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        assertNotNull(mo.remove(KEY_EXTRACTABLE));
        
        final JsonWebKey moJwk = new JsonWebKey(mo);
        assertEquals(jwk.isExtractable(), moJwk.isExtractable());
        assertEquals(jwk.getAlgorithm(), moJwk.getAlgorithm());
        assertEquals(jwk.getId(), moJwk.getId());
        assertNull(moJwk.getRsaKeyPair());
        assertArrayEquals(jwk.getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded(), moJwk.getSecretKey(SECRET_KEY.getAlgorithm()).getEncoded());
        assertEquals(jwk.getType(), moJwk.getType());
        assertEquals(jwk.getUsage(), moJwk.getUsage());
        final byte[] moEncode = moJwk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
        
    @Test
    public void invalidExtractable() throws MslEncodingException, MslEncoderException, MslCryptoException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.put(KEY_EXTRACTABLE, "x");
        
        new JsonWebKey(mo);
    }
    
    @Test
    public void missingKey() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.remove(KEY_KEY);
        
        new JsonWebKey(mo);
    }
    
    @Test
    public void emptyKey() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, SECRET_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.put(KEY_KEY, "");
        
        new JsonWebKey(mo);
    }
    
    @Test
    public void missingModulus() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.remove(KEY_MODULUS);
        
        new JsonWebKey(mo);
    }
    
    @Test
    public void emptyModulus() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.put(KEY_MODULUS, "");
        
        new JsonWebKey(mo);
    }
    
    @Test
    public void missingExponents() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.remove(KEY_PUBLIC_EXPONENT);
        mo.remove(KEY_PRIVATE_EXPONENT);
        
        new JsonWebKey(mo);
    }
    
    @Test
    public void emptyPublicExponent() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.put(KEY_PUBLIC_EXPONENT, "");
        
        new JsonWebKey(mo);
    }

    // This unit test no longer passes because
    // Base64.decode() does not error when given invalid
    // Base64 encoded data.
    @Ignore
    @Test
    public void invalidPublicExpontent() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.put(KEY_PUBLIC_EXPONENT, "x");
        
        new JsonWebKey(mo);
    }
    
    @Test
    public void emptyPrivateExponent() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.put(KEY_PRIVATE_EXPONENT, "");
        
        new JsonWebKey(mo);
    }
    
    // This unit test no longer passes because
    // Base64.decode() does not error when given invalid
    // Base64 encoded data.
    @Ignore
    @Test
    public void invalidPrivateExponent() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.INVALID_JWK_KEYDATA);

        final JsonWebKey jwk = new JsonWebKey(NULL_USAGE, null, false, null, PUBLIC_KEY, PRIVATE_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, jwk);
        
        mo.put(KEY_PRIVATE_EXPONENT, "x");
        
        new JsonWebKey(mo);
    }
}
