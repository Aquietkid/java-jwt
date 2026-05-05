package com.auth0.jwt.algorithms;

import com.auth0.jwt.interfaces.ECDSAKeyProvider;

import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class ECDSA384Factory implements AlgorithmFactory {

    private ECDSAKeyProvider ecdsaKeyProvider;

    public ECDSA384Factory(ECDSAKeyProvider ecdsaKeyProvider) {
        this.ecdsaKeyProvider = ecdsaKeyProvider;
    }

    public ECDSA384Factory(ECPublicKey publicKey, ECPrivateKey privateKey) {
        this.ecdsaKeyProvider = ECDSAAlgorithm.providerForKeys(publicKey, privateKey);
    }

    public ECDSA384Factory(ECKey key) {
        ECPublicKey publicKey = key instanceof ECPublicKey ? (ECPublicKey) key : null;
        ECPrivateKey privateKey = key instanceof ECPrivateKey ? (ECPrivateKey) key : null;
        this.ecdsaKeyProvider = ECDSAAlgorithm.providerForKeys(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA384withECDSA. Tokens specify this as "ES384".
     *
     * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
     * @return a valid createECDSA384 Algorithm.
     * @throws IllegalArgumentException if the Key Provider is null.
     */
    public static Algorithm createECDSA384(ECDSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new ECDSAAlgorithm("ES384", "SHA384withECDSA", 48, keyProvider);
    }

    /**
     * Creates a new Algorithm instance using SHA384withECDSA. Tokens specify this as "ES384".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid createECDSA384 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     */
    public static Algorithm createECDSA384(ECPublicKey publicKey, ECPrivateKey privateKey) throws IllegalArgumentException {
        return new ECDSA384Factory(ECDSAAlgorithm.providerForKeys(publicKey, privateKey)).create();
    }

    /**
     * Creates a new Algorithm instance using SHA384withECDSA. Tokens specify this as "ES384".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid createECDSA384 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     */
    public static Algorithm createECDSA384(ECKey key) throws IllegalArgumentException {
        ECPublicKey publicKey = key instanceof ECPublicKey ? (ECPublicKey) key : null;
        ECPrivateKey privateKey = key instanceof ECPrivateKey ? (ECPrivateKey) key : null;
        return new ECDSA384Factory(publicKey, privateKey).create();
    }

    @Override
    public Algorithm create() {
        return new ECDSAAlgorithm("ES384", "SHA384withECDSA", 48, this.ecdsaKeyProvider);
    }
}