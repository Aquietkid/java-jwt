package com.auth0.jwt.algorithms;

import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class RSA512Factory implements AlgorithmFactory {

    private RSAKeyProvider rsaKeyProvider;

    public RSA512Factory(RSAKeyProvider rsaKeyProvider) {
        this.rsaKeyProvider = rsaKeyProvider;
    }

    public RSA512Factory(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        this.rsaKeyProvider = RSAAlgorithm.providerForKeys(publicKey, privateKey);
    }

    public RSA512Factory(RSAKey key) {
        RSAPublicKey publicKey = key instanceof RSAPublicKey ? (RSAPublicKey) key : null;
        RSAPrivateKey privateKey = key instanceof RSAPrivateKey ? (RSAPrivateKey) key : null;
        this.rsaKeyProvider = RSAAlgorithm.providerForKeys(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA512withRSA. Tokens specify this as "RS512".
     *
     * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
     * @return a valid createRSA512 Algorithm.
     * @throws IllegalArgumentException if the Key Provider is null.
     */
    public static Algorithm createRSA512(RSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new RSAAlgorithm("RS512", "SHA512withRSA", keyProvider);
    }

    /**
     * Creates a new Algorithm instance using SHA512withRSA. Tokens specify this as "RS512".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid createRSA512 Algorithm.
     * @throws IllegalArgumentException if both provided Keys are null.
     */
    public static Algorithm createRSA512(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return new RSA512Factory(RSAAlgorithm.providerForKeys(publicKey, privateKey)).create();
    }

    /**
     * Creates a new Algorithm instance using SHA512withRSA. Tokens specify this as "RS512".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid createRSA512 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     */
    public static Algorithm createRSA512(RSAKey key) throws IllegalArgumentException {
        RSAPublicKey publicKey = key instanceof RSAPublicKey ? (RSAPublicKey) key : null;
        RSAPrivateKey privateKey = key instanceof RSAPrivateKey ? (RSAPrivateKey) key : null;
        return new RSA512Factory(publicKey, privateKey).create();
    }

    @Override
    public Algorithm create() {
        return new RSAAlgorithm("RS512", "SHA512withRSA", this.rsaKeyProvider);
    }
}