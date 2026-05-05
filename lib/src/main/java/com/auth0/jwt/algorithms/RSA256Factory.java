package com.auth0.jwt.algorithms;

import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class RSA256Factory implements AlgorithmFactory {

    private RSAKeyProvider rsaKeyProvider;

    public RSA256Factory(RSAKeyProvider rsaKeyProvider) {
        this.rsaKeyProvider = rsaKeyProvider;
    }

    public RSA256Factory(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        this.rsaKeyProvider = RSAAlgorithm.providerForKeys(publicKey, privateKey);
    }

    public RSA256Factory(RSAKey key) {
        RSAPublicKey publicKey = key instanceof RSAPublicKey ? (RSAPublicKey) key : null;
        RSAPrivateKey privateKey = key instanceof RSAPrivateKey ? (RSAPrivateKey) key : null;
        this.rsaKeyProvider = RSAAlgorithm.providerForKeys(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA256withRSA. Tokens specify this as "RS256".
     *
     * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
     * @return a valid createRSA256 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     */
    public static Algorithm createRSA256(RSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new RSAAlgorithm("RS256", "SHA256withRSA", keyProvider);
    }

    /**
     * Creates a new Algorithm instance using SHA256withRSA. Tokens specify this as "RS256".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid createRSA256 Algorithm.
     * @throws IllegalArgumentException if both provided Keys are null.
     */
    public static Algorithm createRSA256(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return new RSA256Factory(RSAAlgorithm.providerForKeys(publicKey, privateKey)).create();
    }

    /**
     * Creates a new Algorithm instance using SHA256withRSA. Tokens specify this as "RS256".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid createRSA256 Algorithm.
     * @throws IllegalArgumentException if the Key Provider is null.
     */
    public static Algorithm createRSA256(RSAKey key) throws IllegalArgumentException {
        RSAPublicKey publicKey = key instanceof RSAPublicKey ? (RSAPublicKey) key : null;
        RSAPrivateKey privateKey = key instanceof RSAPrivateKey ? (RSAPrivateKey) key : null;
        return new RSA256Factory(publicKey, privateKey).create();
    }

    @Override
    public Algorithm create() {
        return new RSAAlgorithm("RS256", "SHA256withRSA", this.rsaKeyProvider);
    }
}