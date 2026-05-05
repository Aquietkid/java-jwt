package com.auth0.jwt.algorithms;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;


/**
 * Abstraction over JCA cryptographic operations used by JWT signing and
 * verification. Implementations must be thread-safe.
 */
public interface CryptoProvider {
    boolean verifySignatureFor(String algorithm, byte[] secretBytes,
            String header, String payload, byte[] signatureBytes)
            throws NoSuchAlgorithmException, InvalidKeyException;

    boolean verifySignatureFor(String algorithm, PublicKey publicKey,
            String header, String payload, byte[] signatureBytes)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;

    byte[] createSignatureFor(String algorithm, byte[] secretBytes,
            byte[] headerBytes, byte[] payloadBytes)
            throws NoSuchAlgorithmException, InvalidKeyException;

    byte[] createSignatureFor(String algorithm, PrivateKey privateKey,
            byte[] headerBytes, byte[] payloadBytes)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;

    // Retain legacy overloads until deprecated sign(byte[]) is removed
    byte[] createSignatureFor(String algorithm, byte[] secretBytes,
            byte[] contentBytes)
            throws NoSuchAlgorithmException, InvalidKeyException;

    byte[] createSignatureFor(String algorithm, PrivateKey privateKey,
            byte[] contentBytes)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;
}
