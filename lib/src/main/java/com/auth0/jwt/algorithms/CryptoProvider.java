public class CryptoProvider {
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
