# BlindRSA Java

This is a Java library that implements RSA Blind Signatures as described in RFC 9474.

Internally, it uses Bouncy Castle for the cryptographic operations.

It exposes a simple API to perform the four operations required for RSA Blind Signatures as described in the RFC:

```java
package it.dhruv;

public class BlindRsa {
  /**
   * Constructor for the BlindRsa class. It takes the parameters for the RSA
   * Blind Signature, the public key and/or the private key.
   */
  public BlindRsa(BlindRsaParams blindRsaParams, RSAKeyParameters publicKey, RSAKeyParameters privateKey);

  /**
   * Prepare the message for blinding.
   */
  public byte[] prepare(byte[] message);

  /**
   * Blind the message.
   */
  public BlindedOutput blind(byte[] message) throws DataLengthException, CryptoException;

  /**
   * Sign the blinded message.
   */
  public byte[] sign(byte[] blindedMessage) throws DataLengthException, CryptoException;

  /**
   * Finalize the signature.
   */
  public byte[] finalize(byte[] preparedMessage, BlindedOutput blindedOutput, byte[] blindSignature);

  /**
   * Verify the signature.
   */
  public boolean verify(byte[] preparedMessage, byte[] finalSignature);
}
```

