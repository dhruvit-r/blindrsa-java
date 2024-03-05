package it.dhruv;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSABlindingFactorGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;

import it.dhruv.output.BlindedOutput;

public class BlindRsa {
  private BlindRsaParams blindRsaParams;
  private RSAKeyParameters publicKey;
  private RSAKeyParameters privateKey;

  public BlindRsa(BlindRsaParams blindRsaParams, RSAKeyParameters publicKey, RSAKeyParameters privateKey) {
    this.blindRsaParams = blindRsaParams;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  /**
   * Prepare the message for blinding.
   *
   * @param message The message to prepare
   * @return The prepared message
   */
  public byte[] prepare(byte[] message) {
    // Generate a random prefix
    int prefixLength = blindRsaParams.getPrepareType().getValue();
    byte[] prefix = new byte[prefixLength];
    SecureRandom random = new SecureRandom();
    random.nextBytes(prefix);

    // Concatenate the prefix and the message
    byte[] preparedMessage = new byte[prefixLength + message.length];
    System.arraycopy(prefix, 0, preparedMessage, 0, prefixLength);
    System.arraycopy(message, 0, preparedMessage, prefixLength, message.length);

    // Return the prepared message
    return preparedMessage;
  }

  /**
   * Blind the message.
   *
   * @param message The message to blind
   * @return The blinded message
   * @throws DataLengthException
   * @throws CryptoException
   */
  public BlindedOutput blind(byte[] message) throws DataLengthException, CryptoException {
    // Generate a random blinding factor
    RSABlindingFactorGenerator blindingFactorGenerator = new RSABlindingFactorGenerator();
    blindingFactorGenerator.init(publicKey);
    BigInteger blindingFactor = blindingFactorGenerator.generateBlindingFactor();

    // Init blinding parameters
    RSABlindingParameters params = new RSABlindingParameters(publicKey, blindingFactor);

    // Init blinding engine
    RSABlindingEngine blindingEngine = new RSABlindingEngine();
    blindingEngine.init(true, params);
    
    // Init PSS signer
    PSSSigner blindSigner = new PSSSigner(blindingEngine, new SHA384Digest(), blindRsaParams.getSaltLength());

    // Use the blinding signer to generate a blind message
    blindSigner.init(true, new ParametersWithRandom(params, new SecureRandom()));
    blindSigner.update(message, 0, message.length);
    byte[] blindMessage = blindSigner.generateSignature();
    
    // Return the blind message
    return new BlindedOutput(blindMessage, blindingFactor);
  }

  /**
   * Sign the blinded message.
   * 
   * @param blindedMessage The blinded message to sign
   * @return The signature
   * @throws DataLengthException
   * @throws CryptoException
   */
  public byte[] sign(byte[] blindedMessage) throws DataLengthException, CryptoException {
    // Sign the blinded data
    RSAEngine signerEngine = new RSAEngine();
    signerEngine.init(true, privateKey);
    byte[] blindedSig = signerEngine.processBlock(blindedMessage, 0, blindedMessage.length);

    // Unblind the signature
    signerEngine.init(false, publicKey);
    byte[] initialBlindedMessage = signerEngine.processBlock(blindedSig, 0, blindedSig.length);
    
    // Verify that the unblinded signature matches the original message
    if (!Arrays.equals(initialBlindedMessage, blindedMessage)) {
      throw new RuntimeException("Blind signature failed");
    }

    // Return the signature
    return blindedSig;
  }

  /**
   * Finalize the signature.
   *
   * @param preparedMessage The prepared message
   * @param blindedOutput The output from the blinding process
   * @param blindSignature The blind signature
   * @return
   */
  public byte[] finalize(byte[] preparedMessage, BlindedOutput blindedOutput, byte[] blindSignature) {
    int kLen = publicKey.getModulus().bitLength() / 8;

    // Check the length of the blind signature
    if (blindSignature.length != kLen) {
      throw new DataLengthException("Invalid signature length");
    }

    // Initialize blinding engine for unblinding
    RSABlindingEngine blindingEngine = new RSABlindingEngine();
    blindingEngine.init(false, new RSABlindingParameters(publicKey, blindedOutput.getBlindingFactor()));

    // Unblind the signature
    byte[] unblindedSignature = blindingEngine.processBlock(blindSignature, 0, blindSignature.length);

    // Verify the signature
    PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA384Digest(), blindRsaParams.getSaltLength());
    signer.init(false, publicKey);
    signer.update(preparedMessage, 0, preparedMessage.length);
    if (!signer.verifySignature(unblindedSignature)) {
      throw new RuntimeException("Invalid signature");
    }

    // Signature is valid, return it
    return unblindedSignature;
  }
}
