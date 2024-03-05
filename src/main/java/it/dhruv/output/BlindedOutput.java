package it.dhruv.output;

import java.math.BigInteger;

public class BlindedOutput {
  private byte[] blindedMsg;
  private BigInteger blindingFactor;

  public BlindedOutput(byte[] blindedMsg, BigInteger blindingFactor) {
    this.blindedMsg = blindedMsg;
    this.blindingFactor = blindingFactor;
  }

  public byte[] getBlindedMsg() {
    return blindedMsg;
  }

  public void setBlindedMsg(byte[] blindedMsg) {
    this.blindedMsg = blindedMsg;
  }

  public BigInteger getBlindingFactor() {
    return blindingFactor;
  }

  public void setBlindingFactor(BigInteger blindingFactor) {
    this.blindingFactor = blindingFactor;
  }
}
