package it.dhruv;

import it.dhruv.prepare.PrepareType;

public enum BlindRsaParams {
  RSABSSA_SHA384_PSSZERO_Deterministic(PrepareType.Deterministic, 0),
  RSABSSA_SHA384_PSSZERO_Randomized(PrepareType.Randomized, 0),
  RSABSSA_SHA384_PSS_Deterministic(PrepareType.Deterministic, 48),
  RSABSSA_SHA384_PSS_Randomized(PrepareType.Randomized, 48);

  private final PrepareType prepareType;
  private final int saltLength;

  private BlindRsaParams(PrepareType prepareType, int saltLength) {
    this.prepareType = prepareType;
    this.saltLength = saltLength;
  }

  public PrepareType getPrepareType() {
    return prepareType;
  }

  public int getSaltLength() {
    return saltLength;
  }
}
