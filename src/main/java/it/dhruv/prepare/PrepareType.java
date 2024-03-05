package it.dhruv.prepare;

public enum PrepareType {
  Deterministic(0),
  Randomized(32);

  private final int value;

  private PrepareType(int value) {
    this.value = value;
  }

  public int getValue() {
    return value;
  }
}
