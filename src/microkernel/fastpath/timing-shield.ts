/**
 * Decision-Timing Side-Channel Shield
 * Enforces constant-time execution duration (clamped to 135 microseconds)
 * and sequence length padding (L = 128) to eliminate timing feature leakage.
 */
export class TimingShield {
  public static readonly TARGET_DURATION_NANOS: bigint = 135000n; // 135 microseconds
  public static readonly FIXED_SEQ_LENGTH: number = 128;

  /**
   * Pads execution from start timestamp up to the constant-time target duration
   */
  public static clampDuration(startTimeNanos: bigint, targetNanos: bigint = TimingShield.TARGET_DURATION_NANOS): void {
    let elapsed = process.hrtime.bigint() - startTimeNanos;
    while (elapsed < targetNanos) {
      // Busy spin / CPU pause emulation in user-space
      elapsed = process.hrtime.bigint() - startTimeNanos;
    }
  }

  /**
   * Clamps and zero-pads an input embedding array to exactly L = 128 tokens
   */
  public static padSequence(input: Float32Array, channels: number): Float32Array {
    const totalRequired = TimingShield.FIXED_SEQ_LENGTH * channels;
    const output = new Float32Array(totalRequired);
    const copyLen = Math.min(input.length, totalRequired);
    output.set(input.subarray(0, copyLen));
    return output;
  }
}
