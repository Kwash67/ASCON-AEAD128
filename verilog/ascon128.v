/*
 * ascon128.v
 * 
 * Complete ASCON-AEAD128 Implementation in a Single File
 * 
 * Visualizing a state
 * word size = 64 bits unsigned integer
 * Si = word i within the state
 * State = S0 || S1 || S2 || S3 || S4
 * State size = 64 x 5 = 320 bits
 * 
 * State visualization (little-endian bit indexing):
 * S0    LSB -> [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- MSB
 *            s(0,0)                                                          s(0,63)
 * 
 * S1    LSB -> [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- MSB
 *            s(1,0)                                                          s(1,63)
 * 
 * S2    LSB -> [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- MSB
 *            s(2,0)                                                          s(2,63)
 * 
 * S3    LSB -> [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- MSB
 *            s(3,0)                                                          s(3,63)
 * 
 * S4    LSB -> [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- MSB
 *            s(4,0)                                                          s(4,63)
 * 
 * Sizes of each param:
 * 
 * - Key K: 128 bits
 * - Nonce N: 128 bits
 * - Initialization Vector IV: 64 bits (fixed value for Ascon-AEAD128 = 0x00001000808c0001)
 * 
 * - State: 320 bits (5 words of 64 bits each)
 * 
 * - Rate r: 128 bits for Ascon-AEAD128
 * - Capacity c: 192 bits for Ascon-AEAD128
 * 
 * - Associated Data A: variable length
 * - Plaintext P: variable length
 * - Ciphertext C: variable length
 * 
 * Important clarifications for correctness:
 * - Per-lane mapping: when loading/storing bytes into the 64-bit state lanes, use little-endian (le64) per lane.
 *   This applies to IV||K||N loading, AAD/PT absorption, and CT/TAG emission.
 * - Domain separation: after processing AAD (even if empty), set the MSB of S4: S4 ^= (1 << 63).
 * - Padding: for AAD and PT, append 0x01 followed by zeros to fill a 16-byte block.
 * - Outputs: ciphertext is le64(S0)||le64(S1) per block (truncate for partial tails); tag is le64(S3)||le64(S4).
 */

// =============================================================================
// Constants and Configuration
// =============================================================================

// NIST SP 800-232 Ascon-AEAD128 IV (matches official reference layout)
`define ASCON_IV 64'h00001000808C0001

// Number of rounds for different operations
`define ASCON_ROUNDS_INIT 12
`define ASCON_ROUNDS_PROCESS 8
`define ASCON_ROUNDS_FINAL 12

// Constant-Addition Layer 𝑝𝐶
// Round constants for the constant-addition layer
`define CONST_0 64'h000000000000003C
`define CONST_1 64'h000000000000002D
`define CONST_2 64'h000000000000001E
`define CONST_3 64'h000000000000000F
`define CONST_4 64'h00000000000000F0
`define CONST_5 64'h00000000000000E1
`define CONST_6 64'h00000000000000D2
`define CONST_7 64'h00000000000000C3
`define CONST_8 64'h00000000000000B4
`define CONST_9 64'h00000000000000A5
`define CONST_10 64'h0000000000000096
`define CONST_11 64'h0000000000000087
`define CONST_12 64'h0000000000000078
`define CONST_13 64'h0000000000000069
`define CONST_14 64'h000000000000005A
`define CONST_15 64'h000000000000004B

// =============================================================================
// Utility Modules
// =============================================================================

module ascon_rotr (
    input  [63:0] val,
    input  [ 5:0] r,      // Rotation amount (0-63)
    output [63:0] result
);
  // Rotate right function
  // r %= 64 (implicitly handled by 6-bit input)
  // return ((val >> r) | ((val << (64 - r)) & MASK64)) & MASK64
  wire [5:0] left_shift;
  // Compute (64 - r) mod 64 without using a 64 literal that doesn't fit in 6 bits.
  assign left_shift = (~r + 6'd1) & 6'd63;
  assign result = (val >> r) | (val << left_shift);
endmodule


module ascon_round_constant (
    input  [3:0]  total_rounds,  // Total number of rounds (e.g., 12 or 8)
    input  [3:0]  round_idx,     // Current round index (0-based)
    output [63:0] constant
);
  // Get round constant based on: CONST[16 - total_rounds + round_idx]
  wire [4:0] const_idx;
  assign const_idx = 5'd16 - total_rounds + round_idx;

  // Constant lookup table
  reg [63:0] const_value;
  always @(*) begin
    case (const_idx)
      5'd0: const_value = `CONST_0;
      5'd1: const_value = `CONST_1;
      5'd2: const_value = `CONST_2;
      5'd3: const_value = `CONST_3;
      5'd4: const_value = `CONST_4;
      5'd5: const_value = `CONST_5;
      5'd6: const_value = `CONST_6;
      5'd7: const_value = `CONST_7;
      5'd8: const_value = `CONST_8;
      5'd9: const_value = `CONST_9;
      5'd10: const_value = `CONST_10;
      5'd11: const_value = `CONST_11;
      5'd12: const_value = `CONST_12;
      5'd13: const_value = `CONST_13;
      5'd14: const_value = `CONST_14;
      5'd15: const_value = `CONST_15;
      default: const_value = 64'h0;
    endcase
  end

  assign constant = const_value;
endmodule


module ascon_byte_swap_64 (
    input  [63:0] in,
    output [63:0] out
);
  // Convert between big-endian and little-endian representation
  // for a 64-bit word
  assign out = {
    in[7:0], in[15:8], in[23:16], in[31:24], in[39:32], in[47:40], in[55:48], in[63:56]
  };
endmodule


module ascon_byte_swap_128 (
    input  [127:0] in,
    output [127:0] out
);
  // Convert between big-endian and little-endian representation
  // for a 128-bit value (split into two 64-bit words)
  wire [63:0] upper_swapped, lower_swapped;

  ascon_byte_swap_64 swap_upper (
      .in (in[127:64]),
      .out(upper_swapped)
  );

  ascon_byte_swap_64 swap_lower (
      .in (in[63:0]),
      .out(lower_swapped)
  );

  assign out = {upper_swapped, lower_swapped};
endmodule

// =============================================================================
// S-box Layer (𝑝𝑆)
// =============================================================================

/*
 * S-box Layer (𝑝𝑆) for ASCON-AEAD128
 * 
 * The S-box is applied vertically for each bit position 0 to 63.
 * For each column (bit position k), we extract the k-th bit from each 
 * of the 5 rows to form a vertical slice [x0, x1, x2, x3, x4].
 * 
 * Where X = 𝑥0, ..., 𝑥4. A 5 bit word taken by slicing the state vertically
 * 𝑠(0,𝑗), 𝑠(1,𝑗), … , 𝑠(4,𝑗)
 */

module ascon_sbox_5bit (
    input  [4:0] X,  // 5-bit input: {x4, x3, x2, x1, x0}
    output [4:0] Y   // 5-bit output: {y4, y3, y2, y1, y0}
);
  wire x0, x1, x2, x3, x4;
  reg y0, y1, y2, y3, y4;

  // Extract individual bits
  assign x0 = X[0];
  assign x1 = X[1];
  assign x2 = X[2];
  assign x3 = X[3];
  assign x4 = X[4];

  // S-box computation based on the reference implementation
  always @(*) begin
    // result[0] = X[4] & X[1] ^ X[3] ^ X[2] & X[1] ^ X[2] ^ X[1] & X[0] ^ X[1] ^ X[0]
    y0 = (x4 & x1) ^ x3 ^ (x2 & x1) ^ x2 ^ (x1 & x0) ^ x1 ^ x0;

    // result[1] = X[4] ^ X[3] & X[2] ^ X[3] & X[1] ^ X[3] ^ X[2] & X[1] ^ X[2] ^ X[1] ^ X[0]
    y1 = x4 ^ (x3 & x2) ^ (x3 & x1) ^ x3 ^ (x2 & x1) ^ x2 ^ x1 ^ x0;

    // result[2] = X[4] & X[3] ^ X[4] ^ X[2] ^ X[1] ^ 1
    y2 = (x4 & x3) ^ x4 ^ x2 ^ x1 ^ 1'b1;

    // result[3] = X[4] & X[0] ^ X[4] ^ X[3] & X[0] ^ X[3] ^ X[2] ^ X[1] ^ X[0]
    y3 = (x4 & x0) ^ x4 ^ (x3 & x0) ^ x3 ^ x2 ^ x1 ^ x0;

    // result[4] = X[4] & X[1] ^ X[4] ^ X[3] ^ X[1] & X[0] ^ X[1]
    y4 = (x4 & x1) ^ x4 ^ x3 ^ (x1 & x0) ^ x1;
  end

  // Pack output bits
  assign Y = {y4, y3, y2, y1, y0};
endmodule


module ascon_sbox_layer (
    input  [63:0] S0_in,
    S1_in,
    S2_in,
    S3_in,
    S4_in,
    output [63:0] S0_out,
    S1_out,
    S2_out,
    S3_out,
    S4_out
);
  // Apply S-box to all 64 bit positions in parallel
  genvar k;
  generate
    for (k = 0; k < 64; k = k + 1) begin : sbox_column
      wire [4:0] sbox_in, sbox_out;

      // Extract the k-th bit from each of the 5 rows to form vertical slice
      assign sbox_in = {S4_in[k], S3_in[k], S2_in[k], S1_in[k], S0_in[k]};

      // Apply 5-bit S-box
      ascon_sbox_5bit sbox (
          .X(sbox_in),
          .Y(sbox_out)
      );

      // Distribute output bits back to the 5 rows
      assign S0_out[k] = sbox_out[0];
      assign S1_out[k] = sbox_out[1];
      assign S2_out[k] = sbox_out[2];
      assign S3_out[k] = sbox_out[3];
      assign S4_out[k] = sbox_out[4];
    end
  endgenerate
endmodule

// =============================================================================
// Linear Diffusion Layer (𝑝𝐿)
// =============================================================================

/*
 * Linear Diffusion Layer (𝑝𝐿) for ASCON-AEAD128
 * 
 * The linear diffusion layer applies XOR operations with rotated versions
 * of each state word. Each of the 5 state words has its own rotation parameters.
 */

module ascon_diffusion_layer (
    input  [63:0] S0_in,
    S1_in,
    S2_in,
    S3_in,
    S4_in,
    output [63:0] S0_out,
    S1_out,
    S2_out,
    S3_out,
    S4_out
);
  // Rotation wires
  wire [63:0] S0_rot19, S0_rot28;
  wire [63:0] S1_rot61, S1_rot39;
  wire [63:0] S2_rot1, S2_rot6;
  wire [63:0] S3_rot10, S3_rot17;
  wire [63:0] S4_rot7, S4_rot41;

  // Apply rotations for S0
  // x0 = (x0 ^ rotr(x0, 19) ^ rotr(x0, 28)) & MASK64
  ascon_rotr rotr_S0_19 (
      .val(S0_in),
      .r(6'd19),
      .result(S0_rot19)
  );
  ascon_rotr rotr_S0_28 (
      .val(S0_in),
      .r(6'd28),
      .result(S0_rot28)
  );
  assign S0_out = S0_in ^ S0_rot19 ^ S0_rot28;

  // Apply rotations for S1
  // x1 = (x1 ^ rotr(x1, 61) ^ rotr(x1, 39)) & MASK64
  ascon_rotr rotr_S1_61 (
      .val(S1_in),
      .r(6'd61),
      .result(S1_rot61)
  );
  ascon_rotr rotr_S1_39 (
      .val(S1_in),
      .r(6'd39),
      .result(S1_rot39)
  );
  assign S1_out = S1_in ^ S1_rot61 ^ S1_rot39;

  // Apply rotations for S2
  // x2 = (x2 ^ rotr(x2, 1) ^ rotr(x2, 6)) & MASK64
  ascon_rotr rotr_S2_1 (
      .val(S2_in),
      .r(6'd1),
      .result(S2_rot1)
  );
  ascon_rotr rotr_S2_6 (
      .val(S2_in),
      .r(6'd6),
      .result(S2_rot6)
  );
  assign S2_out = S2_in ^ S2_rot1 ^ S2_rot6;

  // Apply rotations for S3
  // x3 = (x3 ^ rotr(x3, 10) ^ rotr(x3, 17)) & MASK64
  ascon_rotr rotr_S3_10 (
      .val(S3_in),
      .r(6'd10),
      .result(S3_rot10)
  );
  ascon_rotr rotr_S3_17 (
      .val(S3_in),
      .r(6'd17),
      .result(S3_rot17)
  );
  assign S3_out = S3_in ^ S3_rot10 ^ S3_rot17;

  // Apply rotations for S4
  // x4 = (x4 ^ rotr(x4, 7) ^ rotr(x4, 41)) & MASK64
  ascon_rotr rotr_S4_7 (
      .val(S4_in),
      .r(6'd7),
      .result(S4_rot7)
  );
  ascon_rotr rotr_S4_41 (
      .val(S4_in),
      .r(6'd41),
      .result(S4_rot41)
  );
  assign S4_out = S4_in ^ S4_rot7 ^ S4_rot41;

endmodule

// =============================================================================
// ASCON Permutation
// =============================================================================

/*
 * ASCON Permutation Module
 * 
 * Apply the Ascon permutation to the state for a given number of rounds.
 * The permutation consists of three layers applied in sequence:
 * 
 * 𝑝 = 𝑝𝐿 ∘ 𝑝𝑆 ∘ 𝑝𝐶
 * 
 * - Constant Addition Layer (𝑝𝐶): XOR round constant to S2
 * - S-box Layer (𝑝𝑆): Apply 5-bit S-box vertically for each bit position 0 to 63
 * - Linear Diffusion Layer (𝑝𝐿): Apply linear transformations with rotations
 */

module ascon_permutation_round (
    input  [63:0] S0_in,
    S1_in,
    S2_in,
    S3_in,
    S4_in,
    input  [63:0] round_constant,
    output [63:0] S0_out,
    S1_out,
    S2_out,
    S3_out,
    S4_out
);
  // Wires for intermediate state between layers
  wire [63:0] S0_after_const, S1_after_const, S2_after_const, S3_after_const, S4_after_const;
  wire [63:0] S0_after_sbox, S1_after_sbox, S2_after_sbox, S3_after_sbox, S4_after_sbox;

  // Constant Addition Layer (𝑝𝐶)
  // XOR round constant to S2
  assign S0_after_const = S0_in;
  assign S1_after_const = S1_in;
  assign S2_after_const = S2_in ^ round_constant;
  assign S3_after_const = S3_in;
  assign S4_after_const = S4_in;

  // S-box Layer (𝑝𝑆)
  // Apply vertically for each bit position 0 to 63
  ascon_sbox_layer sbox (
      .S0_in (S0_after_const),
      .S1_in (S1_after_const),
      .S2_in (S2_after_const),
      .S3_in (S3_after_const),
      .S4_in (S4_after_const),
      .S0_out(S0_after_sbox),
      .S1_out(S1_after_sbox),
      .S2_out(S2_after_sbox),
      .S3_out(S3_after_sbox),
      .S4_out(S4_after_sbox)
  );

  // Linear Diffusion Layer (𝑝𝐿)
  ascon_diffusion_layer diffusion (
      .S0_in (S0_after_sbox),
      .S1_in (S1_after_sbox),
      .S2_in (S2_after_sbox),
      .S3_in (S3_after_sbox),
      .S4_in (S4_after_sbox),
      .S0_out(S0_out),
      .S1_out(S1_out),
      .S2_out(S2_out),
      .S3_out(S3_out),
      .S4_out(S4_out)
  );

endmodule


module ascon_permutation (
    input             clk,
    input             rst,
    input             start,       // Start the permutation
    input      [ 3:0] num_rounds,  // Number of rounds to perform (8 or 12)
    input      [63:0] S0_in,
    S1_in,
    S2_in,
    S3_in,
    S4_in,
    output reg [63:0] S0_out,
    S1_out,
    S2_out,
    S3_out,
    S4_out,
    output reg        done         // Permutation complete
);
  // State machine
  localparam IDLE = 2'b00;
  localparam PERMUTE = 2'b01;
  localparam DONE = 2'b10;

  reg [1:0] state;
  reg [3:0] round_counter;

  // Current state registers
  reg [63:0] S0, S1, S2, S3, S4;

  // Wires for round computation
  wire [63:0] S0_next, S1_next, S2_next, S3_next, S4_next;
  wire [63:0] current_constant;

  // Get round constant based on total rounds and current index
  ascon_round_constant rc_gen (
      .total_rounds(num_rounds),
      .round_idx(round_counter),
      .constant(current_constant)
  );

  // Single round computation
  ascon_permutation_round round (
      .S0_in(S0),
      .S1_in(S1),
      .S2_in(S2),
      .S3_in(S3),
      .S4_in(S4),
      .round_constant(current_constant),
      .S0_out(S0_next),
      .S1_out(S1_next),
      .S2_out(S2_next),
      .S3_out(S3_next),
      .S4_out(S4_next)
  );

  // State machine and permutation logic
  always @(posedge clk or posedge rst) begin
    if (rst) begin
      state <= IDLE;
      round_counter <= 4'd0;
      S0 <= 64'd0;
      S1 <= 64'd0;
      S2 <= 64'd0;
      S3 <= 64'd0;
      S4 <= 64'd0;
      S0_out <= 64'd0;
      S1_out <= 64'd0;
      S2_out <= 64'd0;
      S3_out <= 64'd0;
      S4_out <= 64'd0;
      done <= 1'b0;
    end else begin
      case (state)
        IDLE: begin
          done <= 1'b0;
          if (start) begin
            // Load input state
            S0 <= S0_in;
            S1 <= S1_in;
            S2 <= S2_in;
            S3 <= S3_in;
            S4 <= S4_in;
            round_counter <= 4'd0;
            state <= PERMUTE;
          end
        end

        PERMUTE: begin
          // Apply one round
          S0 <= S0_next;
          S1 <= S1_next;
          S2 <= S2_next;
          S3 <= S3_next;
          S4 <= S4_next;
          round_counter <= round_counter + 4'd1;

          // Check if all rounds are complete
          if (round_counter == num_rounds - 4'd1) begin
            state <= DONE;
          end
        end

        DONE: begin
          // Output the final state
          S0_out <= S0_next;
          S1_out <= S1_next;
          S2_out <= S2_next;
          S3_out <= S3_next;
          S4_out <= S4_next;
          done   <= 1'b1;
          state  <= IDLE;
        end

        default: state <= IDLE;
      endcase
    end
  end

endmodule

// =============================================================================
// ASCON-AEAD128 Algorithm Modules
// =============================================================================

/*
 * ascon_initialize
 * 
 * Initialize the Ascon state with key K, nonce N, and initialization vector IV.
 * 
 * S ← IV || K || N, where each 64-bit lane uses little-endian byte-to-int
 * 
 * Args:
 *     K : The 128 bit secret key.
 *     N : The 128 bit nonce.
 *     IV: The initialization vector as a 64-bit unsigned integer.
 * Returns:
 *     State: The initialized state as a list of five 64-bit unsigned integers [S0, S1, S2, S3, S4].
 */

module ascon_initialize (
    input              clk,
    input              rst,
    input              start,
    input      [127:0] K,      // 128-bit key (big-endian)
    input      [127:0] N,      // 128-bit nonce (big-endian)
    output reg [ 63:0] S0,
    S1,
    S2,
    S3,
    S4,
    output reg         done
);

  localparam IDLE = 3'd0;
  localparam LOAD = 3'd1;
  localparam PERMUTE = 3'd2;
  localparam XOR_KEY = 3'd3;
  localparam DONE = 3'd4;

  reg [2:0] state;

  // Key and nonce converted to little-endian per 64-bit lane
  wire [127:0] K_le, N_le;
  wire [63:0] kh, kl, nh, nl;

  // Convert key and nonce from big-endian to little-endian per lane
  ascon_byte_swap_128 swap_key (
      .in (K),
      .out(K_le)
  );

  ascon_byte_swap_128 swap_nonce (
      .in (N),
      .out(N_le)
  );

  // Extract upper and lower 64 bits
  assign kh = K_le[127:64];  // Upper 64 bits of K
  assign kl = K_le[63:0];  // Lower 64 bits of K
  assign nh = N_le[127:64];  // Upper 64 bits of N
  assign nl = N_le[63:0];  // Lower 64 bits of N

  // Permutation control signals
  reg  perm_start;
  wire perm_done;
  wire [63:0] S0_perm, S1_perm, S2_perm, S3_perm, S4_perm;
  reg [63:0] S0_perm_in, S1_perm_in, S2_perm_in, S3_perm_in, S4_perm_in;

  // Perform 12 rounds of the Ascon permutation
  ascon_permutation perm (
      .clk(clk),
      .rst(rst),
      .start(perm_start),
      .num_rounds(4'd`ASCON_ROUNDS_INIT),
      .S0_in(S0_perm_in),
      .S1_in(S1_perm_in),
      .S2_in(S2_perm_in),
      .S3_in(S3_perm_in),
      .S4_in(S4_perm_in),
      .S0_out(S0_perm),
      .S1_out(S1_perm),
      .S2_out(S2_perm),
      .S3_out(S3_perm),
      .S4_out(S4_perm),
      .done(perm_done)
  );

  always @(posedge clk or posedge rst) begin
    if (rst) begin
      state <= IDLE;
      S0 <= 64'd0;
      S1 <= 64'd0;
      S2 <= 64'd0;
      S3 <= 64'd0;
      S4 <= 64'd0;
      perm_start <= 1'b0;
      done <= 1'b0;
    end else begin
      case (state)
        IDLE: begin
          done <= 1'b0;
          perm_start <= 1'b0;
          if (start) begin
            state <= LOAD;
          end
        end

        LOAD: begin
          // S ← IV || K || N, where each 64-bit lane uses little-endian byte-to-int
          // NIST SP 800-232 Ascon-AEAD128 IV (matches official reference layout)
          S0_perm_in <= `ASCON_IV;
          S1_perm_in <= kh;
          S2_perm_in <= kl;
          S3_perm_in <= nh;
          S4_perm_in <= nl;
          perm_start <= 1'b1;
          state <= PERMUTE;
        end

        PERMUTE: begin
          perm_start <= 1'b0;
          if (perm_done) begin
            // S ← S ⊕ (0^192 ‖ K)
            // XOR K into the last 2 rows of the state
            // This mixes in the key one more time
            S0 <= S0_perm;
            S1 <= S1_perm;
            S2 <= S2_perm;
            S3 <= S3_perm;
            S4 <= S4_perm;
            state <= XOR_KEY;
          end
        end

        XOR_KEY: begin
          // XOR upper 64 bits of K
          S3 <= S3 ^ kh;
          // XOR lower 64 bits of K
          S4 <= S4 ^ kl;
          state <= DONE;
        end

        DONE: begin
          done  <= 1'b1;
          state <= IDLE;
        end

        default: state <= IDLE;
      endcase
    end
  end

endmodule


/*
 * ascon_process_ad
 * 
 * Process associated data in 128-bit (16-byte) blocks.
 * 
 * For each block:
 * - XOR with the first two rows of State (S0, S1)
 * - Apply 8 rounds of permutation
 * 
 * After processing all AD (even if empty):
 * - Domain separation: S4 ^= (1 << 63)
 */

module ascon_process_ad (
    input              clk,
    input              rst,
    input              start,
    input      [ 63:0] S0_in,
    S1_in,
    S2_in,
    S3_in,
    S4_in,
    input      [127:0] ad_block,       // 16-byte associated data block (little-endian per lane)
    input              is_last_block,  // Indicates this is the last AD block
    output reg [ 63:0] S0_out,
    S1_out,
    S2_out,
    S3_out,
    S4_out,
    output reg         done
);

  localparam IDLE = 3'd0;
  localparam XOR_BLOCK = 3'd1;
  localparam PERMUTE = 3'd2;
  localparam DOMAIN_SEP = 3'd3;
  localparam DONE = 3'd4;

  reg [2:0] state;
  reg [63:0] S0, S1, S2, S3, S4;

  // Permutation control
  reg  perm_start;
  wire perm_done;
  wire [63:0] S0_perm, S1_perm, S2_perm, S3_perm, S4_perm;

  ascon_permutation perm (
      .clk(clk),
      .rst(rst),
      .start(perm_start),
      .num_rounds(4'd`ASCON_ROUNDS_PROCESS),
      .S0_in(S0),
      .S1_in(S1),
      .S2_in(S2),
      .S3_in(S3),
      .S4_in(S4),
      .S0_out(S0_perm),
      .S1_out(S1_perm),
      .S2_out(S2_perm),
      .S3_out(S3_perm),
      .S4_out(S4_perm),
      .done(perm_done)
  );

  always @(posedge clk or posedge rst) begin
    if (rst) begin
      state <= IDLE;
      S0 <= 64'd0;
      S1 <= 64'd0;
      S2 <= 64'd0;
      S3 <= 64'd0;
      S4 <= 64'd0;
      S0_out <= 64'd0;
      S1_out <= 64'd0;
      S2_out <= 64'd0;
      S3_out <= 64'd0;
      S4_out <= 64'd0;
      perm_start <= 1'b0;
      done <= 1'b0;
    end else begin
      case (state)
        IDLE: begin
          done <= 1'b0;
          perm_start <= 1'b0;
          if (start) begin
            S0 <= S0_in;
            S1 <= S1_in;
            S2 <= S2_in;
            S3 <= S3_in;
            S4 <= S4_in;
            state <= XOR_BLOCK;
          end
        end

        XOR_BLOCK: begin
          // XOR with the first two rows of State and apply permutation...
          // S[0:127] ← S[0:127] ⊕ AD_block
          S0 <= S0 ^ ad_block[127:64];  // XOR upper 64 bits of block
          S1 <= S1 ^ ad_block[63:0];  // XOR lower 64 bits of block
          perm_start <= 1'b1;
          state <= PERMUTE;
        end

        PERMUTE: begin
          perm_start <= 1'b0;
          if (perm_done) begin
            S0 <= S0_perm;
            S1 <= S1_perm;
            S2 <= S2_perm;
            S3 <= S3_perm;
            S4 <= S4_perm;

            if (is_last_block) begin
              state <= DOMAIN_SEP;
            end else begin
              state <= DONE;
            end
          end
        end

        DOMAIN_SEP: begin
          // Domain separation S ← S ⊕ (0^319 ‖ 1)
          // XOR the MSB of S4 (always, regardless of A length)
          S4 <= S4 ^ (64'd1 << 63);
          state <= DONE;
        end

        DONE: begin
          S0_out <= S0;
          S1_out <= S1;
          S2_out <= S2;
          S3_out <= S3;
          S4_out <= S4;
          done   <= 1'b1;
          state  <= IDLE;
        end

        default: state <= IDLE;
      endcase
    end
  end

endmodule


/*
 * ascon_process_pt
 * 
 * Process plaintext in 128-bit (16-byte) blocks.
 * 
 * For each block:
 * - XOR plaintext with state: S[0:127] ← S[0:127] ⊕ PT_block
 * - Extract ciphertext: CT = S0 || S1
 * - Apply 8 rounds of permutation (except for last block)
 * 
 * For the last block (which may be partial):
 * - Process with padding
 * - Emit ciphertext truncated to |P_n| bits
 */

module ascon_process_pt (
    input              clk,
    input              rst,
    input              start,
    input      [ 63:0] S0_in,
    S1_in,
    S2_in,
    S3_in,
    S4_in,
    input      [127:0] pt_block,       // 16-byte plaintext block (little-endian per lane)
    input              is_last_block,  // Indicates this is the last PT block
    output reg [ 63:0] S0_out,
    S1_out,
    S2_out,
    S3_out,
    S4_out,
    output reg [127:0] ct_block,       // Ciphertext output
    output reg         done
);

  localparam IDLE = 3'd0;
  localparam XOR_BLOCK = 3'd1;
  localparam EXTRACT_CT = 3'd2;
  localparam PERMUTE = 3'd3;
  localparam DONE = 3'd4;

  reg [2:0] state;
  reg [63:0] S0, S1, S2, S3, S4;

  // Permutation control
  reg  perm_start;
  wire perm_done;
  wire [63:0] S0_perm, S1_perm, S2_perm, S3_perm, S4_perm;

  ascon_permutation perm (
      .clk(clk),
      .rst(rst),
      .start(perm_start),
      .num_rounds(4'd`ASCON_ROUNDS_PROCESS),
      .S0_in(S0),
      .S1_in(S1),
      .S2_in(S2),
      .S3_in(S3),
      .S4_in(S4),
      .S0_out(S0_perm),
      .S1_out(S1_perm),
      .S2_out(S2_perm),
      .S3_out(S3_perm),
      .S4_out(S4_perm),
      .done(perm_done)
  );

  always @(posedge clk or posedge rst) begin
    if (rst) begin
      state <= IDLE;
      S0 <= 64'd0;
      S1 <= 64'd0;
      S2 <= 64'd0;
      S3 <= 64'd0;
      S4 <= 64'd0;
      S0_out <= 64'd0;
      S1_out <= 64'd0;
      S2_out <= 64'd0;
      S3_out <= 64'd0;
      S4_out <= 64'd0;
      ct_block <= 128'd0;
      perm_start <= 1'b0;
      done <= 1'b0;
    end else begin
      case (state)
        IDLE: begin
          done <= 1'b0;
          perm_start <= 1'b0;
          if (start) begin
            S0 <= S0_in;
            S1 <= S1_in;
            S2 <= S2_in;
            S3 <= S3_in;
            S4 <= S4_in;
            state <= XOR_BLOCK;
          end
        end

        XOR_BLOCK: begin
          // XOR with the first two rows of State
          // S[0:127] ← S[0:127] ⊕ PT_block
          S0 <= S0 ^ pt_block[127:64];  // XOR upper 64 bits of block
          S1 <= S1 ^ pt_block[63:0];  // XOR lower 64 bits of block
          state <= EXTRACT_CT;
        end

        EXTRACT_CT: begin
          // Extract ciphertext from state
          // Ciphertext is le64(S0)||le64(S1) per block (truncate for partial tails)
          ct_block <= {S0, S1};

          if (!is_last_block) begin
            perm_start <= 1'b1;
            state <= PERMUTE;
          end else begin
            state <= DONE;
          end
        end

        PERMUTE: begin
          perm_start <= 1'b0;
          if (perm_done) begin
            S0 <= S0_perm;
            S1 <= S1_perm;
            S2 <= S2_perm;
            S3 <= S3_perm;
            S4 <= S4_perm;
            state <= DONE;
          end
        end

        DONE: begin
          S0_out <= S0;
          S1_out <= S1;
          S2_out <= S2;
          S3_out <= S3;
          S4_out <= S4;
          done   <= 1'b1;
          state  <= IDLE;
        end

        default: state <= IDLE;
      endcase
    end
  end

endmodule


/*
 * ascon_finalize
 * 
 * Finalization phase of ASCON-AEAD128.
 * 
 * - S ← S ⊕ (0^128 ‖ K || 0^64)
 * - Apply 12 rounds of permutation
 * - S ← S ⊕ (0^192 ‖ K), and extract tag
 * - Tag T = le64(S3 ^ kh) || le64(S4 ^ kl)
 */

module ascon_finalize (
    input              clk,
    input              rst,
    input              start,
    input      [ 63:0] S0_in,
    S1_in,
    S2_in,
    S3_in,
    S4_in,
    input      [127:0] K,      // 128-bit key (big-endian)
    output reg [127:0] tag,    // 128-bit authentication tag
    output reg         done
);

  localparam IDLE = 3'd0;
  localparam XOR_KEY1 = 3'd1;
  localparam PERMUTE = 3'd2;
  localparam XOR_KEY2 = 3'd3;
  localparam DONE = 3'd4;

  reg [2:0] state;
  reg [63:0] S0, S1, S2, S3, S4;

  // Key converted to little-endian per 64-bit lane
  wire [127:0] K_le;
  wire [63:0] kh, kl;

  ascon_byte_swap_128 swap_key (
      .in (K),
      .out(K_le)
  );

  assign kh = K_le[127:64];  // Upper 64 bits of K
  assign kl = K_le[63:0];  // Lower 64 bits of K

  // Permutation control
  reg  perm_start;
  wire perm_done;
  wire [63:0] S0_perm, S1_perm, S2_perm, S3_perm, S4_perm;

  ascon_permutation perm (
      .clk(clk),
      .rst(rst),
      .start(perm_start),
      .num_rounds(4'd`ASCON_ROUNDS_FINAL),
      .S0_in(S0),
      .S1_in(S1),
      .S2_in(S2),
      .S3_in(S3),
      .S4_in(S4),
      .S0_out(S0_perm),
      .S1_out(S1_perm),
      .S2_out(S2_perm),
      .S3_out(S3_perm),
      .S4_out(S4_perm),
      .done(perm_done)
  );

  always @(posedge clk or posedge rst) begin
    if (rst) begin
      state <= IDLE;
      S0 <= 64'd0;
      S1 <= 64'd0;
      S2 <= 64'd0;
      S3 <= 64'd0;
      S4 <= 64'd0;
      tag <= 128'd0;
      perm_start <= 1'b0;
      done <= 1'b0;
    end else begin
      case (state)
        IDLE: begin
          done <= 1'b0;
          perm_start <= 1'b0;
          if (start) begin
            S0 <= S0_in;
            S1 <= S1_in;
            S2 <= S2_in;
            S3 <= S3_in;
            S4 <= S4_in;
            state <= XOR_KEY1;
          end
        end

        XOR_KEY1: begin
          // S ← S ⊕ (0^128 ‖ K || 0^64)
          S2 <= S2 ^ kh;
          S3 <= S3 ^ kl;
          perm_start <= 1'b1;
          state <= PERMUTE;
        end

        PERMUTE: begin
          perm_start <= 1'b0;
          if (perm_done) begin
            S0 <= S0_perm;
            S1 <= S1_perm;
            S2 <= S2_perm;
            S3 <= S3_perm;
            S4 <= S4_perm;
            state <= XOR_KEY2;
          end
        end

        XOR_KEY2: begin
          // S ← S ⊕ (0^192 ‖ K), and extract tag
          // Tag is le64(S3)||le64(S4)
          tag   <= {S3 ^ kh, S4 ^ kl};
          state <= DONE;
        end

        DONE: begin
          done  <= 1'b1;
          state <= IDLE;
        end

        default: state <= IDLE;
      endcase
    end
  end

endmodule
