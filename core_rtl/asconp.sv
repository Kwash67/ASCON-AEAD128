`ifndef INCL_ASCONP
`define INCL_ASCONP

// Licensed under the Creative Commons 1.0 Universal License (CC0), see LICENSE
// for details.
//
// Author: Robert Primas (rprimas 'at' proton.me, https://rprimas.github.io)
//
// ============================================================================
// ASCON PERMUTATION (Ascon-p)
// ============================================================================
// This module implements the core cryptographic permutation of Ascon.
// It's equivalent to your Python ascon_permutation() function.
//
// Your Python does:
//   for i in range(0, rounds):
//       State[2] ^= round_constant      # Constant addition
//       apply_sbox_vertically()         # S-box layer
//       State = linear_diffusion()      # Linear diffusion
//
// This hardware version:
// - Performs UROL rounds per clock cycle (configurable unrolling for speed)
// - Processes all 64 bit positions in parallel (not bit-by-bit like Python)
// - Splits the permutation into 4 distinct layers (see below)
//
// State representation:
//   x0, x1, x2, x3, x4 correspond to your State[0], State[1], ..., State[4]
//   Each is a 64-bit lane (word)

`include "config.sv"

module asconp (
    input  logic [ 3:0] round_cnt,     // Current round number (for constant generation)
    input  logic [63:0] x0_i,          // Input: State lane 0 (like your State[0])
    input  logic [63:0] x1_i,          // Input: State lane 1 (like your State[1])
    input  logic [63:0] x2_i,          // Input: State lane 2 (like your State[2])
    input  logic [63:0] x3_i,          // Input: State lane 3 (like your State[3])
    input  logic [63:0] x4_i,          // Input: State lane 4 (like your State[4])
    output logic [63:0] x0_o,          // Output: Permuted state lane 0
    output logic [63:0] x1_o,          // Output: Permuted state lane 1
    output logic [63:0] x2_o,          // Output: Permuted state lane 2
    output logic [63:0] x3_o,          // Output: Permuted state lane 3
    output logic [63:0] x4_o           // Output: Permuted state lane 4
);

  // Intermediate signals for each permutation round stage
  // _aff1: After 1st affine layer (constant addition + pre-mixing)
  // _chi:  After chi/S-box layer (non-linear substitution)
  // _aff2: After 2nd affine layer (post-S-box mixing)
  // Final result goes into x0..x4 arrays
  logic [UROL-1:0][63:0] x0_aff1, x0_chi, x0_aff2;
  logic [UROL-1:0][63:0] x1_aff1, x1_chi, x1_aff2;
  logic [UROL-1:0][63:0] x2_aff1, x2_chi, x2_aff2;
  logic [UROL-1:0][63:0] x3_aff1, x3_chi, x3_aff2;
  logic [UROL-1:0][63:0] x4_aff1, x4_chi, x4_aff2;
  
  // State arrays: x0[0] is input, x0[1] is after 1 round, x0[UROL] is final output
  logic [UROL : 0][63:0] x0, x1, x2, x3, x4;
  
  logic [UROL-1:0][3:0] t;  // Round constant index for each unrolled round

  // Connect module inputs to the first element of state arrays
  assign x0[0] = x0_i;
  assign x1[0] = x1_i;
  assign x2[0] = x2_i;
  assign x3[0] = x3_i;
  assign x4[0] = x4_i;

  // ============================================================================
  // UNROLLED PERMUTATION ROUNDS
  // ============================================================================
  // Generate UROL copies of the permutation logic in parallel.
  // Each iteration represents one complete permutation round.
  // UROL=1: One round per clock (slow, small)
  // UROL=4: Four rounds per clock (fast, large)
  
  genvar i;
  generate
    for (i = 0; i < UROL; i++) begin : g_asconp
      
      // ======================================================================
      // LAYER 1: FIRST AFFINE LAYER (Constant Addition + Pre-mixing)
      // ======================================================================
      // This combines:
      // 1. Round constant addition (your: State[2] ^= get_round_constant())
      // 2. Pre-S-box linear mixing
      //
      // The constant 't' is the round constant index (0x00 to 0x0B for 12 rounds)
      // It gets embedded into x2 as {0xF-t, t} in the low byte
      // This is equivalent to your: State[2] ^= CONST[16 - rounds + i]
      
      assign t[i] = (4'hC) - (round_cnt - i);  // Calculate round constant index
      
      assign x0_aff1[i] = x0[i] ^ x4[i];       // Mix x0 with x4
      assign x1_aff1[i] = x1[i];                // x1 unchanged in this layer
      assign x2_aff1[i] = x2[i] ^ x1[i] ^ {56'd0, (4'hF - t[i]), t[i]};  // Add round constant here!
      assign x3_aff1[i] = x3[i];                // x3 unchanged in this layer
      assign x4_aff1[i] = x4[i] ^ x3[i];       // Mix x4 with x3
      
      // ======================================================================
      // LAYER 2: NON-LINEAR CHI LAYER (S-box)
      // ======================================================================
      // This is the HEART of the cryptography - the non-linear S-box!
      // Equivalent to your: s_box_compute(X)
      //
      // Your Python applies S-box vertically bit-by-bit (64 times):
      //   for k in range(64):
      //       S_box_input = [extract bit k from each lane]
      //       S_box_output = s_box_compute(S_box_input)
      //
      // This hardware does ALL 64 bit positions in PARALLEL using bitwise ops.
      // The formula (~a & b) implements the non-linear mixing.
      // This is the "chi" function from Keccak/SHA-3 (Ascon's S-box is related).
      
      assign x0_chi[i] = x0_aff1[i] ^ ((~x1_aff1[i]) & x2_aff1[i]);  // x0' = x0 ⊕ (¬x1 ∧ x2)
      assign x1_chi[i] = x1_aff1[i] ^ ((~x2_aff1[i]) & x3_aff1[i]);  // x1' = x1 ⊕ (¬x2 ∧ x3)
      assign x2_chi[i] = x2_aff1[i] ^ ((~x3_aff1[i]) & x4_aff1[i]);  // x2' = x2 ⊕ (¬x3 ∧ x4)
      assign x3_chi[i] = x3_aff1[i] ^ ((~x4_aff1[i]) & x0_aff1[i]);  // x3' = x3 ⊕ (¬x4 ∧ x0)
      assign x4_chi[i] = x4_aff1[i] ^ ((~x0_aff1[i]) & x1_aff1[i]);  // x4' = x4 ⊕ (¬x0 ∧ x1)
      
      // ======================================================================
      // LAYER 3: SECOND AFFINE LAYER (Post-S-box Mixing)
      // ======================================================================
      // Additional linear mixing after the S-box
      // Prepares the state for the linear diffusion layer
      
      assign x0_aff2[i] = x0_chi[i] ^ x4_chi[i];  // Mix x0 with x4
      assign x1_aff2[i] = x1_chi[i] ^ x0_chi[i];  // Mix x1 with x0
      assign x2_aff2[i] = ~x2_chi[i];              // Invert x2
      assign x3_aff2[i] = x3_chi[i] ^ x2_chi[i];  // Mix x3 with x2
      assign x4_aff2[i] = x4_chi[i];               // x4 unchanged in this layer
      
      // ======================================================================
      // LAYER 4: LINEAR DIFFUSION LAYER
      // ======================================================================
      // This spreads changes across the entire lane (diffusion).
      // Equivalent to your: linear_diffusion_layer(State)
      //
      // Your Python: x0 = (x0 ^ rotr(x0, 19) ^ rotr(x0, 28)) & MASK64
      //
      // Hardware rotation notation:
      //   {x[18:0], x[63:19]} means: take bits [18:0] and put them at the top,
      //                                take bits [63:19] and put them at bottom
      //   This rotates RIGHT by 19 positions (rotr(x, 19))
      //
      // Each lane has different rotation amounts (from Ascon spec):
      //   x0: rotate by 19 and 28
      //   x1: rotate by 61 and 39
      //   x2: rotate by 1 and 6
      //   x3: rotate by 10 and 17
      //   x4: rotate by 7 and 41
      
      assign x0[i+1] = x0_aff2[i] ^ {x0_aff2[i][18:0], x0_aff2[i][63:19]} ^ {x0_aff2[i][27:0], x0_aff2[i][63:28]};
                    // x0' = x0 ⊕ rotr(x0, 19) ⊕ rotr(x0, 28)
      
      assign x1[i+1] = x1_aff2[i] ^ {x1_aff2[i][60:0], x1_aff2[i][63:61]} ^ {x1_aff2[i][38:0], x1_aff2[i][63:39]};
                    // x1' = x1 ⊕ rotr(x1, 61) ⊕ rotr(x1, 39)
      
      assign x2[i+1] = x2_aff2[i] ^ {x2_aff2[i][0:0], x2_aff2[i][63:01]} ^ {x2_aff2[i][05:0], x2_aff2[i][63:06]};
                    // x2' = x2 ⊕ rotr(x2, 1) ⊕ rotr(x2, 6)
      
      assign x3[i+1] = x3_aff2[i] ^ {x3_aff2[i][9:0], x3_aff2[i][63:10]} ^ {x3_aff2[i][16:0], x3_aff2[i][63:17]};
                    // x3' = x3 ⊕ rotr(x3, 10) ⊕ rotr(x3, 17)
      
      assign x4[i+1] = x4_aff2[i] ^ {x4_aff2[i][6:0], x4_aff2[i][63:07]} ^ {x4_aff2[i][40:0], x4_aff2[i][63:41]};
                    // x4' = x4 ⊕ rotr(x4, 7) ⊕ rotr(x4, 41)
    end
  endgenerate

  // Connect final state (after UROL rounds) to module outputs
  assign x0_o = x0[UROL];
  assign x1_o = x1[UROL];
  assign x2_o = x2[UROL];
  assign x3_o = x3[UROL];
  assign x4_o = x4[UROL];

endmodule

`endif  // INCL_ASCONP
