`ifndef INCL_FUNCTIONS
`define INCL_FUNCTIONS

// Licensed under the Creative Commons 1.0 Universal License (CC0), see LICENSE
// for details.
//
// Author: Robert Primas (rprimas 'at' proton.me, https://rprimas.github.io)
//
// Generic functions for the Ascon core.
// These implement the padding logic required by the Ascon specification.

`include "config.sv"

// ============================================================================
// PADDING FUNCTION FOR ENCRYPTION (Associated Data & Plaintext)
// ============================================================================
// This implements the Ascon padding rule: append 0x01 followed by zeros
// Like your Python: pad_len = 16 - (len(A) % 16) - 1
//                   a_padding = b"\x01" + (b"\x00" * pad_len)
//
// Hardware does this incrementally as data arrives byte-by-byte:
// - 'in' contains the actual data bytes
// - 'val' is a bitmask showing which bytes in 'in' are valid (1=valid, 0=empty)
// - When we see the last valid byte, we insert 0x01 in the next position
//
// Example with CCW=32 (4 bytes):
//   in:  [0x00, 0x00, 0x11, 0x22]  <- data bytes
//   val: [   0,    0,    1,    1]  <- byte 2 and 3 are valid
//   =>
//   pad: [0x00, 0x01, 0x11, 0x22]  <- inserted padding byte 0x01 after last valid
//
// This is called during:
// - ABS_AD state: absorbing associated data (like your process_associated_data)
// - ABS_MSG state: absorbing plaintext during encryption (like your process_plaintext)

function automatic logic [CCW-1:0] pad;
  input logic [CCW-1:0] in;          // Input data word (CCW bits wide)
  input logic [CCW/8-1:0] val;       // Valid byte mask (1 bit per byte)
  
  // Process first byte (byte 0)
  // If valid, use input data; otherwise zero it out
  pad[7:0] = val[0] ? in[7:0] : 'd0;
  
  // Process remaining bytes (bytes 1 to CCW/8-1)
  for (int i = 1; i < CCW / 8; i += 1) begin
    // For each byte position:
    // - If this byte is valid (val[i]=1): use input data
    // - Else if previous byte was valid (val[i-1]=1): insert padding byte 0x01
    // - Otherwise: zero padding
    pad[i*8+:8] = val[i] ? in[i*8+:8] : val[i-1] ? 'd1 : 'd0;
  end
endfunction

// ============================================================================
// PADDING FUNCTION FOR DECRYPTION (Plaintext Recovery)
// ============================================================================
// During decryption, we need to reconstruct plaintext AND apply padding simultaneously.
// This is trickier because:
// - We XOR ciphertext with state to get plaintext
// - But partial blocks need padding inserted where there's no ciphertext
//
// Inputs:
// - in1: The recovered plaintext bytes (from XORing ciphertext with state)
// - in2: The current state bytes (for positions where we have no ciphertext)
// - val: Valid byte mask showing which ciphertext bytes we have
//
// Example with CCW=32 (4 bytes):
//   in1:  [0x00, 0x11, 0x22, 0x33]  <- recovered plaintext
//   in2:  [0x44, 0x55, 0x66, 0x77]  <- state values
//   val:  [   0,    0,    1,    1]  <- only bytes 2,3 have ciphertext
//   =>
//   pad2: [0x44, 0x54, 0x22, 0x33]  <- byte 1 = state[1] XOR 0x01 (padding)
//                                       byte 0 = state[0] (no data, no padding yet)
//
// This ensures the state is updated correctly even for partial final blocks.

function automatic logic [CCW-1:0] pad2;
  input logic [CCW-1:0] in1;         // Recovered plaintext
  input logic [CCW-1:0] in2;         // Current state
  input logic [CCW/8-1:0] val;       // Valid byte mask
  
  // Process first byte (byte 0)
  // If we have ciphertext, use recovered plaintext; otherwise use state directly
  pad2[7:0] = val[0] ? in1[7:0] : in2[7:0];
  
  // Process remaining bytes
  for (int i = 1; i < CCW / 8; i += 1) begin
    // For each byte position:
    // - If this byte has ciphertext (val[i]=1): use recovered plaintext
    // - Else if previous byte had ciphertext (val[i-1]=1): XOR state with padding 0x01
    // - Otherwise: use state directly (haven't reached padding position yet)
    pad2[i*8+:8] = val[i] ? in1[i*8+:8] : (val[i-1] ? 'd1 ^ in2[i*8+:8] : in2[i*8+:8]);
  end
endfunction

`endif  // INCL_FUNCTIONS
