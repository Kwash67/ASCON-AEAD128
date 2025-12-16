`ifndef INCL_CONFIG
`define INCL_CONFIG

// Licensed under the Creative Commons 1.0 Universal License (CC0), see LICENSE
// for details.
//
// Author: Robert Primas (rprimas 'at' proton.me, https://rprimas.github.io)
//
// Configuration of the Ascon core.

// ============================================================================
// HARDWARE VARIANTS: Trade-off between speed and area
// ============================================================================
// These defines allow you to compile different hardware configurations.
// To use a variant, pass -DV1 (or V2, etc.) to your synthesis tool.
//
// UROL: UnRoll Level - how many permutation rounds happen per clock cycle
//       Higher UROL = faster but more hardware (combinational logic)
//       Your Python does 1 round per loop iteration, similar to UROL=1
//
// CCW: Core Communication Width - width of data buses (bits)
//      32-bit = process data in smaller chunks (like your bytes processing)
//      64-bit = process larger chunks per clock (faster but wider datapath)
//
// Variants:
//   V1: Slowest, smallest area  - 1 round/cycle, 32-bit buses
//   V2: Medium                  - 2 rounds/cycle, 32-bit buses
//   V3: Faster                  - 4 rounds/cycle, 32-bit buses
//   V4: Medium, wider buses     - 1 round/cycle, 64-bit buses
//   V5: Faster, wider buses     - 2 rounds/cycle, 64-bit buses
//   V6: Fastest, largest area   - 4 rounds/cycle, 64-bit buses

`ifdef V1
localparam logic [3:0] UROL = 1;   // 1 permutation round per clock
localparam unsigned CCW = 32;       // 32-bit data buses
`elsif V2
localparam logic [3:0] UROL = 2;   // 2 permutation rounds per clock
localparam unsigned CCW = 32;       // 32-bit data buses
`elsif V3
localparam logic [3:0] UROL = 4;   // 4 permutation rounds per clock
localparam unsigned CCW = 32;       // 32-bit data buses
`elsif V4
localparam logic [3:0] UROL = 1;   // 1 permutation round per clock
localparam unsigned CCW = 64;       // 64-bit data buses (full lane width)
`elsif V5
localparam logic [3:0] UROL = 2;   // 2 permutation rounds per clock
localparam unsigned CCW = 64;       // 64-bit data buses (full lane width)
`elsif V6
localparam logic [3:0] UROL = 4;   // 4 permutation rounds per clock
localparam unsigned CCW = 64;       // 64-bit data buses (full lane width)
`endif

// Default configuration if no variant is specified
`ifndef V1
`ifndef V2
`ifndef V3
`ifndef V4
`ifndef V5
`ifndef V6
localparam logic [3:0] UROL = 1;   // Default: slowest, smallest
localparam unsigned CCW = 32;
`endif
`endif
`endif
`endif
`endif
`endif

// ============================================================================
// DATA SIZE HELPERS: How many CCW-width "words" fit in standard sizes
// ============================================================================
// These calculate how many clock cycles are needed to transfer standard sizes.
// Example: If CCW=32, then 128 bits needs 4 words (4 transfers)
//          If CCW=64, then 128 bits needs 2 words (2 transfers)
localparam logic [3:0] W64 = CCW == 32 ? 4'd2 : 4'd1;   // Words in 64 bits (1 lane)
localparam logic [3:0] W128 = CCW == 32 ? 4'd4 : 4'd2;  // Words in 128 bits (key, nonce, tag)
localparam logic [3:0] W192 = CCW == 32 ? 4'd6 : 4'd3;  // Words in 192 bits (capacity)

// ============================================================================
// ASCON ALGORITHM PARAMETERS
// ============================================================================
// These match the Ascon specification exactly

localparam unsigned LANES = 5;       // State size: 5 lanes of 64 bits each = 320 bits total
                                     // In your Python: State = [S0, S1, S2, S3, S4]

localparam unsigned ROUNDS_A = 12;   // Number of rounds for initialization and finalization
                                     // In your Python: ascon_permutation(State, 12)

localparam unsigned ROUNDS_B = 8;    // Number of rounds for processing data (AD, plaintext)
                                     // In your Python: ascon_permutation(State, 8)

// Initialization Vector
localparam logic [63:0] IV_AEAD = 64'h00001000808c0001;  // For AEAD encryption/decryption

// ============================================================================
// MODE SELECTION: What operation is the core performing?
// ============================================================================
// Enumerated type for selecting which Ascon algorithm to use
typedef enum logic [3:0] {
  M_INVALID     = 0,  // Invalid/no operation
  M_AEAD128_ENC = 1,  // Authenticated Encryption (like your ascon_aead128_enc)
  M_AEAD128_DEC = 2  // Authenticated Decryption (verify and decrypt)
} mode_e;

// ============================================================================
// DATA TYPE TAGS: What kind of data is being transferred?
// ============================================================================
// Used to tag data going in/out of the core so the FSM knows how to process it
typedef enum logic [3:0] {
  D_INVALID = 0,  // Invalid/no data
  D_NONCE   = 1,  // Nonce N (like your N parameter)
  D_AD      = 2,  // Associated Data (like your A parameter, or customization for CXOF)
  D_MSG     = 3,  // Message/Plaintext (like your P parameter)
  D_TAG     = 4  // Authentication Tag (like your T output)
} data_e;

`endif  // INCL_CONFIG
