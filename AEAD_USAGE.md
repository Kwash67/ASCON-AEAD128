# ASCON AEAD-Only Files for Your RFID Project

## Core core_rtl Files

1. **`core_rtl/ascon_core_aead.sv`** - Main AEAD controller (AEAD-only version)
2. **`core_rtl/asconp.sv`** - Ascon permutation module (cryptographic rounds)
3. **`core_rtl/config.sv`** - Configuration parameters (hardware variants, constants)
4. **`core_rtl/functions.sv`** - Padding functions (pad, pad2)

### What Each File Does:

- **ascon_core_aead.sv**: FSM controller that implements the complete AEAD encrypt/decrypt flow
  - Input: key (128b), nonce (128b), associated data, plaintext/ciphertext
  - Output: ciphertext/plaintext, authentication tag (128b)

- **asconp.sv**: Hardware implementation of the Ascon permutation
  - Performs the cryptographic transformation (S-box + linear diffusion)
  - Configurable unrolling (UROL parameter) for speed/area tradeoff

- **config.sv**: Defines hardware parameters
  - `UROL`: Permutation rounds per clock cycle (1, 2, or 4)
  - `CCW`: Communication width (32 or 64 bits)
  - Variants V1-V6 for different speed/area configurations
  - Constants: IV values, round counts, data types, modes

- **functions.sv**: Helper functions for AEAD
  - `pad()`: Adds 0x01 padding for encryption
  - `pad2()`: Special padding for decryption

## Testing Files (For Verification)

If you want to test the AEAD core before integrating:

1. **`test_aead_only.py`** - Python testbench (AEAD tests only)
2. **`Makefile`** - Build script for simulation
3. **`ascon.py`** - Reference Python implementation (already in repo)

### To Run Tests:
```bash
# Using the AEAD-only makefile
make -f Makefile sim

# This will:
# - Compile ascon_core_aead.sv with Verilator
# - Run encryption tests (100 test vectors)
# - Run decryption tests (100 test vectors)
# - Verify against software reference
```

## Synthesis Files (For ASIC/FPGA)

For synthesis to gates or FPGA:

1. **`syn/syn_aead.ys`** - Yosys synthesis script (AEAD-only)
2. **`syn/cmos_cells.lib`** - Cell library (if doing ASIC synthesis)

### To Synthesize:
```bash
# Using the AEAD-only makefile
make -f Makefile syn

# This will:
# - Read ascon_core_aead.sv
# - Synthesize to gates
# - Map to cell library
# - Output: syn_aead.v (synthesized netlist)
# - Print area/timing statistics
```

## Configuration Guide

### Hardware Variants (Choose One in config.sv or via -DV1):

| Variant | UROL | CCW | Speed      | Area      | Use Case                    |
|---------|------|-----|------------|-----------|----------------------------|
| **V1**  | 1    | 32  | Slowest    | Smallest  | Ultra-low area RFID tags   |
| V2      | 2    | 32  | Medium     | Medium    | Balanced tags              |
| V3      | 4    | 32  | Fast       | Large     | Performance tags           |
| V4      | 1    | 64  | Medium     | Medium    | Wider datapath             |
| V5      | 2    | 64  | Faster     | Larger    | High-performance readers   |
| V6      | 4    | 64  | Fastest    | Largest   | Maximum throughput         |

**For typical RFID tags, use V1 (smallest area).**

### Data Width Configuration:

- **CCW = 32**: Processes data in 4-byte (32-bit) chunks
  - Suitable for V1, V2, V3
  - More cycles, less hardware

- **CCW = 64**: Processes data in 8-byte (64-bit) chunks  
  - Suitable for V4, V5, V6
  - Fewer cycles, more hardware


### Port Interface:

```systemverilog
module ascon_core (
    // Clock and reset
    input  logic        clk,
    input  logic        rst,
    
    // Key input (128 bits total, transferred in CCW-bit chunks)
    input  logic [CCW-1:0] key,
    input  logic           key_valid,
    output logic           key_ready,
    
    // Block data input (nonce, AD, plaintext/ciphertext, tag)
    input  logic [CCW-1:0]   bdi,
    input  logic [CCW/8-1:0] bdi_valid,  // Byte enable
    output logic             bdi_ready,
    input  data_e            bdi_type,   // D_NONCE, D_AD, D_MSG, D_TAG
    input  logic             bdi_eot,    // End of type
    input  logic             bdi_eoi,    // End of input
    input  mode_e            mode,       // M_AEAD128_ENC or M_AEAD128_DEC
    
    // Block data output (ciphertext/plaintext, tag)
    output logic [CCW-1:0] bdo,
    output logic           bdo_valid,
    input  logic           bdo_ready,
    output data_e          bdo_type,     // D_MSG or D_TAG
    output logic           bdo_eot,      // End of type
    input  logic           bdo_eoo,      // End of output (early termination)
    
    // Status
    output logic auth,       // Authentication result (1=valid, 0=invalid)
    output logic auth_valid, // Authentication result ready
    output logic done        // Operation complete
);
```

### Typical Usage Sequence:

**Encryption:**
1. Set `mode = M_AEAD128_ENC`
2. Send key (4 or 2 transfers depending on CCW)
3. Send nonce (4 or 2 transfers)
4. Send associated data (optional)
5. Send plaintext → receive ciphertext
6. Receive tag (4 or 2 transfers)

**Decryption:**
1. Set `mode = M_AEAD128_DEC`
2. Send key
3. Send nonce
4. Send associated data (optional)
5. Send ciphertext → receive plaintext
6. Send received tag
7. Wait for `auth_valid`, check `auth` signal

## Size Estimates (V1 variant, typical)

- **Area**: ~5,000-8,000 gates (ASIC) or ~1,000-1,500 LUTs (FPGA)
- **Latency**: ~40-60 cycles for minimal message (no AD, no plaintext)
- **Throughput**: CCW bits per permutation round
- **Critical Path**: Through permutation S-box and diffusion layers
