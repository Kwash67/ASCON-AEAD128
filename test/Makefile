# This file is public domain, it can be freely copied without restrictions.
# SPDX-License-Identifier: CC0-1.0
# AEAD-only Makefile

MAKEFLAGS=-j8

# Hardware variant selection
VARIANT = V1
# VARIANT = V2
# VARIANT = V3
# VARIANT = V4
# VARIANT = V5
# VARIANT = V6

# Verilator arguments
SIM ?= verilator
TOPLEVEL_LANG ?= verilog
EXTRA_ARGS += --threads 8
EXTRA_ARGS += --relative-includes
EXTRA_ARGS += -Wno-UNOPTFLAT
EXTRA_ARGS += -D$(VARIANT)

# TOPLEVEL is the name of the toplevel module in your Verilog or VHDL file
TOPLEVEL = ascon_core

# MODULE is the basename of the Python test file
MODULE = test_aead_only

# Set source files
VERILOG_SOURCES = $(PWD)/../core_rtl/ascon_core_aead.sv

# Include cocotb makefile
include $(shell cocotb-config --makefiles)/Makefile.sim

# Synthesis using Yosys
syn:
	yosys -D${VARIANT} ../syn/syn_aead.ys

.PHONY: syn
