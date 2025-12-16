# This file is public domain, it can be freely copied without restrictions.
# SPDX-License-Identifier: CC0-1.0
# AEAD-only version of test.py (removed HASH/XOF/CXOF tests)

import cocotb
from cocotb.triggers import RisingEdge
from cocotb.clock import Clock

import random
from enum import Enum

from ascon import *

VERBOSE = 1
RUNS = range(0, 10)
# RUNS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 256, 512, 1024]
CCW = 32
# CCW = 64
CCWD8 = CCW // 8
STALLS = 0


# Needs to match "mode_e" in "core_rtl/config.sv"
class Mode(Enum):
    M_INVALID = 0
    M_AEAD128_ENC = 1
    M_AEAD128_DEC = 2


# Needs to match "data_type_e" in "core_rtl/config.sv"
class Data(Enum):
    D_INVALID = 0
    D_NONCE = 1
    D_AD = 2
    D_MSG = 3
    D_TAG = 4


# Reset BDI signals
async def clear_bdi(dut):
    dut.bdi.value = 0
    dut.bdi_valid.value = 0
    dut.bdi_type.value = 0
    dut.bdi_eot.value = 0
    dut.bdi_eoi.value = 0
    dut.bdo_ready.value = 0


# Send data of specific type to dut
async def send_data(dut, data_in, bdi_type, bdo_ready, bdi_eoi):
    dlen = len(data_in)
    d = 0
    data_out = []
    while d < dlen:
        bdi = 0
        bdi_valid = 0
        for dd in range(d, min(d + CCWD8, dlen)):
            bdi |= data_in[dd] << 8 * (dd % CCWD8)
            bdi_valid |= 1 << (dd % CCWD8)
        dut.bdi.value = bdi
        dut.bdi_valid.value = bdi_valid
        dut.bdi_type.value = bdi_type
        dut.bdi_eot.value = d + CCWD8 >= dlen
        dut.bdi_eoi.value = d + CCWD8 >= dlen and bdi_eoi
        dut.bdo_ready.value = bdo_ready
        if STALLS and (random.randint(0, 10) != 0):
            await clear_bdi(dut)
        await RisingEdge(dut.clk)
        if int(dut.bdi_valid.value) and int(dut.bdi_ready.value):
            if VERBOSE >= 3:
                dut._log.info("bdi:      {:08X}".format(bdi))
            bdo_bytes = int(dut.bdo.value).to_bytes(CCWD8, byteorder="big")
            for dd in range(CCWD8):
                if bdi_valid & (1 << dd):
                    data_out.append(bdo_bytes[CCWD8 - 1 - dd])
            d += CCWD8
    await clear_bdi(dut)
    return data_out


# Send key data to dut
async def send_key(dut, key_in):
    k = 0
    while k < 16:
        key2 = 0
        for kk in range(k, min(k + CCWD8, 16)):
            key2 |= key_in[kk] << 8 * (kk % CCWD8)
        dut.key.value = key2
        dut.key_valid.value = 1
        await RisingEdge(dut.clk)
        if int(dut.key_ready.value):
            if VERBOSE >= 3:
                dut._log.info("key:      {:08X}".format(int(dut.key.value)))
            k += CCWD8
    dut.key.value = 0
    dut.key_valid.value = 0


# Receive data of specific type from dut
async def receive_data(dut, type, len=16, bdo_eoo=0):
    d = 0
    data_out = []
    while d < len:
        dut.bdo_ready.value = 1
        dut.bdo_eoo.value = (d + CCWD8 >= len) & bdo_eoo
        if STALLS and (random.randint(0, 10) != 0):
            dut.bdo_ready.value = 0
            dut.bdo_eoo.value = 0
        await RisingEdge(dut.clk)
        if (
            int(dut.bdo_ready.value)
            and int(dut.bdo_valid.value)
            and (int(dut.bdo_type.value) == type)
        ):
            if VERBOSE >= 3:
                dut._log.info("bdo:      {:08X}".format(int(dut.bdo.value)))
            bdo_bytes = int(dut.bdo.value).to_bytes(CCWD8, byteorder="big")
            for dd in range(CCWD8):
                data_out.append(bdo_bytes[CCWD8 - 1 - dd])
            d += CCWD8
    dut.bdo_ready.value = 0
    dut.bdo_eoo.value = 0
    return data_out


# Toggle the value of one signal
async def toggle(dut, signalStr, value):
    eval(signalStr, dict(dut=cocotb.top)).value = value
    await RisingEdge(dut.clk)
    eval(signalStr, dict(dut=cocotb.top)).value = 0


# Log the content of multiple byte arrays
def log(dut, verbose, dashes, **kwargs):
    if verbose <= VERBOSE:
        for k, val in kwargs.items():
            dut._log.info(
                "%s %s %s",
                k,
                " " * (8 - len(k)),
                "".join("{:02X}".format(x) for x in val),
            )
        if dashes:
            dut._log.info("------------------------------------------")


# Count cycles until dut reaches IDLE state
async def cycle_cnt(dut):
    cycles = 1
    await RisingEdge(dut.clk)
    while 1:
        await RisingEdge(dut.clk)
        if int(dut.fsm.value) == 1:
            if VERBOSE >= 1:
                dut._log.info("cycles    %d", cycles)
            return
        cycles += 1


# Test case fails if dut fsm state stays the same for 100 cycles
async def timeout(dut):
    last_fsm = 0
    last_fsm_cycles = 0
    await RisingEdge(dut.clk)
    while 1:
        await RisingEdge(dut.clk)
        dut_fsm = int(dut.fsm.value)
        if dut_fsm == last_fsm:
            last_fsm_cycles += 1
        else:
            last_fsm_cycles = 0
            last_fsm = int(dut.fsm.value)
        if last_fsm_cycles >= 1000:
            assert False, "Timeout"
        if dut_fsm == int.from_bytes("IDLE".encode("ascii"), byteorder="big"):
            return


@cocotb.test()
async def test_enc(dut):

    # init test
    random.seed(31415)
    mode = Mode.M_AEAD128_ENC
    if cocotb.__version__[0] == "2":
        clock = Clock(dut.clk, 1, unit="ns")
    else:
        clock = Clock(dut.clk, 1, units="ns")
    cocotb.start_soon(clock.start(start_high=False))
    cocotb.start_soon(toggle(dut, "dut.rst", 1))
    await RisingEdge(dut.clk)

    key = bytearray([random.randint(0, 255) for x in range(16)])
    npub = bytearray([random.randint(0, 255) for x in range(16)])

    log(dut, verbose=2, dashes=1, key=key, npub=npub)

    for msglen in RUNS:
        for adlen in RUNS:
            dut._log.info("test      %s ad:%d msg:%d", mode.name, adlen, msglen)

            ad = bytearray([random.randint(0, 255) for x in range(adlen)])
            pt = bytearray([random.randint(0, 255) for x in range(msglen)])

            # compute in software
            (ct, tag) = ascon_encrypt(key, npub, ad, pt)

            log(dut, verbose=2, dashes=0, ad=ad, pt=pt, ct=ct, tag=tag)

            cocotb.start_soon(cycle_cnt(dut))
            cocotb.start_soon(timeout(dut))
            cocotb.start_soon(toggle(dut, "dut.mode", mode.value))

            # send key
            await send_key(dut, key)

            # send nonce
            await send_data(
                dut, npub, Data.D_NONCE.value, 0, (adlen == 0) and (msglen == 0)
            )

            # send ad
            if adlen > 0:
                await send_data(dut, ad, Data.D_AD.value, 0, (msglen == 0))

            # send pt/ct
            if msglen > 0:
                ct_hw = await send_data(dut, pt, Data.D_MSG.value, 1, 1)
                log(dut, verbose=2, dashes=0, ct_hw=ct_hw)

            # receive tag
            tag_hw = await receive_data(dut, Data.D_TAG.value)
            log(dut, verbose=2, dashes=0, tag_hw=tag_hw)

            # check ciphertext
            for i in range(len(ct)):
                assert ct_hw[i] == ct[i], "ct mismatch"

            # check tag
            for i in range(len(tag)):
                assert tag_hw[i] == tag[i], "tag mismatch"

            await RisingEdge(dut.clk)

            log(dut, verbose=1, dashes=1)


@cocotb.test()
async def test_dec(dut):

    # init test
    random.seed(27182)
    mode = Mode.M_AEAD128_DEC
    if cocotb.__version__[0] == "2":
        clock = Clock(dut.clk, 1, unit="ns")
    else:
        clock = Clock(dut.clk, 1, units="ns")
    cocotb.start_soon(clock.start(start_high=False))
    cocotb.start_soon(toggle(dut, "dut.rst", 1))
    await RisingEdge(dut.clk)

    key = bytearray([random.randint(0, 255) for x in range(16)])
    npub = bytearray([random.randint(0, 255) for x in range(16)])

    log(dut, verbose=2, dashes=1, key=key, npub=npub)

    for msglen in RUNS:
        for adlen in RUNS:
            dut._log.info("test      %s ad:%d msg:%d", mode.name, adlen, msglen)

            ad = bytearray([random.randint(0, 255) for x in range(adlen)])
            pt = bytearray([random.randint(0, 255) for x in range(msglen)])

            # compute in software
            (ct, tag) = ascon_encrypt(key, npub, ad, pt)

            log(dut, verbose=2, dashes=0, ad=ad, ct=ct, tag=tag, pt=pt)

            cocotb.start_soon(cycle_cnt(dut))
            cocotb.start_soon(timeout(dut))
            cocotb.start_soon(toggle(dut, "dut.mode", mode.value))

            # send key
            await send_key(dut, key)

            # send nonce
            await send_data(
                dut, npub, Data.D_NONCE.value, 0, (adlen == 0) and (msglen == 0)
            )

            # send ad
            if adlen > 0:
                await send_data(dut, ad, Data.D_AD.value, 0, (msglen == 0))

            # send ct/pt
            if msglen > 0:
                pt_hw = await send_data(dut, ct, Data.D_MSG.value, 1, 0)
                log(dut, verbose=2, dashes=0, pt_hw=pt_hw)

            # send tag
            await send_data(dut, tag, Data.D_TAG.value, 0, 1)

            # check decrypted plaintext
            for i in range(len(pt)):
                assert pt_hw[i] == pt[i], "pt mismatch"

            # Wait for authentication check
            while not int(dut.auth_valid.value):
                await RisingEdge(dut.clk)

            # check authentication
            assert int(dut.auth.value) == 1, "auth failed"

            await RisingEdge(dut.clk)

            log(dut, verbose=1, dashes=1)
