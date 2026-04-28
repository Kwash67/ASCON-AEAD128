import os
import sys
import random
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge
from cocotb.utils import get_sim_time

sys.path.append(str(Path(__file__).resolve().parents[1] / "test"))
from ascon import ascon_encrypt

VERBOSE = int(os.getenv("VERBOSE", "1"))
MAX_LEN = int(os.getenv("MAX_LEN", "10"))
RUNS = range(0, MAX_LEN)
STALLS = int(os.getenv("STALLS", "0"))

CLK_PERIOD_NS = 1.0

CCWD8 = 16

BDI_TYPE_NPUB = 0b00
BDI_TYPE_AD = 0b01
BDI_TYPE_MSG = 0b10
BDI_TYPE_TAG = 0b11


def log(dut, verbose, dashes, **kwargs):
    if verbose <= VERBOSE:
        for key, val in kwargs.items():
            dut._log.info(
                "%s %s %s",
                key,
                " " * (8 - len(key)),
                "".join("{:02X}".format(x) for x in val),
            )
        if dashes:
            dut._log.info("------------------------------------------")


def pack_bytes_to_word_le(data):
    word = 0
    for i, b in enumerate(data):
        word |= int(b) << (8 * i)
    return word


def unpack_word_to_bytes_by_valid(word, valid_mask):
    out = []
    raw = int(word).to_bytes(CCWD8, byteorder="big")
    for i in range(CCWD8):
        if valid_mask & (1 << i):
            out.append(raw[CCWD8 - 1 - i])
    return out


async def reset_inputs(dut):
    dut.decrypt.value = 0
    dut.key.value = 0
    dut.key_valid.value = 0

    dut.bdi.value = 0
    dut.bdi_valid.value = 0
    dut.bdi_type.value = 0
    dut.bdi_eot.value = 0
    dut.bdi_eoi.value = 0

    dut.bdo_ready.value = 0


async def reset_dut(dut):
    await reset_inputs(dut)
    dut.rst.value = 1
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)


async def send_key(dut, key_bytes):
    dut.key.value = pack_bytes_to_word_le(key_bytes)
    dut.key_valid.value = 1

    for _ in range(40):
        await RisingEdge(dut.clk)
        if int(dut.bdi_ready.value):
            break
    else:
        raise AssertionError("Timeout waiting for key load completion (LD_NPUB)")

    dut.key_valid.value = 0
    dut.key.value = 0


async def send_data(dut, data_in, bdi_type, bdo_ready, bdi_eoi_last):
    dlen = len(data_in)
    index = 0
    data_out = []

    while index < dlen:
        chunk = data_in[index : min(index + CCWD8, dlen)]
        valid_mask = (1 << len(chunk)) - 1

        dut.bdi.value = pack_bytes_to_word_le(chunk)
        dut.bdi_valid.value = valid_mask
        dut.bdi_type.value = bdi_type
        dut.bdi_eot.value = 1 if (index + len(chunk) >= dlen) else 0
        dut.bdi_eoi.value = 1 if (index + len(chunk) >= dlen and bdi_eoi_last) else 0
        dut.bdo_ready.value = 1 if bdo_ready else 0

        accepted = False
        for _ in range(400):
            if STALLS and (random.randint(0, 10) != 0):
                dut.bdi_valid.value = 0
                dut.bdo_ready.value = 0
            await RisingEdge(dut.clk)

            if int(dut.bdo_valid.value) and int(dut.bdo_ready.value):
                data_out.extend(
                    unpack_word_to_bytes_by_valid(dut.bdo.value, valid_mask)
                )

            if int(dut.bdi_valid.value) and int(dut.bdi_ready.value):
                accepted = True
                break

            if int(dut.bdi_valid.value) == 0:
                dut.bdi_valid.value = valid_mask
                dut.bdo_ready.value = 1 if bdo_ready else 0

        if not accepted:
            raise AssertionError(
                f"Timeout sending bdi_type={bdi_type} at index {index}"
            )

        index += len(chunk)

    dut.bdi.value = 0
    dut.bdi_valid.value = 0
    dut.bdo_ready.value = 0

    return data_out


async def receive_tag(dut):
    dut.bdo_ready.value = 1
    for _ in range(2000):
        await RisingEdge(dut.clk)
        if (
            int(dut.bdo_ready.value)
            and int(dut.bdo_valid.value)
            and int(dut.bdo_type.value) == BDI_TYPE_TAG
        ):
            dut.bdo_ready.value = 0
            return unpack_word_to_bytes_by_valid(dut.bdo.value, 0xFFFF)

    dut.bdo_ready.value = 0
    raise AssertionError("Timeout waiting for output tag")


async def wait_auth_valid(dut, timeout_cycles=3000):
    for _ in range(timeout_cycles):
        await RisingEdge(dut.clk)
        if int(dut.auth_valid.value):
            return
    raise AssertionError("Timeout waiting for auth_valid")


@cocotb.test()
async def test_enc(dut):
    random.seed(31415)
    if cocotb.__version__[0] == "2":
        clock = Clock(dut.clk, 1, unit="ns")
    else:
        clock = Clock(dut.clk, 1, units="ns")
    cocotb.start_soon(clock.start(start_high=False))

    await reset_dut(dut)
    dut.decrypt.value = 0

    key = bytearray([random.randint(0, 255) for _ in range(16)])
    npub = bytearray([random.randint(0, 255) for _ in range(16)])

    log(dut, verbose=2, dashes=1, key=key, npub=npub)

    for msglen in RUNS:
        for adlen in RUNS:
            dut._log.info("test      ENC ad:%d msg:%d", adlen, msglen)

            ad = bytearray([random.randint(0, 255) for _ in range(adlen)])
            pt = bytearray([random.randint(0, 255) for _ in range(msglen)])
            ct_ref, tag_ref = ascon_encrypt(
                bytes(key), bytes(npub), bytes(ad), bytes(pt)
            )

            log(dut, verbose=2, dashes=0, ad=ad, pt=pt, ct=ct_ref, tag=tag_ref)

            start_ns = get_sim_time(unit="ns")

            await send_key(dut, key)

            await send_data(
                dut,
                npub,
                BDI_TYPE_NPUB,
                bdo_ready=0,
                bdi_eoi_last=(adlen == 0 and msglen == 0),
            )

            if adlen > 0:
                await send_data(
                    dut,
                    ad,
                    BDI_TYPE_AD,
                    bdo_ready=0,
                    bdi_eoi_last=(msglen == 0),
                )

            ct_hw = []
            if msglen > 0:
                ct_hw = await send_data(
                    dut,
                    pt,
                    BDI_TYPE_MSG,
                    bdo_ready=1,
                    bdi_eoi_last=1,
                )

            tag_hw = await receive_tag(dut)

            end_ns = get_sim_time(unit="ns")
            latency_ns = end_ns - start_ns
            latency_cycles = int(round(latency_ns / CLK_PERIOD_NS))

            assert bytes(ct_hw) == bytes(ct_ref), "ct mismatch"
            assert bytes(tag_hw) == bytes(tag_ref), "tag mismatch"

            dut._log.info(
                "latency   ENC ad:%d msg:%d cycles:%d time_ns:%.1f",
                adlen,
                msglen,
                latency_cycles,
                latency_ns,
            )

            await RisingEdge(dut.clk)
            log(dut, verbose=1, dashes=1)


@cocotb.test()
async def test_dec(dut):
    random.seed(27182)
    if cocotb.__version__[0] == "2":
        clock = Clock(dut.clk, 1, unit="ns")
    else:
        clock = Clock(dut.clk, 1, units="ns")
    cocotb.start_soon(clock.start(start_high=False))

    await reset_dut(dut)
    dut.decrypt.value = 1

    key = bytearray([random.randint(0, 255) for _ in range(16)])
    npub = bytearray([random.randint(0, 255) for _ in range(16)])

    log(dut, verbose=2, dashes=1, key=key, npub=npub)

    for msglen in RUNS:
        for adlen in RUNS:
            dut._log.info("test      DEC ad:%d msg:%d", adlen, msglen)

            ad = bytearray([random.randint(0, 255) for _ in range(adlen)])
            pt_ref = bytearray([random.randint(0, 255) for _ in range(msglen)])
            ct_ref, tag_ref = ascon_encrypt(
                bytes(key), bytes(npub), bytes(ad), bytes(pt_ref)
            )

            log(dut, verbose=2, dashes=0, ad=ad, ct=ct_ref, tag=tag_ref, pt=pt_ref)

            start_ns = get_sim_time(unit="ns")

            await send_key(dut, key)

            await send_data(
                dut,
                npub,
                BDI_TYPE_NPUB,
                bdo_ready=0,
                bdi_eoi_last=(adlen == 0 and msglen == 0),
            )

            if adlen > 0:
                await send_data(
                    dut,
                    ad,
                    BDI_TYPE_AD,
                    bdo_ready=0,
                    bdi_eoi_last=(msglen == 0),
                )

            pt_hw = []
            if msglen > 0:
                pt_hw = await send_data(
                    dut,
                    ct_ref,
                    BDI_TYPE_MSG,
                    bdo_ready=1,
                    bdi_eoi_last=0,
                )

            await send_data(
                dut,
                tag_ref,
                BDI_TYPE_TAG,
                bdo_ready=0,
                bdi_eoi_last=1,
            )

            await wait_auth_valid(dut)
            end_ns = get_sim_time(unit="ns")
            latency_ns = end_ns - start_ns
            latency_cycles = int(round(latency_ns / CLK_PERIOD_NS))

            assert int(dut.auth.value) == 1, "auth failed"
            assert bytes(pt_hw) == bytes(pt_ref), "pt mismatch"

            dut._log.info(
                "latency   DEC ad:%d msg:%d cycles:%d time_ns:%.1f",
                adlen,
                msglen,
                latency_cycles,
                latency_ns,
            )

            await RisingEdge(dut.clk)
            log(dut, verbose=1, dashes=1)
