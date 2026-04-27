#!/usr/bin/env python3
"""Quiet Apple Magic Trackpad battery reader.

Prints only the source that worked and the battery percentage. The verbose
decoder remains in decode_magic_trackpad_battery.py.
"""

from __future__ import annotations

import fcntl
import glob
import os
import re
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


REPORT_ID = 0x90
APPLE_BT_VENDOR_ID = 0x004C
APPLE_USB_VENDOR_ID = 0x05AC

BUS_NAMES = {
    0x0003: "USB HID",
    0x0005: "Bluetooth HID",
}

IOC_NRBITS = 8
IOC_TYPEBITS = 8
IOC_SIZEBITS = 14
IOC_NRSHIFT = 0
IOC_TYPESHIFT = IOC_NRSHIFT + IOC_NRBITS
IOC_SIZESHIFT = IOC_TYPESHIFT + IOC_TYPEBITS
IOC_DIRSHIFT = IOC_SIZESHIFT + IOC_SIZEBITS
IOC_READ = 2
IOC_WRITE = 1


@dataclass
class HidDevice:
    path: str
    name: str
    bustype: int
    vendor: int
    product: int


@dataclass
class BatteryReading:
    percent: int
    path: str
    detail: str
    status: str | None = None


def _ioc(direction: int, type_: str, nr: int, size: int) -> int:
    return (
        (direction << IOC_DIRSHIFT)
        | (ord(type_) << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)
        | (size << IOC_SIZESHIFT)
    )


def hid_iocgrawinfo() -> int:
    return _ioc(IOC_READ, "H", 0x03, struct.calcsize("Ihh"))


def hid_iocgrawname(length: int) -> int:
    return _ioc(IOC_READ, "H", 0x04, length)


def hid_iocginput(length: int) -> int:
    return _ioc(IOC_READ | IOC_WRITE, "H", 0x0A, length)


def hidraw_sort_key(path: str) -> tuple[int, str]:
    match = re.search(r"(\d+)$", Path(path).name)
    if match:
        return int(match.group(1)), path
    return sys.maxsize, path


def read_hid_device(path: str) -> HidDevice:
    fd = os.open(path, os.O_RDWR)
    try:
        info = bytearray(struct.calcsize("Ihh"))
        fcntl.ioctl(fd, hid_iocgrawinfo(), info, True)
        bustype, vendor, product = struct.unpack("Ihh", info)

        raw_name = bytearray(256)
        fcntl.ioctl(fd, hid_iocgrawname(len(raw_name)), raw_name, True)
        name = raw_name.split(b"\0", 1)[0].decode("utf-8", "replace")
    finally:
        os.close(fd)

    return HidDevice(
        path=path,
        name=name,
        bustype=bustype,
        vendor=vendor & 0xFFFF,
        product=product & 0xFFFF,
    )


def is_magic_trackpad(device: HidDevice) -> bool:
    if "Magic Trackpad" in device.name:
        return True
    return device.vendor in {APPLE_BT_VENDOR_ID, APPLE_USB_VENDOR_ID} and device.product == 0x0265


def query_hid_report(path: str) -> bytes:
    fd = os.open(path, os.O_RDWR)
    try:
        report = bytearray([REPORT_ID, 0, 0, 0])
        fcntl.ioctl(fd, hid_iocginput(len(report)), report, True)
        return bytes(report)
    finally:
        os.close(fd)


def direct_hid_reading() -> BatteryReading | None:
    for path in sorted(glob.glob("/dev/hidraw*"), key=hidraw_sort_key):
        try:
            device = read_hid_device(path)
        except OSError:
            continue
        if not is_magic_trackpad(device):
            continue

        try:
            report = query_hid_report(device.path)
        except OSError:
            continue
        if len(report) < 3 or report[0] != REPORT_ID:
            continue

        percent = report[2]
        if not 0 <= percent <= 100:
            continue

        flags = report[1]
        if flags & 0x04:
            status = "fully charged"
        elif flags & 0x02:
            status = "charging"
        else:
            status = None

        bus = BUS_NAMES.get(device.bustype, f"bus 0x{device.bustype:04x}")
        detail = f"{bus}, {device.path}, report 0x{REPORT_ID:02x}"
        return BatteryReading(percent=percent, path="direct HID", detail=detail, status=status)
    return None


def parse_upower_device(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        values[key.strip()] = value.strip()
    return values


def upower_reading() -> BatteryReading | None:
    if not shutil.which("upower"):
        return None
    try:
        objects = subprocess.run(
            ["upower", "-e"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError):
        return None

    for obj in objects:
        try:
            output = subprocess.run(
                ["upower", "-i", obj],
                check=True,
                text=True,
                capture_output=True,
            ).stdout
        except (OSError, subprocess.CalledProcessError):
            continue

        values = parse_upower_device(output)
        model = values.get("model", "")
        if "Magic Trackpad" not in model:
            continue

        updated = values.get("updated", "")
        icon = values.get("icon-name", "")
        percentage = values.get("percentage", "")
        if "1970" in updated or "missing" in icon:
            continue

        match = re.search(r"(\d+(?:\.\d+)?)%", percentage)
        if not match:
            continue
        percent = round(float(match.group(1)))
        if not 0 <= percent <= 100:
            continue

        native = values.get("native-path", obj)
        status = values.get("state")
        return BatteryReading(percent=percent, path="UPower", detail=native, status=status)
    return None


def main() -> int:
    reading = direct_hid_reading() or upower_reading()
    if not reading:
        print("Magic Trackpad battery: unavailable")
        print("Path: no direct HID report or fresh UPower value found")
        return 1

    print(f"Magic Trackpad battery: {reading.percent}%")
    print(f"Path: {reading.path} ({reading.detail})")
    if reading.status:
        print(f"Status: {reading.status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
