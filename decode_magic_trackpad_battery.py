#!/usr/bin/env python3
"""Read and decode the Apple Magic Trackpad battery/status HID report.

The script queries a Magic Trackpad hidraw device for input report 0x90 and
decodes the fields named by the device's HID report descriptor:

  - Power.Good
  - BatterySystem.Charging
  - BatterySystem.FullyCharged
  - BatterySystem.AbsoluteStateOfCharge

It also prints the kernel power_supply snapshot when present, because that is
the path UPower normally reads and it can be stale or wrong on affected kernels.

For this Apple trackpad, Linux's power_supply and UPower layers treat
BatterySystem.AbsoluteStateOfCharge as a direct percent value, even though the
HID descriptor advertises a broad 0..255 logical range. The script reports that
direct percent as the battery level.
"""

from __future__ import annotations

import argparse
import errno
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


DEFAULT_REPORT_ID = 0x90
APPLE_BT_VENDOR_ID = 0x004C
APPLE_USB_VENDOR_ID = 0x05AC

USAGE_NAMES = {
    (0x84, 0x61): "Power.Good",
    (0x85, 0x44): "BatterySystem.Charging",
    (0x85, 0x46): "BatterySystem.FullyCharged",
    (0x85, 0x65): "BatterySystem.AbsoluteStateOfCharge",
}

REPORT_KIND_INPUT = "input"
REPORT_KIND_OUTPUT = "output"
REPORT_KIND_FEATURE = "feature"


@dataclass
class HidDevice:
    path: str
    name: str
    bustype: int
    vendor: int
    product: int


@dataclass
class BluetoothDevice:
    address: str
    name: str
    properties: dict[str, str]


@dataclass
class QueryFailure:
    path: str
    name: str
    message: str


@dataclass
class HidField:
    kind: str
    report_id: int
    offset: int
    size: int
    count: int
    usages: list[tuple[int, int]]
    logical_min: int
    logical_max: int
    flags: int


@dataclass
class DecodedValue:
    name: str
    usage_page: int
    usage: int
    offset: int
    size: int
    value: int
    logical_min: int
    logical_max: int


# Linux ioctl bit layout from asm-generic/ioctl.h.
IOC_NRBITS = 8
IOC_TYPEBITS = 8
IOC_SIZEBITS = 14
IOC_NRSHIFT = 0
IOC_TYPESHIFT = IOC_NRSHIFT + IOC_NRBITS
IOC_SIZESHIFT = IOC_TYPESHIFT + IOC_TYPEBITS
IOC_DIRSHIFT = IOC_SIZESHIFT + IOC_SIZEBITS
IOC_READ = 2
IOC_WRITE = 1


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


def parse_int(text: str) -> int:
    return int(text, 0)


def maybe_reexec_with_sudo(args: argparse.Namespace) -> None:
    if args.no_auto_sudo or os.geteuid() == 0:
        return
    if not sys.stdin.isatty():
        return
    sudo = shutil.which("sudo")
    if not sudo:
        return
    os.execvp(sudo, [sudo, sys.executable, os.path.abspath(__file__), *sys.argv[1:]])


def suggest_sudo(args: argparse.Namespace) -> None:
    if args.no_auto_sudo or os.geteuid() == 0:
        return
    print("Try running this script with sudo.", file=sys.stderr)


def open_hidraw(path: str) -> int:
    return os.open(path, os.O_RDWR)


def hidraw_sort_key(path: str) -> tuple[int, str]:
    match = re.search(r"(\d+)$", Path(path).name)
    if match:
        return int(match.group(1)), path
    return sys.maxsize, path


def read_device_info(path: str) -> HidDevice:
    fd = open_hidraw(path)
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
    if device.vendor in {APPLE_BT_VENDOR_ID, APPLE_USB_VENDOR_ID} and device.product == 0x0265:
        return True
    return False


def discover_magic_trackpads() -> tuple[list[HidDevice], list[str]]:
    errors: list[str] = []
    devices: list[HidDevice] = []
    for path in sorted(glob.glob("/dev/hidraw*"), key=hidraw_sort_key):
        try:
            device = read_device_info(path)
        except OSError as exc:
            errors.append(f"{path}: {exc.strerror}")
            continue
        if is_magic_trackpad(device):
            devices.append(device)
    return devices, errors


def query_first_magic_trackpad(report_id: int, length: int) -> tuple[HidDevice, bytes, list[QueryFailure], list[str]]:
    devices, discovery_errors = discover_magic_trackpads()
    failures: list[QueryFailure] = []
    for device in devices:
        try:
            return device, query_input_report(device.path, report_id, length), failures, discovery_errors
        except OSError as exc:
            failures.append(QueryFailure(device.path, device.name, exc.strerror or str(exc)))

    if devices:
        tried = ", ".join(device.path for device in devices)
        lines = [f"No Magic Trackpad hidraw interface returned report 0x{report_id:02x}; tried {tried}."]
        for failure in failures:
            lines.append(f"  {failure.path} ({failure.name}): {failure.message}")
        raise RuntimeError("\n".join(lines))

    detail = "\n".join(f"  {line}" for line in discovery_errors[:8])
    suffix = f"\nOpen errors:\n{detail}" if detail else ""
    raise RuntimeError(f"No connected Magic Trackpad hidraw device found.{suffix}")


def bluetooth_magic_trackpads() -> list[BluetoothDevice]:
    if not shutil.which("bluetoothctl"):
        return []
    try:
        output = subprocess.run(
            ["bluetoothctl", "devices"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return []

    devices: list[BluetoothDevice] = []
    for line in output.splitlines():
        match = re.match(r"(?:Device|\[[^\]]+\]\s+Device)\s+([0-9A-Fa-f:]{17})\s+(.+)$", line.strip())
        if not match:
            continue
        address, name = match.groups()
        if "Magic Trackpad" not in name:
            continue
        properties = bluetooth_device_properties(address)
        devices.append(BluetoothDevice(address=address, name=name, properties=properties))
    return devices


def bluetooth_device_properties(address: str) -> dict[str, str]:
    try:
        output = subprocess.run(
            ["bluetoothctl", "info", address],
            check=False,
            text=True,
            capture_output=True,
        ).stdout
    except OSError:
        return {}

    properties: dict[str, str] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        properties[key.strip()] = value.strip()
    return properties


def print_bluetooth_state() -> None:
    devices = bluetooth_magic_trackpads()
    if not devices:
        print("Bluetooth Magic Trackpad State")
        print("  No Magic Trackpad entry found in bluetoothctl.")
        print("  If the device was removed/unpaired, pair or connect it before reading Bluetooth battery data.")
        print()
        return

    print("Bluetooth Magic Trackpad State")
    for device in devices:
        print(f"  {device.name} ({device.address})")
        for key in ("Paired", "Bonded", "Trusted", "Blocked", "Connected"):
            if key in device.properties:
                print(f"    {key}: {device.properties[key]}")
    print()


def query_input_report(path: str, report_id: int, length: int) -> bytes:
    if length < 2:
        raise ValueError("report length must be at least 2 bytes")

    fd = open_hidraw(path)
    try:
        buf = bytearray([report_id] + [0] * (length - 1))
        fcntl.ioctl(fd, hid_iocginput(len(buf)), buf, True)
        return bytes(buf)
    finally:
        os.close(fd)


def hidraw_sysfs_dir(path: str) -> Path:
    return Path("/sys/class/hidraw") / Path(path).name


def read_report_descriptor(path: str) -> bytes | None:
    descriptor = hidraw_sysfs_dir(path) / "device" / "report_descriptor"
    try:
        return descriptor.read_bytes()
    except OSError:
        return None


def hid_item_value(data: bytes, *, signed: bool = False) -> int:
    if not data:
        return 0
    return int.from_bytes(data, "little", signed=signed)


def parse_report_descriptor(descriptor: bytes) -> list[HidField]:
    fields: list[HidField] = []
    offsets: dict[tuple[str, int], int] = {}

    usage_page = 0
    logical_min = 0
    logical_max = 0
    report_size = 0
    report_count = 0
    report_id = 0
    usages: list[tuple[int, int]] = []
    usage_min: tuple[int, int] | None = None
    usage_max: tuple[int, int] | None = None

    def reset_local() -> None:
        nonlocal usages, usage_min, usage_max
        usages = []
        usage_min = None
        usage_max = None

    def expanded_usages() -> list[tuple[int, int]]:
        if usages:
            return usages[:]
        if usage_min and usage_max and usage_min[0] == usage_max[0]:
            page = usage_min[0]
            return [(page, usage) for usage in range(usage_min[1], usage_max[1] + 1)]
        return []

    i = 0
    while i < len(descriptor):
        prefix = descriptor[i]
        i += 1

        if prefix == 0xFE:
            if i + 2 > len(descriptor):
                break
            long_size = descriptor[i]
            i += 2 + long_size
            continue

        size_code = prefix & 0x03
        size = 4 if size_code == 3 else size_code
        item_type = (prefix >> 2) & 0x03
        tag = (prefix >> 4) & 0x0F
        data = descriptor[i : i + size]
        i += size

        unsigned_value = hid_item_value(data)
        signed_value = hid_item_value(data, signed=True)

        if item_type == 0:  # Main
            kind = None
            if tag == 0x08:
                kind = REPORT_KIND_INPUT
            elif tag == 0x09:
                kind = REPORT_KIND_OUTPUT
            elif tag == 0x0B:
                kind = REPORT_KIND_FEATURE

            if kind:
                key = (kind, report_id)
                offset = offsets.get(key, 0)
                fields.append(
                    HidField(
                        kind=kind,
                        report_id=report_id,
                        offset=offset,
                        size=report_size,
                        count=report_count,
                        usages=expanded_usages(),
                        logical_min=logical_min,
                        logical_max=logical_max,
                        flags=unsigned_value,
                    )
                )
                offsets[key] = offset + report_size * report_count
                reset_local()
            elif tag in {0x0A, 0x0C}:  # Collection / End Collection
                reset_local()

        elif item_type == 1:  # Global
            if tag == 0x00:
                usage_page = unsigned_value
            elif tag == 0x01:
                logical_min = signed_value
            elif tag == 0x02:
                logical_max = signed_value
            elif tag == 0x07:
                report_size = unsigned_value
            elif tag == 0x08:
                report_id = unsigned_value
            elif tag == 0x09:
                report_count = unsigned_value

        elif item_type == 2:  # Local
            if tag == 0x00:
                if size == 4:
                    page = (unsigned_value >> 16) & 0xFFFF
                    usage = unsigned_value & 0xFFFF
                else:
                    page = usage_page
                    usage = unsigned_value
                usages.append((page, usage))
            elif tag == 0x01:
                usage_min = (usage_page, unsigned_value)
            elif tag == 0x02:
                usage_max = (usage_page, unsigned_value)

    return fields


def extract_bits(raw_report: bytes, offset: int, size: int) -> int:
    value = 0
    for bit_index in range(size):
        payload_bit = offset + bit_index
        byte_index = 1 + payload_bit // 8
        if byte_index >= len(raw_report):
            break
        bit = (raw_report[byte_index] >> (payload_bit % 8)) & 1
        value |= bit << bit_index
    return value


def decode_report(raw_report: bytes, fields: list[HidField], report_id: int) -> list[DecodedValue]:
    decoded: list[DecodedValue] = []
    for field in fields:
        if field.kind != REPORT_KIND_INPUT or field.report_id != report_id:
            continue
        if field.flags & 0x01:  # Constant padding.
            continue
        for index in range(field.count):
            if index >= len(field.usages):
                continue
            usage_page, usage = field.usages[index]
            name = USAGE_NAMES.get((usage_page, usage), f"UsagePage0x{usage_page:02x}.0x{usage:02x}")
            decoded.append(
                DecodedValue(
                    name=name,
                    usage_page=usage_page,
                    usage=usage,
                    offset=field.offset + index * field.size,
                    size=field.size,
                    value=extract_bits(raw_report, field.offset + index * field.size, field.size),
                    logical_min=field.logical_min,
                    logical_max=field.logical_max,
                )
            )
    return decoded


def fallback_fields(report_id: int) -> list[HidField]:
    return [
        HidField(
            kind=REPORT_KIND_INPUT,
            report_id=report_id,
            offset=0,
            size=1,
            count=3,
            usages=[(0x84, 0x61), (0x85, 0x44), (0x85, 0x46)],
            logical_min=0,
            logical_max=1,
            flags=0x02,
        ),
        HidField(
            kind=REPORT_KIND_INPUT,
            report_id=report_id,
            offset=8,
            size=8,
            count=1,
            usages=[(0x85, 0x65)],
            logical_min=0,
            logical_max=255,
            flags=0x02,
        ),
    ]


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def power_supply_snapshot(hidraw_path: str) -> list[tuple[str, dict[str, str]]]:
    root = hidraw_sysfs_dir(hidraw_path) / "device" / "power_supply"
    if not root.exists():
        return []

    snapshots: list[tuple[str, dict[str, str]]] = []
    for supply in sorted(root.iterdir()):
        if not supply.is_dir():
            continue
        values: dict[str, str] = {}
        for key in ("model_name", "status", "capacity", "present", "online", "scope", "type"):
            value = read_text(supply / key)
            if value is not None:
                values[key] = value
        snapshots.append((supply.name, values))
    return snapshots


def upower_snapshot(native_name: str) -> dict[str, str] | None:
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
        if f"native-path:          {native_name}" not in output:
            continue
        values: dict[str, str] = {}
        for line in output.splitlines():
            stripped = line.strip()
            if ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            if key in {"native-path", "model", "updated", "state", "warning-level", "percentage", "icon-name"}:
                values[key] = value.strip()
        return values
    return None


def format_bool(value: int) -> str:
    return "yes" if value else "no"


def direct_percent(item: DecodedValue) -> int | None:
    if 0 <= item.value <= 100:
        return item.value
    return None


def print_report(device: HidDevice, raw_report: bytes, decoded: list[DecodedValue], descriptor_used: bool) -> None:
    by_name = {item.name: item for item in decoded}
    charge = by_name.get("BatterySystem.AbsoluteStateOfCharge")
    charging = by_name.get("BatterySystem.Charging")
    fully_charged = by_name.get("BatterySystem.FullyCharged")
    power_good = by_name.get("Power.Good")

    print("Device")
    print(f"  hidraw:  {device.path}")
    print(f"  name:    {device.name}")
    print(f"  bus:     0x{device.bustype:04x}")
    print(f"  vendor:  0x{device.vendor:04x}")
    print(f"  product: 0x{device.product:04x}")
    print()

    print("Raw HID Input Report")
    print(f"  report id: 0x{raw_report[0]:02x}")
    print("  bytes:     " + " ".join(f"{byte:02x}" for byte in raw_report))
    print()

    source = "current HID report descriptor" if descriptor_used else "built-in fallback mapping"
    print(f"Decoded Fields ({source})")
    if not decoded:
        print("  No known fields decoded.")
    for item in decoded:
        print(
            f"  {item.name}: {item.value} "
            f"(usage 0x{item.usage_page:02x}:0x{item.usage:02x}, "
            f"offset {item.offset} bits, size {item.size}, "
            f"logical {item.logical_min}..{item.logical_max})"
        )
    print()

    print("Meaning")
    if power_good:
        print(f"  Power.Good: {format_bool(power_good.value)}")
    if charging:
        print(f"  Charging: {format_bool(charging.value)}")
    if fully_charged:
        print(f"  Fully charged: {format_bool(fully_charged.value)}")

    if fully_charged and fully_charged.value:
        charge_state = "fully charged"
    elif charging and charging.value:
        charge_state = "charging"
    else:
        charge_state = "not charging / discharging / unknown"
    print(f"  Derived charge state: {charge_state}")

    if charge:
        percent = direct_percent(charge)
        print(f"  AbsoluteStateOfCharge raw byte: 0x{charge.value:02x} ({charge.value})")
        print(f"  Descriptor logical range: {charge.logical_min}..{charge.logical_max}")
        if percent is None:
            print("  Battery level: unknown; raw charge is outside 0..100")
        else:
            print(f"  Battery level: {percent}%")
    print()


def print_power_layers(device: HidDevice) -> None:
    snapshots = power_supply_snapshot(device.path)
    if not snapshots:
        return

    print("Kernel power_supply Snapshot")
    for name, values in snapshots:
        print(f"  {name}")
        for key, value in values.items():
            print(f"    {key}: {value}")
    print()

    for name, _values in snapshots:
        upower = upower_snapshot(name)
        if not upower:
            continue
        print("UPower Snapshot")
        print(f"  object native path: {name}")
        for key, value in upower.items():
            print(f"    {key}: {value}")
        print()
        break


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode Apple Magic Trackpad HID battery/status report 0x90."
    )
    parser.add_argument(
        "--hidraw",
        help="Specific hidraw device path, e.g. /dev/hidraw8. If omitted, scan for Magic Trackpad.",
    )
    parser.add_argument(
        "--report-id",
        type=parse_int,
        default=DEFAULT_REPORT_ID,
        help="Input report ID to query. Default: 0x90.",
    )
    parser.add_argument(
        "--length",
        type=int,
        default=4,
        help="Number of bytes to request, including the report ID byte. Default: 4.",
    )
    parser.add_argument(
        "--no-auto-sudo",
        action="store_true",
        help="Do not re-run through sudo when launched from an interactive non-root shell.",
    )
    args = parser.parse_args()

    maybe_reexec_with_sudo(args)

    try:
        if args.hidraw:
            device = read_device_info(args.hidraw)
            raw_report = query_input_report(device.path, args.report_id, args.length)
        else:
            device, raw_report, _failures, _discovery_errors = query_first_magic_trackpad(
                args.report_id, args.length
            )
    except PermissionError as exc:
        print(f"Permission denied while reading hidraw: {exc}", file=sys.stderr)
        suggest_sudo(args)
        return 1
    except OSError as exc:
        if exc.errno == errno.EACCES:
            print(f"Permission denied while reading hidraw: {exc}", file=sys.stderr)
            suggest_sudo(args)
            return 1
        print(f"Error: {exc}", file=sys.stderr)
        print_bluetooth_state()
        return 1
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        print_bluetooth_state()
        return 1

    descriptor = read_report_descriptor(device.path)
    descriptor_used = descriptor is not None
    fields = parse_report_descriptor(descriptor) if descriptor is not None else fallback_fields(args.report_id)
    decoded = decode_report(raw_report, fields, args.report_id)
    if not decoded:
        fields = fallback_fields(args.report_id)
        decoded = decode_report(raw_report, fields, args.report_id)
        descriptor_used = False

    print_report(device, raw_report, decoded, descriptor_used)
    print_bluetooth_state()
    print_power_layers(device)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
