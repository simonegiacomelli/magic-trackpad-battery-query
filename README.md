# Apple Magic Trackpad Battery Decoder

This repo contains a small Linux script for reading and decoding the Apple Magic Trackpad battery/status HID report.

Run it with:

```bash
sudo ./decode_magic_trackpad_battery.py
```

It needs root on systems where `/dev/hidraw*` nodes are owned by `root:root`.

The useful HID input report is report `0x90`. A recent read returned:

```text
90 03 63 00
```

The report descriptor identifies the payload fields as:

```text
INPUT(144)              # 144 decimal = 0x90 report ID

Field(0)
  Power.Good
  BatterySystem.Charging
  BatterySystem.FullyCharged
  Report Size(1)
  Report Count(3)
  Report Offset(0)

Field(1)
  BatterySystem.AbsoluteStateOfCharge
  Report Size(8)
  Report Count(1)
  Report Offset(8)
  Logical Minimum(0)
  Logical Maximum(255)
```

Mapping the report bytes:

```text
90 = report ID 0x90
03 = status bits: Power.Good=1, Charging=1, FullyCharged=0
63 = AbsoluteStateOfCharge raw value, 0x63 = 99
00 = trailing byte from the requested read length
```

Even though the HID descriptor advertises a broad `0..255` logical range, Linux treats `BatterySystem.AbsoluteStateOfCharge` for this Apple trackpad as a direct percent value. That is confirmed by the kernel `power_supply` layer and UPower:

```text
Kernel power_supply capacity: 99
UPower percentage: 99%
```

So the practical interpretation is:

```text
Battery level = AbsoluteStateOfCharge value as percent
0x63 = 99%
```

Status bits:

```text
Power.Good       1 = external power is present / power is good
Charging         1 = charging
FullyCharged     0 = not fully charged
```

Bluetooth and USB can show different transport states. In the observed state, Bluetooth showed `Connected: no`, while the trackpad was connected over USB and charging. The script in this folder handles that by scanning all Magic Trackpad `hidraw` interfaces and using the one that successfully returns report `0x90`.
