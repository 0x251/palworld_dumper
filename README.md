# Palworld offset Dumper in python using pygg
- Gworld (uint32)
- GObject (uint32)
- FName (uint32) 
- AppendString (uint32)
- ProcessEvent (uint32)
- Tick (uint32)

Offsets will be logged to **offsets.log** with a timestamp and there type

## Update patterns (11th Feb, 3AM 2024)
```python
 self._patterns = {
            "GObject": b"\x48\x8B\x05....\x48\x8B\x0C\xC8\x4C\x8D\x04\xD1\xEB\x03",
            "GWorld": b"\x48\x8B\x1D....\x48\x85\xDB\x74\x33\x41\xB0",
            "FName": b"\x48\x8D\x05....\xEB\x13\x48\x8D\x0D....\xE8....\xC6\x05.....\x0F\x10",
            "AppendString": b"\xC3\x48\x89\x5C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x20\x80",
            "ProcessEvent": b"\x40\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x81\xEC\x10\x01\x00\x00\x48\x8D",
            "Tick": b"\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x60\x48\x8B\xF9\xE8\x00\x00\x00\x00\x48\x8B"
        }
```

**This Dumper requires Pygg for Aob scanning and RPM https://github.com/0x251/pygg**
