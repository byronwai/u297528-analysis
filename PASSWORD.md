# Malware Samples — Access Information

## Password-Protected Archive

**File:** `malware_samples.zip`

**Password:** `infected`

## Contents

| File | Description | Size | SHA256 |
|------|-------------|------|--------|
| `u297528.dat` | Original DLL (idll.dll) — encrypted loader | 12.6 MB | `e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba` |
| `decrypted_payload.exe` | AES-256-CBC decrypted dropper | 6.81 MB | `d59e83b0be737896dec8b91c7a52f87e16f83e911af52826b98481b5c50f32b2` |
| `embedded_00_miner.bin` | XMRig miner component | 230 KB | `5543d3b826de134bc47212be344f0c7def51704516d40f611b406c6e98baaa3a` |
| `embedded_01_dropper.bin` | Main dropper with networking | 6.3 MB | `2be97a48015544620fe1e3bb69b130a24ddbb31f9719173868579df489e9356c` |

## Extraction

```bash
unzip -P infected malware_samples.zip
```

## Warning

These are live malware samples. Handle only in isolated analysis environments. Do NOT execute on production or personal systems.
