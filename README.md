# decode-header - Decode and Print Kadena Chainweb BlockHeaders

The tool reads Kadena Chainweb Headers in various formats from stdin
and prints a JSON representation of each header to stdout.

# Installation

```sh
gcc -o decode-header decode-header.c
```

# Usage Examples

Hex encoded header:

```sh
> {
    curl -sl \
      -H 'accept: application/json' \
      "https://us-w1.chainweb.com/chainweb/0.0/mainnet01/chain/19/header?minheight=2120386&limit=1" |
    jq -r '.items[0]' |
    base64 -D |
    xxd -p |
    tr -d '\n'
    echo
} | decode-header | jq
{
  "featureFlags": "0x0000000000000000",
  "creationTime": 1636017804852849,
  "parent": "E1Yn2PjLICvmE6btR_SxYXa1eIVbGLEn5mQCrpTfxzI",
  "adjacents": {
    "4": "KDEYd5SoiZCsRMaBWqdQO_nsQCPHvP6AACQEdT_bcog",
    "10": "Ct-41UsXL5n5U-fmZBEbFInz9yKfcYYxQ0ElTNiQhjQ",
    "18": "jrMh3_uuH2qnhZVXfKJdcmped4R06p8w8K_bss9-0IA"
  },
  "target": "UxcAp6aIDyVg8JKsvDt9iUHKFDFkyODK8gAAAAAAAAA",
  "payloadHash": "U2QeC3bS28tM69fj38C1nsQwTklLuN1SMThNLUvpIw0",
  "chainId": 19,
  "weight": "XQDc2gA6_yBxAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "height": 2120386,
  "chainwebVersion": "mainnet01",
  "epochStart": 1636014475997508,
  "nonce": "0xb5e73061a41efa61",
  "hash": "V1dct_klG12WPHUfnYBDVYsUMjmgdGq1Es4SOWfhxAY"
}
```

Decode base64 encoded header:

```sh
> curl -sl \
    -H 'accept: application/json' \
    "https://us-w1.chainweb.com/chainweb/0.0/mainnet01/chain/19/header?minheight=2120386&limit=1" |
  jq -r '.items[0]' |
  decode-header |
  jq
{
  "featureFlags": "0x0000000000000000",
  "creationTime": 1636017804852849,
  "parent": "E1Yn2PjLICvmE6btR_SxYXa1eIVbGLEn5mQCrpTfxzI",
  "adjacents": {
    "4": "KDEYd5SoiZCsRMaBWqdQO_nsQCPHvP6AACQEdT_bcog",
    "10": "Ct-41UsXL5n5U-fmZBEbFInz9yKfcYYxQ0ElTNiQhjQ",
    "18": "jrMh3_uuH2qnhZVXfKJdcmped4R06p8w8K_bss9-0IA"
  },
  "target": "UxcAp6aIDyVg8JKsvDt9iUHKFDFkyODK8gAAAAAAAAA",
  "payloadHash": "U2QeC3bS28tM69fj38C1nsQwTklLuN1SMThNLUvpIw0",
  "chainId": 19,
  "weight": "XQDc2gA6_yBxAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "height": 2120386,
  "chainwebVersion": "mainnet01",
  "epochStart": 1636014475997508,
  "nonce": "0xb5e73061a41efa61",
  "hash": "V1dct_klG12WPHUfnYBDVYsUMjmgdGq1Es4SOWfhxAY"
}
```
