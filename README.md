# decode-header - Decode and Print Kadena Chainweb BlockHeaders

The tool reads Kadena Chainweb Headers in various formats from stdin
and prints a JSON representation of each header to stdout.

# Installation

```sh
gcc -o decode-header decode-header.c
```

# Container Image

```sh
docker run -i --rm ghcr.io/larskuhtz/decode-header --version
```


# Usage Examples

Show usage information

```sh
docker run -i --rm ghcr.io/larskuhtz/decode-header --help
```

Decode base64 encoded header using the container image:

```sh
curl -sl \
    -H 'accept: application/json' \
    "https://us-w1.chainweb.com/chainweb/0.0/mainnet01/chain/19/header?minheight=2120386&limit=1" |
jq '.items[0]' |
docker run -i --rm ghcr.io/larskuhtz/decode-header |
jq
```

Output:

```
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

Hex encoded header:

```sh
echo 000000000000000071be1a14f3cf0500135627d8f8cb202be613a6ed47f4b16176b578855b18b127e66402ae94dfc7320300040000002831187794a88990ac44c6815aa7503bf9ec4023c7bcfe80002404753fdb72880a0000000adfb8d54b172f99f953e7e664111b1489f3f7229f7186314341254cd8908634120000008eb321dffbae1f6aa78595577ca25d726a5e778474ea9f30f0afdbb2cf7ed080531700a7a6880f2560f092acbc3b7d8941ca143164c8e0caf20000000000000053641e0b76d2dbcb4cebd7e3dfc0b59ec4304e494bb8dd5231384d2d4be9230d130000005d00dcda003aff20710300000000000000000000000000000000000000000000c25a200000000000050000004471b04df2cf050061fa1ea46130e7b557575cb7f9251b5d963c751f9d8043558b143239a0746ab512ce123967e1c406 |
decode-header |
jq
```

Output:

```
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

Print list of newline separated headers:

```sh
curl -sl \
    -H 'accept: application/json' \
    "https://us-w1.chainweb.com/chainweb/0.0/mainnet01/chain/19/header?minheight=2120386&limit=10" |
jq '.items[]' |
docker run -i --rm ghcr.io/larskuhtz/decode-header |
jq
```

