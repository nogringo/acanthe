# NIP-XXXX

## Vault Storage

`draft` `optional`

This NIP defines a standard for storing and synchronizing credentials (passwords, passkeys, TOTP, secure notes) on the Nostr network using the Bitwarden format.

## Motivation

Password managers and authenticator apps each implement proprietary sync solutions. This NIP provides an open, interoperable standard using:

- **Nostr** for decentralized sync
- **Bitwarden format** for data structure (battle-tested, widely supported)
- **NIP-44** for end-to-end encryption

Benefits:
- Cross-platform sync without vendor lock-in
- Multiple specialized apps can share the same vault
- Import/export compatibility with Bitwarden ecosystem
- User-controlled key management

## Specification

### Event Kind

Vault events use **kind 3078** (regular events).

Regular events preserve history and enable conflict-free merging across devices.

### Event Structure

```json
{
  "kind": 3078,
  "tags": [
    ["d", "store:vault"]
  ],
  "content": "<NIP-44 encrypted Bitwarden item>"
}
```

### Tags

| Tag | Value | Description |
|-----|-------|-------------|
| `d` | `store:vault` | Required. Identifies vault storage events. |

The `d` tag value `store:vault` is the interoperability identifier. All compliant clients MUST use this value.

### Encrypted Payload

The `content` field contains a NIP-44 encrypted Bitwarden item. Encryption is performed to self (sender = recipient).

## Bitwarden Item Format

Each event contains one Bitwarden vault item. The format follows the [Bitwarden export specification](https://bitwarden.com/help/export-your-data/).

### Item Types

| Type | Value | Description |
|------|-------|-------------|
| Login | `1` | Passwords and passkeys |
| Secure Note | `2` | Encrypted notes |
| Card | `3` | Payment cards |
| Identity | `4` | Personal information |

### Base Item Structure

```json
{
  "id": "<uuid>",
  "type": 1,
  "name": "example.com",
  "notes": null,
  "favorite": false,
  "fields": [],
  "reprompt": 0,
  "creationDate": "2026-02-10T17:10:29.283Z",
  "revisionDate": "2026-02-10T17:10:29.453Z",
  "login": { ... },
  "secureNote": { ... },
  "card": { ... },
  "identity": { ... }
}
```

### Login Object (type=1)

```json
{
  "login": {
    "uris": [
      { "uri": "https://example.com/" }
    ],
    "username": "user@example.com",
    "password": "secret123",
    "totp": "otpauth://totp/...",
    "fido2Credentials": [
      {
        "credentialId": "b58a1a0c-abc9-49d7-a097-2f7971f9acfe",
        "keyType": "public-key",
        "keyAlgorithm": "ECDSA",
        "keyCurve": "P-256",
        "keyValue": "<PKCS#8 base64 private key>",
        "rpId": "example.com",
        "rpName": "Example Site",
        "userHandle": "<base64 user id>",
        "userName": "user@example.com",
        "userDisplayName": "John Doe",
        "counter": "0",
        "discoverable": "true",
        "creationDate": "2026-02-10T17:10:29.376Z"
      }
    ]
  }
}
```

### Passkey Fields (fido2Credentials)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credentialId` | string | Yes | Unique credential identifier |
| `keyType` | string | Yes | Always `"public-key"` |
| `keyAlgorithm` | string | Yes | `"ECDSA"` or `"EdDSA"` |
| `keyCurve` | string | Yes | `"P-256"`, `"P-384"`, `"P-521"`, or `"Ed25519"` |
| `keyValue` | string | Yes | PKCS#8 encoded private key (base64) |
| `rpId` | string | Yes | Relying party identifier (domain) |
| `rpName` | string | No | Relying party display name |
| `userHandle` | string | No | User handle (base64) |
| `userName` | string | No | User account name |
| `userDisplayName` | string | No | User display name |
| `counter` | string | No | Signature counter |
| `discoverable` | string | No | `"true"` or `"false"` |
| `creationDate` | string | No | ISO 8601 timestamp |

## App Behavior

### Specialized Apps

Different apps can focus on different parts of the vault:

| App Type | Reads | Writes |
|----------|-------|--------|
| Password Manager | All login items | login.username, login.password |
| Passkey Manager | Items with fido2Credentials | login.fido2Credentials |
| TOTP Authenticator | Items with totp | login.totp |
| Secure Notes | type=2 items | secureNote |

### Coexistence Rules

Apps MUST:
- Preserve fields they don't understand
- Not delete data from other app types
- Merge changes, not overwrite entire items

Example: A passkey-only app updating `fido2Credentials` must preserve existing `username`, `password`, and `totp` fields.

## Security Considerations

### Encryption

- All vault data MUST be encrypted using NIP-44 before publishing
- Sensitive data MUST never appear in plaintext on relays
- Encryption is to self: `nip44.encrypt(content, conversationKey(sk, pk))`

## Implementations

| Client | Type | Features | Repository |
|--------|------|----------|------------|
| Acanthe | Browser Extension | Passkeys | [nogringo/acanthe](https://github.com/nogringo/acanthe) |
