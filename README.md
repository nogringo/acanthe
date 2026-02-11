# Acanthe

Zero SPOF passkey manager. Local-first browser extension with Nostr sync.

A Browser extension that lets you manage your passkeys locally, without relying on any cloud service. No account, no sync to Big Tech servers, no single point of failure.

## Why Acanthe?

With traditional passkey managers:
- Your provider can lock you out
- Servers can go down
- Companies can go bankrupt
- Governments can request access
- Terms of service can change

With Acanthe:
- Your keys stay on your device
- No external dependency
- No one can delete your account
- You own your data, period

## Features

- **Local-first** - Passkeys are stored encrypted on your device
- **Strong encryption** - AES-256-GCM with Argon2id key derivation
- **Bitwarden compatible** - Import/export in Bitwarden JSON format
- **No account required** - Just set a master password and go
- **Open source** - Audit the code yourself

## Installation

1. Clone this repo
2. Run `npm install && npm run build`
3. Open Chrome and go to `chrome://extensions`
4. Enable "Developer mode"
5. Click "Load unpacked" and select the `dist` folder

## Security

- Master password never leaves your device
- Passkeys encrypted with AES-256-GCM
- Key derivation using Argon2id (memory-hard, resistant to GPU attacks)
- Private keys stored in encrypted form only
