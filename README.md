# JWKS Juggler : JWKS -> Private Key

```
USAGE:
  jwksjuggler [OPTIONS]

OPTIONS:
  -in <file>     Input JWKS file path (required for export)
  -out <file>    Output private key file path (required for export)
  -test          Create test.jwks example file
  -help          Show this help message

EXAMPLES:
  # Export private keys from JWKS file:
  jwks-export -in keys.jwks -out private-keys.pem

  # Create test JWKS file:
  jwks-export -test

FEATURES:
  • Supports various JWKS JSON formats
  • Exports multiple RSA private keys
  • Handles nested JSON structures
  • Includes key IDs in PEM headers
  • Only processes RSA keys (skips other types)
```
