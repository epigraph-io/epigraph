Android attestation status lists for the tests, in the format Google publishes
at https://android.googleapis.com/attestation/status (an `entries` object keyed
by certificate serial number in lowercase hex, each with a `status` of
`REVOKED` or `SUSPENDED`).

- `google-example.json`: the example list from Google's key attestation
  documentation, verbatim.
- `empty.json`: no entry (every certificate in good standing).
- `leading-zero.json`: one REVOKED serial whose big-endian bytes start with a
  zero nibble (`0a 1b 2c 3d 4e 5f 60 71`), so a hex form padded to whole bytes
  (`0a1b...`) differs from the list's key (`a1b2...`).

The tests embed them with `include_str!` and write them to a temporary file
whose modification time they set, so no test reaches the network.
