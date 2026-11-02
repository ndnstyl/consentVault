# The only rights the vault's OpenBao token holds: per-organisation transit keys, wrap and unwrap, and the key
# lifecycle calls OpenBaoKeyProvider makes. No other mount, no auth or policy administration.
path "transit/keys/cv-org-*"        { capabilities = ["create", "read", "update", "delete"] }
path "transit/keys/cv-org-*/config" { capabilities = ["update"] }
path "transit/encrypt/cv-org-*"     { capabilities = ["update"] }
path "transit/decrypt/cv-org-*"     { capabilities = ["update"] }
