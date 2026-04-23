DELETE FROM xdp_profile_crypto_policies;
DELETE FROM xdp_profiles WHERE id = 1;
DELETE FROM xdp_configs WHERE id = 1;

INSERT INTO xdp_configs (id) VALUES (1);

INSERT INTO xdp_profiles (id, config_id, profile_name, enabled, channel_bonding, description) 
VALUES (1, 1, 'pqc_test_profile', 1, 1, 'Profile test PQC-GCM');

INSERT INTO xdp_profile_crypto_policies (
    profile_id, 
    priority, 
    action, 
    protocol, 
    src_cidr, 
    src_port, 
    dst_cidr, 
    dst_port, 
    crypto_mode, 
    aes_bits, 
    nonce_size, 
    crypto_key
) VALUES (
    1,                  -- profile_id
    100,                -- priority (default 100)
    'encrypt_l4',       -- action
    'ANY',              -- protocol
    'ANY',              -- src_cidr
    'ANY',              -- src_port
    'ANY',              -- dst_cidr
    'ANY',              -- dst_port
    'pqc_gcm',          -- crypto_mode
    256,                -- aes_bits (PQC requires 256)
    12,                 -- nonce_size
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' -- crypto_key (32 bytes = 64 hex chars)
);

SELECT p.profile_name, c.action, c.crypto_mode, c.crypto_key 
FROM xdp_profiles p
JOIN xdp_profile_crypto_policies c ON p.id = c.profile_id;
