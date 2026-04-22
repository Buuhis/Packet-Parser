-- 1. Xóa dữ liệu cũ theo đúng trình tự ràng buộc (Con trước Cha sau)
DELETE FROM xdp_profile_crypto_policies;
DELETE FROM xdp_profiles WHERE id = 1;
DELETE FROM xdp_configs WHERE id = 1;

-- 2. Tạo dữ liệu gốc cho xdp_configs
INSERT INTO xdp_configs (id) VALUES (1);

-- 3. Tạo dữ liệu cho xdp_profiles theo đúng format schema
-- Cột: id, config_id, profile_name, enabled, channel_bonding, description
INSERT INTO xdp_profiles (id, config_id, profile_name, enabled, channel_bonding, description) 
VALUES (1, 1, 'pqc_test_profile', 1, 1, 'Profile test PQC-GCM');

-- 4. Chèn Policy Test PQC-GCM cho Layer 4 theo đúng format schema
-- Cột: profile_id, priority, action, protocol, src_cidr, src_port, dst_cidr, dst_port, crypto_mode, aes_bits, nonce_size, crypto_key
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
    'pqc-gcm',          -- crypto_mode
    256,                -- aes_bits (PQC requires 256)
    12,                 -- nonce_size
    '0123456789abcdef0123456789abcdef' -- crypto_key (32 bytes hex)
);

-- 5. Truy vấn kiểm tra đúng tên cột trong schema
SELECT p.profile_name, c.action, c.crypto_mode, c.crypto_key 
FROM xdp_profiles p
JOIN xdp_profile_crypto_policies c ON p.id = c.profile_id;
