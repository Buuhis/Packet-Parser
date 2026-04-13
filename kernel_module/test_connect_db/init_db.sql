CREATE TABLE IF NOT EXISTS public.nodes (
    id SERIAL PRIMARY KEY,
    node_id INTEGER UNIQUE NOT NULL,
    local_if VARCHAR(20) NOT NULL,
    remote_cidr VARCHAR(50) NOT NULL,
    loopback_ip VARCHAR(50) NOT NULL,
    encryption_enabled BOOLEAN DEFAULT FALSE,
    encrypt_type VARCHAR(32) DEFAULT 'aes-gcm-128', -- 'aes-gcm-128' or 'aes-gcm-256'
    encrypt_key VARCHAR(64) DEFAULT NULL,            -- Hex string: 32 chars (128-bit) or 64 chars (256-bit)
    encrypt_nonce VARCHAR(8) DEFAULT NULL             -- Hex string: 8 chars = 4 bytes Salt for IV
);

CREATE TABLE IF NOT EXISTS public.ne_tunnels (
    id SERIAL PRIMARY KEY,
    node_id INTEGER NOT NULL REFERENCES public.nodes(node_id) ON DELETE CASCADE,
    ifname VARCHAR(20) NOT NULL,
    gateway VARCHAR(50) NOT NULL,
    port INTEGER NOT NULL,
    weight INTEGER NOT NULL DEFAULT 1
);

TRUNCATE TABLE public.ne_tunnels RESTART IDENTITY CASCADE;
TRUNCATE TABLE public.nodes RESTART IDENTITY CASCADE;

INSERT INTO public.nodes (node_id, local_if, remote_cidr, loopback_ip, encryption_enabled, encrypt_type, encrypt_key, encrypt_nonce)
VALUES (
    1, 'enp6s0', '192.168.90.0/24', '10.0.0.1', 
    TRUE, 'aes-gcm-256', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'deadbeef'
);

INSERT INTO public.ne_tunnels (node_id, ifname, gateway, port, weight)
VALUES 
    (1, 'ne_tunnel1', '172.16.23.2', 65001, 1),
    (1, 'ne_tunnel2', '172.16.25.2', 65002, 1);

INSERT INTO public.nodes (node_id, local_if, remote_cidr, loopback_ip, encryption_enabled, encrypt_type, encrypt_key, encrypt_nonce)
VALUES (
    2, 'enp6s0', '192.168.68.0/24', '10.0.0.2',
    TRUE, 'aes-gcm-256', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'deadbeef'
);

INSERT INTO public.ne_tunnels (node_id, ifname, gateway, port, weight)
VALUES 
    (2, 'ne_tunnel1', '172.16.23.1', 65001, 1),
    (2, 'ne_tunnel2', '172.16.25.1', 65002, 1);

