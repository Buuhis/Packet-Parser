CREATE TABLE IF NOT EXISTS public.nodes (
    id SERIAL PRIMARY KEY,
    node_id INTEGER UNIQUE NOT NULL,
    local_if VARCHAR(20) NOT NULL,
    remote_cidr VARCHAR(50) NOT NULL,
    loopback_ip VARCHAR(50) NOT NULL,
    encryption_enabled BOOLEAN DEFAULT FALSE,
    encrypt_type VARCHAR(32) DEFAULT 'aes-gcm', -- Allow users to choose cipher: 'aes-gcm', 'chacha20-poly1305', etc.
    encrypt_key INTEGER DEFAULT 128,          -- Hex string for the symmetric key
    encrypt_nonce INTEGER DEFAULT 12            -- Hex string for Salt/IV generation
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
    TRUE, 'gcm(aes)', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', '12' -- Example 256-bit key & salt
);

INSERT INTO public.ne_tunnels (node_id, ifname, gateway, port, weight)
VALUES 
    (1, 'ne_tunnel1', '172.16.23.2', 65001, 1),
    (1, 'ne_tunnel2', '172.16.25.2', 65002, 1);

INSERT INTO public.nodes (node_id, local_if, remote_cidr, loopback_ip, encryption_enabled, encrypt_type, encrypt_key, encrypt_nonce)
VALUES (
    2, 'enp6s0', '192.168.68.0/24', '10.0.0.2',
    TRUE, 'gcm(aes)', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', '12'
);

INSERT INTO public.ne_tunnels (node_id, ifname, gateway, port, weight)
VALUES 
    (2, 'ne_tunnel1', '172.16.23.1', 65001, 1),
    (2, 'ne_tunnel2', '172.16.25.1', 65002, 1);

