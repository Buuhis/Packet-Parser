CREATE TABLE IF NOT EXISTS public.nodes (
    id SERIAL PRIMARY KEY,
    node_id INTEGER UNIQUE NOT NULL,
    local_if VARCHAR(20) NOT NULL,
    encryption_enabled BOOLEAN DEFAULT FALSE,
    encrypt_layer INTEGER DEFAULT 3,                  -- 2: L2 (MACsec), 3: L3 (Overlay)
    encrypt_type VARCHAR(32) DEFAULT 'aes-gcm-128',   -- 'aes-gcm-128', 'aes-gcm-256', or 'pqc-gcm'
    encrypt_key VARCHAR(64) DEFAULT NULL             -- Hex string: 32 chars (128-bit) or 64 chars (256-bit)
);

CREATE TABLE IF NOT EXISTS public.node_status (
    node_id INTEGER PRIMARY KEY REFERENCES public.nodes(node_id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'OFFLINE',
    error_message TEXT,
    last_seen TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.ne_tunnels (
    id SERIAL PRIMARY KEY,
    node_id INTEGER NOT NULL REFERENCES public.nodes(node_id) ON DELETE CASCADE,
    ifname VARCHAR(20) NOT NULL,
    gateway VARCHAR(50) NOT NULL,
    port INTEGER NOT NULL,
    weight INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS public.pqc_identities (
    node_id INTEGER PRIMARY KEY REFERENCES public.nodes(node_id) ON DELETE CASCADE,
    local_identity_fingerprint VARCHAR(32) NOT NULL, -- Lưu dạng '<fingerprint>.key'
    peer_pub VARCHAR(255) NOT NULL
);

-- TRUNCATE TABLE public.pqc_identities RESTART IDENTITY CASCADE;
-- TRUNCATE TABLE public.ne_tunnels RESTART IDENTITY CASCADE;
-- TRUNCATE TABLE public.node_status RESTART IDENTITY CASCADE;
-- TRUNCATE TABLE public.nodes RESTART IDENTITY CASCADE;


----------------------------------------------------------------
------------------ SERVER1 -----------------------------------
----------------------------------------------------------------

INSERT INTO public.nodes (node_id, local_if, encryption_enabled, encrypt_layer, encrypt_type, encrypt_key)
VALUES (
    1, 'enp7s0', TRUE, 3, 'pqc-gcm', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
);

-- Nạp thông tin tunnel của node 1 (gateway hướng về .2)
INSERT INTO public.ne_tunnels (node_id, ifname, gateway, port, weight)
VALUES 
    (1, 'ne_tunnel1', '172.16.23.2', 65001, 1),
    (1, 'ne_tunnel2', '172.16.25.2', 65002, 1);

-- Nạp thông tin định danh PQC của node 1
INSERT INTO public.pqc_identities (node_id, local_identity_fingerprint, peer_pub)
VALUES 
    (1, 'node1_fg.key', 'peer1.key');


----------------------------------------------------------------
------------------ SERVER2 -----------------------------------
----------------------------------------------------------------

INSERT INTO public.nodes (node_id, local_if, encryption_enabled, encrypt_layer, encrypt_type, encrypt_key)
VALUES (
    1, 'enp7s0', TRUE, 3, 'pqc-gcm', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
);

-- Nạp thông tin tunnel (gốc là của node 2 đổi gateway hướng về .1)
INSERT INTO public.ne_tunnels (node_id, ifname, gateway, port, weight)
VALUES 
    (1, 'ne_tunnel1', '172.16.23.1', 65001, 1),
    (1, 'ne_tunnel2', '172.16.25.1', 65002, 1);

-- Nạp thông tin định danh PQC (gốc là của node 2)
INSERT INTO public.pqc_identities (node_id, local_identity_fingerprint, peer_pub)
VALUES 
    (1, 'node2_fg.key', 'peer2.key');
