CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. interfaces (Quản lý các Giao diện phần cứng thực tế trên Host)
CREATE TABLE IF NOT EXISTS public.interfaces (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    interface VARCHAR(50) NOT NULL,
    ifname VARCHAR(50),
    interface_type VARCHAR(20) DEFAULT 'WAN'
);

-- 2. sdwan_profiles (Profile cấu hình mã hóa & chính sách WAN Quality)
CREATE TABLE IF NOT EXISTS public.sdwan_profiles (
    id INT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(80),
    action VARCHAR(20) DEFAULT '2',                      -- '2' (L2 PQC) hoặc '3' (L3 Overlay)
    method VARCHAR(32) DEFAULT 'pqc-gcm',               -- 'aes-gcm-128', 'aes-gcm-256', 'pqc-gcm', 'None'
    encryption_key VARCHAR(64),
    weight_enable BOOLEAN DEFAULT TRUE,
    latency_enable BOOLEAN DEFAULT FALSE,
    loss_enable BOOLEAN DEFAULT FALSE,
    latency_duration INT DEFAULT 5,
    loss_duration INT DEFAULT 5,
    created_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(50) DEFAULT 'system',
    updated_at TIMESTAMP DEFAULT NOW(),
    updated_by VARCHAR(50) DEFAULT 'system'
);

-- 3. sdwan_tunnels (Cấu hình các Đường hầm Multi-WAN)
CREATE TABLE IF NOT EXISTS public.sdwan_tunnels (
    id INT PRIMARY KEY,
    tunnel_name VARCHAR(100) NOT NULL,
    profile_id INT NOT NULL REFERENCES public.sdwan_profiles(id) ON DELETE CASCADE,
    ip_addr VARCHAR(50),
    local UUID NOT NULL REFERENCES public.interfaces(id) ON DELETE CASCADE,
    remote VARCHAR(50) NOT NULL,
    segment_id INT NOT NULL DEFAULT 1234,              -- VNI ID (e.g. 1234, 1235)
    tunnel_port INT DEFAULT 65001,
    weight INT DEFAULT 1,
    latency_ip VARCHAR(45),
    latency INT DEFAULT 100,
    latency_enable BOOLEAN DEFAULT FALSE,
    loss_ip VARCHAR(45),
    loss_percentage INT DEFAULT 5,
    loss_enable BOOLEAN DEFAULT FALSE
);

-- 4. sdwan_pqc_ref (Tham chiếu giữa Profile SD-WAN và Khóa PQC)
CREATE TABLE IF NOT EXISTS public.sdwan_pqc_ref (
    profile_id INT NOT NULL REFERENCES public.sdwan_profiles(id) ON DELETE CASCADE,
    key_id VARCHAR(100) NOT NULL,
    PRIMARY KEY (profile_id, key_id)
);

-- 5. pqc_keys (Quản lý Định danh Cụm Khóa PQC)
CREATE TABLE IF NOT EXISTS public.pqc_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_id VARCHAR(100) UNIQUE NOT NULL,
    local VARCHAR(100) NOT NULL,
    remote VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'establish',
    created_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(50) DEFAULT 'system',
    updated_at TIMESTAMP DEFAULT NOW(),
    updated_by VARCHAR(50) DEFAULT 'system'
);

-- 6. sdwan_tunnel_ref (Tham chiếu giữa Profile SD-WAN và Tunnel Bắt tay PQC)
CREATE TABLE IF NOT EXISTS public.sdwan_tunnel_ref (
    profile_id INT NOT NULL REFERENCES public.sdwan_profiles(id) ON DELETE CASCADE,
    tunnel_id VARCHAR(100) NOT NULL,
    PRIMARY KEY (profile_id, tunnel_id)
);

-- 7. pqc_exchange_tunnels (Đường hầm Bắt tay & Định tuyến PQC)
CREATE TABLE IF NOT EXISTS public.pqc_exchange_tunnels (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tunnel_name VARCHAR(100) UNIQUE NOT NULL,
    tunnel_ip VARCHAR(50) NOT NULL,
    peer_tunnel_ip VARCHAR(50) NOT NULL,
    mode VARCHAR(20) DEFAULT 'client',
    client_peer_public_ip VARCHAR(50),
    client_peer_listen_port INT DEFAULT 65001,
    public_key TEXT,
    private_key TEXT,
    peer_public_key TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 8. Bảng Báo cáo Trạng thái Node (Dành cho Heartbeat)
CREATE TABLE IF NOT EXISTS public.node_status (
    node_id INT PRIMARY KEY,
    status VARCHAR(20) NOT NULL DEFAULT 'OFFLINE',
    error_message TEXT,
    last_seen TIMESTAMP DEFAULT NOW()
);

----------------------------------------------------------------
-- SEED DATA SETUP FOR TESTING (Server 1: profile_id = 1, Server 2: profile_id = 2)
----------------------------------------------------------------

-- Interfaces cho Server 1 (enp8s0, enp9s0)
INSERT INTO public.interfaces (id, interface, ifname, interface_type)
VALUES 
    ('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 'enp8s0', 'enp8s0', 'WAN'),
    ('b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22', 'enp9s0', 'enp9s0', 'WAN')
ON CONFLICT (id) DO NOTHING;

-- Profile 1 (Server 1)
INSERT INTO public.sdwan_profiles (id, name, description, action, method, encryption_key, weight_enable, latency_enable, loss_enable)
VALUES (
    1, 'PQC_L2_PROFILE_SERVER1', 'Profile L2 PQC for Server 1', '2', 'pqc-gcm', 
    '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', TRUE, FALSE, FALSE
) ON CONFLICT (id) DO UPDATE SET method = EXCLUDED.method, action = EXCLUDED.action;

-- Tunnels cho Profile 1
INSERT INTO public.sdwan_tunnels (id, tunnel_name, profile_id, ip_addr, local, remote, segment_id, tunnel_port, weight)
VALUES 
    (1, 'sdwan_tun1', 1, '172.16.23.1', 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', '100.64.2.2', 1234, 65001, 1),
    (2, 'sdwan_tun2', 1, '172.16.25.1', 'b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22', '100.64.22.2', 1235, 65002, 1)
ON CONFLICT (id) DO NOTHING;

-- PQC Keys cho Profile 1
INSERT INTO public.pqc_keys (key_id, local, remote, status)
VALUES ('pqc_key_p1', 'node1_fg.key', 'peer1.key', 'establish')
ON CONFLICT (key_id) DO NOTHING;

INSERT INTO public.sdwan_pqc_ref (profile_id, key_id)
VALUES (1, 'pqc_key_p1')
ON CONFLICT DO NOTHING;

-- PQC Exchange Tunnel cho Profile 1
INSERT INTO public.pqc_exchange_tunnels (tunnel_name, tunnel_ip, peer_tunnel_ip, mode, client_peer_public_ip, client_peer_listen_port)
VALUES ('pqc_hs_tun1', '172.16.23.1', '172.16.23.2', 'client', '100.64.2.2', 65001)
ON CONFLICT (tunnel_name) DO NOTHING;

INSERT INTO public.sdwan_tunnel_ref (profile_id, tunnel_id)
VALUES (1, 'pqc_hs_tun1')
ON CONFLICT DO NOTHING;
