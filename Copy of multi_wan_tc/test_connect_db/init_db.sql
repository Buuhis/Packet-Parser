CREATE TABLE IF NOT EXISTS public.nodes (
    id SERIAL PRIMARY KEY,
    node_id VARCHAR(50) UNIQUE NOT NULL,
    role VARCHAR(20) NOT NULL,
    local_if VARCHAR(20) NOT NULL,
    remote_cidr VARCHAR(50) NOT NULL,
    lan_ip VARCHAR(50) NOT NULL,
    lan_gw VARCHAR(50) NOT NULL,
    lan_dst_mac VARCHAR(20) NOT NULL
);

CREATE TABLE IF NOT EXISTS public.ne_tunnels (
    id SERIAL PRIMARY KEY,
    node_id VARCHAR(50) NOT NULL REFERENCES public.nodes(node_id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    ifname VARCHAR(20) NOT NULL,
    gateway VARCHAR(50) NOT NULL,
    port INTEGER NOT NULL,
    weight INTEGER NOT NULL DEFAULT 1
);

-- Xóa dữ liệu cũ nếu có
TRUNCATE TABLE public.ne_tunnels RESTART IDENTITY CASCADE;
TRUNCATE TABLE public.nodes RESTART IDENTITY CASCADE;

-- Thêm dữ liệu cho server1
INSERT INTO public.nodes (node_id, role, local_if, remote_cidr, lan_ip, lan_gw, lan_dst_mac)
VALUES (
    'server1', 'server', 'enp7s0', '192.168.182.0/24', 
    '192.168.9.1/24', '192.168.9.2', '20:7c:14:f8:0d:08'
);

INSERT INTO public.ne_tunnels (node_id, name, ifname, gateway, port, weight)
VALUES 
    ('server1', 'ne_tunnel1', 'ne_tunnel1', '172.16.23.2', 65001, 1),
    ('server1', 'ne_tunnel2', 'ne_tunnel2', '172.16.25.2', 65002, 1);

-- Thêm dữ liệu cho server2
INSERT INTO public.nodes (node_id, role, local_if, remote_cidr, lan_ip, lan_gw, lan_dst_mac)
VALUES (
    'server2', 'server', 'enp7s0', '192.168.9.0/24', 
    '192.168.182.1/24', '192.168.182.2', '20:7c:14:f8:0c:f6'
);

INSERT INTO public.ne_tunnels (node_id, name, ifname, gateway, port, weight)
VALUES 
    ('server2', 'ne_tunnel1', 'ne_tunnel1', '172.16.23.1', 65001, 1),
    ('server2', 'ne_tunnel2', 'ne_tunnel2', '172.16.25.1', 65002, 1);
