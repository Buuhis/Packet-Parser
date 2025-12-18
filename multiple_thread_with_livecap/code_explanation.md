# Chi tiết giải thích Packet Capture System

## 📋 Tổng quan luồng hoạt động

```
[NIC LAN] → [Capture Thread] → [Queue] → [Worker Threads] → [WAN Interfaces]
```

---

## 🔧 PHẦN 1: CẤU TRÚC DỮ LIỆU

### 1.1 Cấu trúc Configuration
```c
typedef struct {
    char interface[32];      // Tên interface (vd: ens33)
    int port;                // Port local (vd: 5001)
    char peer_ip[64];        // IP đích (vd: 192.168.203.2)
    int peer_port;           // Port đích (vd: 5001)
    int sock_fd;             // Socket file descriptor
} wan_config_t;
```
**Mục đích:** Lưu thông tin 1 WAN interface để forward packet

```c
typedef struct {
    char local_interface[32];                    // Interface LAN capture
    wan_config_t wan_interfaces[MAX_WAN_INTERFACES];  // Mảng các WAN
    int num_wan;                                 // Số lượng WAN
} config_t;
```
**Mục đích:** Lưu toàn bộ cấu hình từ file .conf

### 1.2 Cấu trúc Packet đã capture
```c
typedef struct {
    uuid_t uuid;                    // ID duy nhất của packet
    uint8_t *data;                  // Dữ liệu payload
    size_t len;                     // Độ dài payload
    struct sockaddr_in src_addr;    // IP:Port nguồn
    uint64_t timestamp;             // Thời gian capture
} captured_packet_t;
```
**Mục đích:** Đóng gói thông tin packet sau khi capture từ NIC

### 1.3 Cấu trúc Queue (Hàng đợi)
```c
typedef struct queue_node {
    captured_packet_t *packet;   // Con trỏ đến packet
    struct queue_node *next;     // Con trỏ node kế tiếp
} queue_node_t;
```
**Mục đích:** Node trong linked list của queue

```c
typedef struct {
    queue_node_t *head;          // Đầu queue
    queue_node_t *tail;          // Cuối queue
    int size;                    // Số packet trong queue
    pthread_mutex_t mutex;       // Khóa để đồng bộ
    pthread_cond_t cond;         // Biến điều kiện
    int done;                    // Flag kết thúc
} packet_queue_t;
```
**Mục đích:** Queue thread-safe để chia sẻ packet giữa capture thread và worker threads

---

## 🚀 PHẦN 2: HÀM CHÍNH - MAIN()

### Bước 1: Parse file config
```c
if (parse_config(argv[1], &global_config) < 0) {
    fprintf(stderr, "Failed to parse config file\n");
    return EXIT_FAILURE;
}
```
**Hoạt động:**
1. Mở file config
2. Đọc từng dòng
3. Nếu dòng bắt đầu bằng `local` → lưu interface LAN
4. Nếu dòng bắt đầu bằng `wan` → parse và lưu vào mảng wan_interfaces[]

**Ví dụ parsing:**
```
Input: "wan ens33:5001 192.168.203.2:5001"
→ interface = "ens33"
→ port = 5001
→ peer_ip = "192.168.203.2"
→ peer_port = 5001
```

### Bước 2: Khởi tạo Queue
```c
queue_init(&global_queue);
```
**Hoạt động:**
- Set head = NULL, tail = NULL, size = 0
- Khởi tạo mutex và condition variable
- Queue này sẽ chứa các packet đã capture

### Bước 3: Tạo Capture Thread
```c
pthread_create(&capture_tid, NULL, capture_thread, &global_queue);
```
**Hoạt động:**
- Tạo 1 thread riêng chạy hàm `capture_thread()`
- Thread này sẽ liên tục capture packet từ NIC
- Truyền global_queue làm tham số

### Bước 4: Tạo Worker Threads
```c
for (int i = 0; i < NUM_THREADS; i++) {
    args[i].wan_configs = global_config.wan_interfaces;
    args[i].num_wan = global_config.num_wan;
    args[i].queue = &global_queue;
    args[i].thread_id = i;
    
    pthread_create(&threads[i], NULL, thread_worker, &args[i]);
}
```
**Hoạt động:**
- Tạo 10 worker threads
- Mỗi thread sẽ:
  - Lấy packet từ queue
  - Xử lý và forward qua WAN

### Bước 5: Chờ và Cleanup
```c
// Chờ signal Ctrl+C
while (running) {
    sleep(1);
}

// Dừng capture thread
global_queue.done = 1;
pthread_cond_broadcast(&global_queue.cond);

// Chờ tất cả threads kết thúc
pthread_join(capture_tid, NULL);
for (int i = 0; i < NUM_THREADS; i++) {
    pthread_join(threads[i], NULL);
}
```

---

## 📡 PHẦN 3: CAPTURE THREAD - capture_thread()

### Bước 1: Tạo Raw Socket
```c
int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
```
**Giải thích:**
- `AF_PACKET`: Socket ở layer 2 (Data Link)
- `SOCK_RAW`: Nhận raw packets (không qua kernel processing)
- `ETH_P_IP`: Chỉ nhận IP packets

### Bước 2: Bind socket vào interface
```c
struct ifreq ifr;
strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
ioctl(sock, SIOCGIFINDEX, &ifr);  // Lấy interface index

struct sockaddr_ll sll;
sll.sll_ifindex = ifr.ifr_ifindex;
bind(sock, (struct sockaddr *)&sll, sizeof(sll));
```
**Hoạt động:**
- Lấy index của interface (vd: ens38 → index 3)
- Bind socket vào interface đó
- Từ giờ chỉ nhận packet từ interface này

### Bước 3: Loop capture packets
```c
while (running) {
    // Dùng select() để chờ packet (timeout 1 giây)
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    
    int ret = select(sock + 1, &fds, NULL, NULL, &tv);
    if (ret <= 0) continue;
    
    // Nhận packet
    ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
```
**Hoạt động:**
- `select()`: Chờ có data trên socket (non-blocking với timeout)
- `recvfrom()`: Đọc raw packet vào buffer

### Bước 4: Parse packet structure
```c
// Buffer chứa: [Ethernet Header 14 bytes][IP Header][UDP Header][Payload]

// Skip Ethernet header (14 bytes)
struct iphdr *ip_header = (struct iphdr *)(buffer + 14);

// Check protocol
if (ip_header->protocol != IPPROTO_UDP) continue;

// Get IP header length
int ip_header_len = ip_header->ihl * 4;  // ihl = số lượng 32-bit words

// Parse UDP header
struct udphdr *udp_header = (struct udphdr *)(buffer + 14 + ip_header_len);

// Check destination port
if (ntohs(udp_header->dest) != DEST_PORT) continue;  // DEST_PORT = 2345
```

**Cấu trúc packet trong buffer:**
```
[0-13]:   Ethernet Header (14 bytes)
[14-33]:  IP Header (20 bytes, có thể khác)
[34-41]:  UDP Header (8 bytes)
[42-...]: UDP Payload (data thực sự)
```

### Bước 5: Extract payload
```c
int udp_header_len = 8;
uint8_t *payload = buffer + 14 + ip_header_len + udp_header_len;
size_t payload_len = len - 14 - ip_header_len - udp_header_len;
```
**Hoạt động:**
- Bỏ qua Ethernet + IP + UDP headers
- Lấy phần data thuần túy

### Bước 6: Tạo captured_packet_t
```c
captured_packet_t *packet = malloc(sizeof(captured_packet_t));
packet->data = malloc(payload_len);
memcpy(packet->data, payload, payload_len);
packet->len = payload_len;
packet->timestamp = get_miliseconds();

// Lưu thông tin nguồn
packet->src_addr.sin_family = AF_INET;
packet->src_addr.sin_addr.s_addr = ip_header->saddr;
packet->src_addr.sin_port = udp_header->source;

// Generate UUID cho packet này
generate_uuid7(packet->uuid);
```

### Bước 7: Push vào queue
```c
queue_push(queue, packet);
```
**Hoạt động:**
- Lock mutex
- Thêm packet vào cuối queue
- Signal condition variable (đánh thức worker threads)
- Unlock mutex

---

## ⚙️ PHẦN 4: WORKER THREAD - thread_worker()

### Bước 1: Pop packet từ queue
```c
captured_packet_t *packet = queue_pop(targ->queue);
if (!packet) break;  // Queue done
```
**Hoạt động queue_pop():**
```c
pthread_mutex_lock(&queue->mutex);

// Chờ nếu queue trống
while (queue->size == 0 && !queue->done) {
    pthread_cond_wait(&queue->cond, &queue->mutex);
}

// Lấy packet từ đầu queue
queue_node_t *node = queue->head;
queue->head = node->next;
queue->size--;

pthread_mutex_unlock(&queue->mutex);

return node->packet;
```

### Bước 2: Chọn WAN interface (Load Balancing)
```c
uint32_t flow_hash = calc_flow_hash(packet->uuid);
int wan_index = flow_hash % targ->num_wan;
wan_config_t *wan = &targ->wan_configs[wan_index];
```

**Giải thích calc_flow_hash():**
```c
uint32_t calc_flow_hash(const uuid_t uuid) {
    uint32_t hash = 0;
    for (int i = 0; i < 16; i++) {
        hash = hash * 31 + uuid[i];
    }
    return hash;
}
```
- Tạo hash từ UUID (16 bytes)
- Dùng hash % số_WAN để chọn WAN
- **Lợi ích:** Cùng flow (cùng UUID) luôn đi qua cùng WAN

### Bước 3: Tạo socket để gửi
```c
int sock = socket(AF_INET, SOCK_DGRAM, 0);

struct sockaddr_in dest = {0};
dest.sin_family = AF_INET;
dest.sin_port = htons(wan->peer_port);
inet_pton(AF_INET, wan->peer_ip, &dest.sin_addr);
```
**Hoạt động:**
- Tạo UDP socket mới
- Set địa chỉ đích = peer_ip:peer_port từ config

### Bước 4: Chia packet thành chunks và gửi
```c
int total = (packet->len + CHUNK - 1) / CHUNK;  // CHUNK = 512 bytes

for (int i = 0; i < total; i++) {
    char pkt[CHUNK + 28];  // 28 = header size
    int offset = i * CHUNK;
    int len = (packet->len - offset > CHUNK) ? CHUNK : (packet->len - offset);
    
    // Tạo header (28 bytes)
    memcpy(pkt, packet->uuid, 16);           // [0-15]: UUID
    *(int *)(pkt + 16) = htonl(i);           // [16-19]: Sequence number
    *(int *)(pkt + 20) = htonl(total);       // [20-23]: Total chunks
    *(int *)(pkt + 24) = htonl(len);         // [24-27]: Chunk length
    
    // Copy data
    memcpy(pkt + 28, packet->data + offset, len);
    
    // Gửi qua WAN
    sendto(sock, pkt, 28 + len, 0, (struct sockaddr *)&dest, sizeof(dest));
    
    usleep(800);  // Delay 800 microseconds
}
```

**Cấu trúc packet gửi đi:**
```
[0-15]:   UUID (16 bytes)
[16-19]:  Sequence Number (4 bytes)
[20-23]:  Total Chunks (4 bytes)
[24-27]:  Chunk Length (4 bytes)
[28-...]: Data (max 512 bytes)
```

**Ví dụ:**
- Packet size = 1500 bytes
- CHUNK = 512 bytes
- Total chunks = (1500 + 512 - 1) / 512 = 3 chunks
- Chunk 0: bytes [0-511]
- Chunk 1: bytes [512-1023]
- Chunk 2: bytes [1024-1499]

### Bước 5: Cleanup
```c
close(sock);
free(packet->data);
free(packet);
```

---

## 🔐 PHẦN 5: QUEUE THREAD-SAFE

### queue_push() - Producer (Capture thread)
```c
void queue_push(packet_queue_t *queue, captured_packet_t *packet) {
    queue_node_t *node = malloc(sizeof(queue_node_t));
    node->packet = packet;
    node->next = NULL;

    pthread_mutex_lock(&queue->mutex);     // 🔒 Lock
    
    if (queue->tail) {
        queue->tail->next = node;
    } else {
        queue->head = node;
    }
    queue->tail = node;
    queue->size++;
    
    pthread_cond_signal(&queue->cond);     // 📢 Signal workers
    pthread_mutex_unlock(&queue->mutex);   // 🔓 Unlock
}
```

### queue_pop() - Consumer (Worker threads)
```c
captured_packet_t* queue_pop(packet_queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);     // 🔒 Lock
    
    // Chờ nếu queue trống
    while (queue->size == 0 && !queue->done) {
        pthread_cond_wait(&queue->cond, &queue->mutex);  // 😴 Sleep & auto unlock
        // Khi được signal → tự động lock lại
    }
    
    if (queue->size == 0 && queue->done) {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;  // Kết thúc
    }

    queue_node_t *node = queue->head;
    queue->head = node->next;
    queue->size--;
    
    pthread_mutex_unlock(&queue->mutex);   // 🔓 Unlock
    
    captured_packet_t *packet = node->packet;
    free(node);
    return packet;
}
```

**Cơ chế hoạt động:**
1. Worker thread gọi `queue_pop()`
2. Nếu queue trống → `pthread_cond_wait()` → thread ngủ
3. Capture thread push packet → `pthread_cond_signal()` → đánh thức 1 worker
4. Worker thức dậy → lấy packet → xử lý

---

## 🎯 PHẦN 6: LUỒNG HOẠT ĐỘNG TỔNG THỂ

```
┌─────────────────────────────────────────────────────────────┐
│                         MAIN THREAD                          │
│  1. Parse config file                                        │
│  2. Initialize queue                                         │
│  3. Create capture thread                                    │
│  4. Create 10 worker threads                                 │
│  5. Wait for Ctrl+C                                          │
└─────────────────────────────────────────────────────────────┘
                    │                    │
        ┌───────────┘                    └───────────┐
        ▼                                            ▼
┌──────────────────┐                    ┌─────────────────────┐
│ CAPTURE THREAD   │                    │  WORKER THREADS (10)│
│                  │                    │                     │
│ while(running) { │                    │ while(1) {          │
│   1. recvfrom()  │                    │   1. queue_pop()    │
│      ↓           │                    │      ↓              │
│   2. Parse       │                    │   2. Hash → WAN     │
│      headers     │                    │      ↓              │
│      ↓           │                    │   3. Create socket  │
│   3. Extract     │                    │      ↓              │
│      payload     │                    │   4. Split chunks   │
│      ↓           │                    │      ↓              │
│   4. Create      │                    │   5. sendto() WAN   │
│      packet      │                    │      ↓              │
│      ↓           │                    │   6. Cleanup        │
│   5. queue_push()│──────QUEUE────────▶│ }                   │
│ }                │                    │                     │
└──────────────────┘                    └─────────────────────┘
        │                                            │
        │                                            │
        ▼                                            ▼
   [NIC: ens38]                          [WAN: ens33, ens37, ...]
```

---

## 📊 VÍ DỤ CỤ THỂ

### Scenario: Packet đi qua hệ thống

**Bước 1:** Client gửi UDP packet đến 192.168.9.100:2345
```
Ethernet: [src_mac][dst_mac][type]
IP:       [src_ip: 192.168.9.50][dst_ip: 192.168.9.100]
UDP:      [src_port: 12345][dst_port: 2345]
Payload:  "Hello World" (11 bytes)
```

**Bước 2:** Capture thread nhận packet
```
Buffer: [14 bytes Eth][20 bytes IP][8 bytes UDP]["Hello World"]
→ payload = "Hello World" (11 bytes)
→ Generate UUID: 01234567-89ab-cdef-0123-456789abcdef
→ Create captured_packet_t
→ queue_push()
```

**Bước 3:** Worker thread #3 lấy packet
```
→ queue_pop() = packet
→ calc_flow_hash(UUID) = 0xABCD1234
→ 0xABCD1234 % 2 = 0 → Chọn WAN 0 (ens33)
→ peer = 192.168.203.2:5001
```

**Bước 4:** Chia thành chunks (11 bytes < 512 → 1 chunk)
```
Chunk 0:
  [0-15]:  UUID
  [16-19]: seq = 0
  [20-23]: total = 1
  [24-27]: len = 11
  [28-38]: "Hello World"
  
→ sendto(192.168.203.2:5001)
```

**Bước 5:** Peer nhận được packet đầy đủ!

---

## 🔍 PHÂN TÍCH CHI TIẾT MỘT SỐ HÀM

### generate_uuid7()
```c
void generate_uuid7(uuid_t uuid) {
    // Lấy timestamp milliseconds
    uint64_t ts = get_miliseconds();
    
    // 6 bytes đầu = timestamp
    for (int i = 0; i < 6; i++) {
        uuid[i] = (ts >> ((5 - i) * 8)) & 0xFF;
    }
    
    // 10 bytes sau = random
    get_random_bytes(uuid + 6, 10);
    
    // Set version = 7
    uuid[6] = 0x70 | (uuid[6] & 0x0F);
    
    // Set variant = 10xx
    uuid[8] = 0x80 | (uuid[8] & 0x3F);
}
```
**UUID7 format:**
```
[timestamp 48 bits][version 4 bits][random 12 bits][variant 2 bits][random 62 bits]
```

### parse_config() - Chi tiết
```c
// Đọc dòng: "wan ens33:5001 192.168.203.2:5001"
char local_part[64], peer_part[64];
sscanf(line + 4, "%s %s", local_part, peer_part);
// local_part = "ens33:5001"
// peer_part = "192.168.203.2:5001"

// Split by ':'
char *colon = strchr(local_part, ':');
*colon = '\0';
// local_part = "ens33\0:5001"
strncpy(wan->interface, local_part, ...);  // "ens33"
wan->port = atoi(colon + 1);               // 5001
```

---

## ⚡ TỐI ƯU & LƯU Ý

### 1. Raw Socket yêu cầu root
```bash
sudo ./packet_capture config.conf
```

### 2. Performance
- **10 worker threads:** Xử lý song song
- **Queue:** Tách biệt capture và processing
- **select():** Non-blocking I/O

### 3. Thread-safe
- **Mutex:** Bảo vệ queue
- **Condition Variable:** Đồng bộ producer-consumer

### 4. Load Balancing
- **Flow hash:** Cùng flow đi cùng path (giữ thứ tự)
- **Modulo:** Phân phối đều

---

## 🎓 KẾT LUẬN

Code này implement một **Multi-Path UDP Proxy** với:
- ✅ Raw packet capture từ NIC
- ✅ Thread-safe queue
- ✅ Multi-threaded processing
- ✅ Load balancing across multiple WANs
- ✅ Chunking cho large packets

**Use case:** Tunnel traffic qua nhiều đường mạng để tăng throughput và reliability!
