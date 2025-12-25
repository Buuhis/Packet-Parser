# Chi tiết luồng xử lý Packet trong Load Balancer

## 🔄 Tổng quan kiến trúc

```
┌─────────────────┐
│  Local Network  │
│   (eth0)        │
└────────┬────────┘
         │ packet arrives
         ▼
┌─────────────────────────────────────────────────────────┐
│              CAPTURE THREAD (capture_local)             │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 1. recv() - Đọc raw packet từ socket            │   │
│  │ 2. Filter by destination IP & protocol          │   │
│  │ 3. Round-robin chọn WAN index                   │   │
│  │ 4. thread_pool_submit() - Đưa vào queue         │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                   PACKET QUEUE                          │
│  ┌─────────────────────────────────────────────────┐   │
│  │ Thread-safe queue with mutex & condition vars   │   │
│  │ • Max size: 1000 packets                        │   │
│  │ • Blocking push/pop operations                  │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
         ▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   WORKER 1   │  │   WORKER 2   │  │   WORKER N   │
│              │  │              │  │              │
│ thread_worker│  │ thread_worker│  │ thread_worker│
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │
       └─────────────────┼─────────────────┘
                         │
                         ▼
            ┌────────────────────────┐
            │  send_to_wan_callback  │
            └────────────┬───────────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
    ┌────────┐      ┌────────┐      ┌────────┐
    │ WAN 0  │      │ WAN 1  │      │ WAN N  │
    │(eth1)  │      │(eth2)  │      │(ethN)  │
    └────────┘      └────────┘      └────────┘
```

---

## 📦 Bước 1: Capture Packet từ Local Interface

### Thread: `capture_local()` trong lb.c

```c
void *capture_local(void *arg) {
    uint8_t buf[MAX_PKT];  // Buffer 65536 bytes
    
    while (running) {
        // STEP 1.1: Đọc raw IP packet từ local interface
        int n = recv(cfg.local_fd, buf, sizeof(buf), 0);
        // Ví dụ: Nhận được 1500 bytes UDP packet
        
        if (n < sizeof(struct iphdr)) {
            continue;  // Packet quá nhỏ, bỏ qua
        }
```

**Chi tiết:**
- Socket type: `AF_PACKET` với `SOCK_DGRAM` (không có Ethernet header)
- Chỉ nhận IP packets (`ETH_P_IP`)
- Blocking read - thread ngủ cho đến khi có packet

---

## 🔍 Bước 2: Filter Packet

```c
        struct iphdr *ip = (struct iphdr *)buf;
        uint32_t dip = ntohl(ip->daddr);

        // STEP 2.1: Kiểm tra destination IP có thuộc remote network không
        if ((dip & cfg.remote_mask) != (cfg.remote_ip & cfg.remote_mask)) {
            continue;  // Không phải remote network, bỏ qua
        }

        // STEP 2.2: Chỉ xử lý UDP packets
        if (ip->protocol != IPPROTO_UDP) {
            continue;  // Không phải UDP, bỏ qua
        }
```

**Ví dụ cụ thể:**
- Config: `remote 10.0.0.0/24`
- Packet đến: `10.0.0.100` → ✅ Match
- Packet đến: `192.168.1.1` → ❌ Drop
- Protocol: UDP (17) → ✅ Match
- Protocol: TCP (6) → ❌ Drop

---

## 🎲 Bước 3: Round-Robin chọn WAN

```c
        // STEP 3.1: Lock mutex để tránh race condition
        pthread_mutex_lock(&rr_lock);
        int idx = cfg.rr_idx++ % cfg.nwan;
        pthread_mutex_unlock(&rr_lock);
        
        // Ví dụ: 
        // - Có 3 WAN (nwan=3)
        // - rr_idx = 0 → idx = 0 (WAN 0)
        // - rr_idx = 1 → idx = 1 (WAN 1)
        // - rr_idx = 2 → idx = 2 (WAN 2)
        // - rr_idx = 3 → idx = 0 (WAN 0) - lặp lại
```

**Tại sao cần mutex?**
- Nhiều threads có thể đọc/ghi `cfg.rr_idx` cùng lúc
- Mutex đảm bảo mỗi packet được assign đúng WAN

---

## 📥 Bước 4: Submit vào Thread Pool

```c
        // STEP 4.1: Gọi thread_pool_submit()
        if (thread_pool_submit(worker_pool, buf, n, idx) < 0) {
            fprintf(stderr, "Failed to submit packet\n");
        }
    }
    return NULL;
}
```

### Trong `thread_pool_submit()` (packet_queue.c):

```c
int thread_pool_submit(thread_pool_t *pool, uint8_t *pkt, int len, int wan_idx) {
    // STEP 4.2: Allocate memory cho packet item
    packet_item_t *packet = malloc(sizeof(packet_item_t));
    
    // STEP 4.3: Copy packet data vào packet item
    memcpy(packet->data, pkt, len);  // Copy 1500 bytes
    packet->len = len;                // 1500
    packet->wan_idx = wan_idx;        // 0, 1, hoặc 2
    packet->timestamp = get_milliseconds();  // Ví dụ: 1735142400000
    
    // STEP 4.4: Tạo UUID7 cho packet
    generate_uuid7(packet->uuid);
    // Ví dụ UUID: 01-93-a4-e8-40-00-70-1a-80-b3-c4-d5-e6-f7-a8-b9
    //             └─────timestamp────┘└ver┘└var┘└──random──┘
    
    // STEP 4.5: Push vào queue
    if (packet_queue_push(pool->queue, packet) < 0) {
        free(packet);
        return -1;
    }
    
    return 0;
}
```

---

## 🗂️ Bước 5: Packet vào Queue

### Trong `packet_queue_push()` (packet_queue.c):

```c
int packet_queue_push(packet_queue_t *queue, packet_item_t *packet) {
    pthread_mutex_lock(&queue->mutex);
    
    // STEP 5.1: Kiểm tra queue có đầy không
    while (queue->size >= queue->max_size && !queue->shutdown) {
        // Queue đầy (1000 packets), đợi worker lấy bớt
        pthread_cond_wait(&queue->cond_not_full, &queue->mutex);
    }
    
    if (queue->shutdown) {
        pthread_mutex_unlock(&queue->mutex);
        return -1;  // Hệ thống đang shutdown
    }
    
    // STEP 5.2: Tạo node mới trong linked list
    packet_node_t *node = malloc(sizeof(packet_node_t));
    node->packet = packet;
    node->next = NULL;
    
    // STEP 5.3: Thêm vào cuối queue
    if (queue->tail) {
        queue->tail->next = node;  // Nối vào node cuối
    } else {
        queue->head = node;  // Queue trống, đây là node đầu
    }
    queue->tail = node;
    queue->size++;
    
    // STEP 5.4: Signal cho worker threads có packet mới
    pthread_cond_signal(&queue->cond_not_empty);
    
    pthread_mutex_unlock(&queue->mutex);
    return 0;
}
```

**Trạng thái queue:**
```
Before push: [P1] → [P2] → [P3] → NULL (size=3)
After push:  [P1] → [P2] → [P3] → [P4] → NULL (size=4)
                                    ↑
                                  new packet
```

---

## 👷 Bước 6: Worker Thread xử lý

### Trong `thread_worker()` (packet_queue.c):

```c
static void* thread_worker(void *arg) {
    thread_pool_t *pool = (thread_pool_t *)arg;
    
    while (pool->running) {
        // STEP 6.1: Pop packet từ queue (blocking call)
        packet_item_t *packet = packet_queue_pop(pool->queue);
        
        if (!packet) {
            break;  // Queue shutdown, thoát
        }
```

### Trong `packet_queue_pop()`:

```c
packet_item_t* packet_queue_pop(packet_queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    
    // STEP 6.2: Đợi cho đến khi có packet
    while (queue->size == 0 && !queue->shutdown) {
        // Queue trống, worker ngủ đợi
        pthread_cond_wait(&queue->cond_not_empty, &queue->mutex);
    }
    
    if (queue->shutdown && queue->size == 0) {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }
    
    // STEP 6.3: Lấy packet từ đầu queue
    packet_node_t *node = queue->head;
    queue->head = node->next;
    if (!queue->head) {
        queue->tail = NULL;  // Queue rỗng
    }
    queue->size--;
    
    // STEP 6.4: Signal cho capture thread nếu queue đã đầy
    pthread_cond_signal(&queue->cond_not_full);
    
    pthread_mutex_unlock(&queue->mutex);
    
    // STEP 6.5: Trả về packet
    packet_item_t *packet = node->packet;
    free(node);  // Free node nhưng giữ packet
    
    return packet;
}
```

---

## 📤 Bước 7: Send Packet ra WAN

### Quay lại `thread_worker()`:

```c
        // STEP 7.1: Gọi callback để send packet
        if (pool->send_callback) {
            pool->send_callback(packet->data, packet->len, 
                              packet->wan_idx, packet->uuid);
        }
        
        // STEP 7.2: Debug log
        uint32_t flow_hash = calc_flow_hash(packet->uuid);
        printf("[Thread %lu] Processed: len=%d, wan=%d, flow=%08X\n",
               pthread_self(), packet->len, packet->wan_idx, flow_hash);
        
        // STEP 7.3: Free packet memory
        free(packet);
    }
    
    return NULL;
}
```

### Trong `send_to_wan_callback()` (lb.c):

```c
void send_to_wan_callback(uint8_t *pkt, int len, int wan_idx, const uuid_t uuid) {
    // STEP 7.4: Validate WAN index
    if (wan_idx < 0 || wan_idx >= cfg.nwan) {
        fprintf(stderr, "Invalid WAN index: %d\n", wan_idx);
        return;
    }

    wan_t *w = &cfg.wan[wan_idx];  // Lấy WAN interface
    
    // STEP 7.5: Tạo sockaddr_ll để gửi packet
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = w->idx;           // Interface index
    sll.sll_halen = 6;                   // MAC address length
    memcpy(sll.sll_addr, w->peer_mac, 6); // Destination MAC
    
    // STEP 7.6: Gửi packet ra WAN interface
    ssize_t sent = sendto(w->fd, pkt, len, 0, 
                         (struct sockaddr *)&sll, sizeof(sll));
    
    if (sent < 0) {
        perror("sendto WAN");
    }
}
```

---

## 📊 Timeline Example: 1 Packet hoàn chỉnh

```
T=0ms:    Packet arrives at local interface (eth0)
          ↓
T=0.1ms:  capture_local() recv() packet (1500 bytes)
          ↓
T=0.2ms:  Filter check: IP=10.0.0.100 ✓, Protocol=UDP ✓
          ↓
T=0.3ms:  Round-robin: rr_idx=5 % 3 = 2 → WAN[2]
          ↓
T=0.4ms:  thread_pool_submit():
          - malloc packet_item_t
          - memcpy 1500 bytes
          - generate UUID: 0193a4e8400070...
          - timestamp: 1735142400000
          ↓
T=0.5ms:  packet_queue_push():
          - Lock mutex
          - Create node
          - Add to queue tail
          - size: 23 → 24
          - Signal cond_not_empty
          - Unlock mutex
          ↓
T=0.6ms:  capture_local() quay lại recv() đợi packet tiếp
          
          === QUEUE STATE ===
          [P20] → [P21] → [P22] → [P23] → [NEW_P24] → NULL
          
T=1ms:    Worker thread #2 đang chờ ở cond_wait()
          - Nhận signal cond_not_empty
          - Wake up!
          ↓
T=1.1ms:  packet_queue_pop():
          - Lock mutex
          - Pop from head: [P20]
          - size: 24 → 23
          - Signal cond_not_full
          - Unlock mutex
          ↓
T=1.2ms:  Worker #2 có packet [P20]
          ↓
T=1.3ms:  send_to_wan_callback():
          - wan_idx = 2 → cfg.wan[2]
          - Setup sockaddr_ll
          - Destination MAC: ff:ff:ff:ff:ff:ff
          ↓
T=1.4ms:  sendto() trên WAN[2] interface (eth3)
          - 1500 bytes sent
          ↓
T=1.5ms:  free(packet)
          ↓
T=1.6ms:  Worker #2 quay lại packet_queue_pop() đợi packet mới
```

---

## 🔄 Multiple Threads Working Together

**Scenario: 3 WAN, 4 Workers, 100 packets/sec**

```
Time  | Capture Thread | Queue | Worker1  | Worker2  | Worker3  | Worker4
------|----------------|-------|----------|----------|----------|----------
0ms   | Recv P1 → Q   | [P1]  | Pop P1   | Sleep    | Sleep    | Sleep
1ms   | Recv P2 → Q   | [P2]  | Send P1  | Pop P2   | Sleep    | Sleep
      |                |       | WAN[0]   |          |          |
2ms   | Recv P3 → Q   | [P3]  | Pop P3   | Send P2  | Sleep    | Sleep
      |                |       |          | WAN[1]   |          |
3ms   | Recv P4 → Q   | [P4]  | Send P3  | Sleep    | Pop P4   | Sleep
      |                |       | WAN[2]   |          |          |
4ms   | Recv P5 → Q   | [P5]  | Pop P5   | Sleep    | Send P4  | Sleep
      |                |       |          |          | WAN[0]   |
```

**Round-robin distribution:**
- P1 → WAN[0]
- P2 → WAN[1]
- P3 → WAN[2]
- P4 → WAN[0]
- P5 → WAN[1]

---

## 🎯 Key Points

1. **Thread-safe**: Tất cả operations trên queue đều được protect bởi mutex
2. **Non-blocking capture**: Capture thread không bị block khi queue đầy
3. **Load balancing**: Workers tự động pick packets từ queue
4. **UUID tracking**: Mỗi packet có unique ID để debug/tracking
5. **Graceful shutdown**: Đợi queue rỗng trước khi thoát
6. **Zero packet loss**: Blocking queue đảm bảo không drop packets
7. **Scalable**: Dễ dàng tăng số workers để xử lý traffic cao hơn

---

## 📈 Performance Considerations

**Queue size = 1000:**
- Nếu traffic burst > 1000 packets → Capture thread bị block
- Workers phải process đủ nhanh để giải phóng queue

**Number of workers = 4:**
- Tối ưu cho hệ thống 4-core
- Có thể tăng lên 8-16 nếu có nhiều CPU cores

**Memory usage per packet:**
- packet_item_t: ~65KB (MAX_PKT buffer)
- Queue full: 1000 × 65KB = ~65MB RAM
