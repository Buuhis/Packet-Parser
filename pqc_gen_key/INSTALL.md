# Hướng dẫn Cài đặt PQC Key Generation Service

Tài liệu này hướng dẫn cài đặt và xử lý sự cố cho dịch vụ PQC.

---

## 1. Yêu cầu Tiền đề (Prerequisites)

Hệ thống cần đáp ứng các điều kiện sau trước khi cài đặt:

1. **Hệ điều hành:** Linux x86_64 (Ubuntu 22.04 / 24.04, Debian 11/12...).
2. **Phiên bản GLIBC:** Yêu cầu **GLIBC >= 2.35**.
   - Kiểm tra phiên bản GLIBC trên thiết bị bằng lệnh:
     ```bash
     getconf GNU_GLIBC_VERSION
     ```
     *Hoặc:*
     ```bash
     ldd --version | head -n 1
     ```
3. **Dịch vụ HashiCorp Vault:**

---

## 2. Hướng dẫn Cài đặt & Vận hành

### Cài đặt tự động bằng file `.deb`

1. **Thực hiện cài đặt gói `.deb`:**
   ```bash
   sudo dpkg -i pqc-keygen_1.0.0_amd64.deb
   ```
   *(Gói `.deb` sẽ tự động sao chép các tệp nhị phân, cấu hình thư viện  và khởi chạy dịch vụ `pqc.service`).*

2. **Chạy lệnh sinh khóa PQC mới:**
   Ngay sau khi cài xong, bạn có thể thực thi ngay lệnh sinh cặp khóa PQC:
   ```bash
   pqc -gi
   ```

---

## 3. Thao tác Kiểm tra & Quản lý (CLI Operations)

| Lệnh thao tác | Mục đích |
| :--- | :--- |
| `sudo systemctl status pqc` | Kiểm tra trạng thái dịch vụ ngầm |
| `journalctl -u pqc -f` | Xem log hoạt động theo thời gian thực |
| `pqc -gi` | Kích hoạt sinh cặp khóa PQC mới và đẩy lên Vault |
| `sudo systemctl restart pqc` | Khởi động lại dịch vụ PQC |

### Minh họa kết quả khi chạy `pqc -gi` thành công:
```text
[PQC-GI] Public Key Exported: kv/PQC_Key/local_public/a1b2c3d4.key
[PQC-GI] Successfully exported identity [a1b2c3d4] to HashiCorp Vault (kv/PQC_Key/local_public & local_private).
```

---

## 4. Troubleshooting

### 1. Lỗi `[PQC-GI] ERROR: PQC Service is not running!`
- **Nguyên nhân:** Dịch vụ `pqc.service` chưa khởi chạy nên chưa tạo file Unix socket `/var/run/pqc_keygen.sock`.
- **Khắc phục:**
  ```bash
  sudo systemctl restart pqc
  sudo systemctl status pqc
  ```

### 2. Lỗi `libscrypt.so => not found` khi kiểm tra `ldd /usr/local/bin/pqc`
- **Nguyên nhân:** Thư mục `/usr/local/lib/pqc` chưa được nạp vào cache bộ liên kết động.
- **Khắc phục:**
  ```bash
  echo "/usr/local/lib/pqc" | sudo tee /etc/ld.so.conf.d/pqc.conf
  sudo ldconfig
  ```

### 3. Lỗi `ERROR: Failed to write key to Vault`
- **Nguyên nhân:** Dịch vụ Vault chưa bật, Vault đang bị niêm phong (sealed), hoặc tệp cấu hình `.env` thiếu/sai Token & Unseal keys.
- **Các bước kiểm tra & khắc phục:**
  1. Kiểm tra trạng thái Vault:
     ```bash
     curl -s http://127.0.0.1:8200/v1/sys/health
     ```
     - **Nếu báo `Connection refused`:** Dịch vụ Vault chưa khởi chạy ➔ Chạy: `sudo systemctl restart vault`.
     - **Nếu JSON trả về `"sealed": true`:** Vault đang bị niêm phong ➔ Cần mở khóa (unseal) Vault bằng lệnh `vault operator unseal` hoặc đảm bảo file `.env` chứa đúng các `UNSEAL_KEY`.

  2. Kiểm tra log của PQC Service:
     ```bash
     journalctl -u pqc -n 50 --no-pager
     ```
     - Nếu log báo không tìm thấy `.env` hoặc sai Token ➔ Kiểm tra và cập nhật lại file `.env`:
       ```env
       VAULT_ADDR=http://127.0.0.1:8200
       VAULT_TOKEN=your_token
       UNSEAL_KEY1=key1
       UNSEAL_KEY2=key2
       UNSEAL_KEY3=key3
       ```

  3. **Sau khi xử lý xong các nguyên nhân trên:**
     Khởi động lại dịch vụ PQC và thử sinh lại khóa:
     ```bash
     sudo systemctl restart pqc
     pqc -gi
     ```

---

## 5. Hướng dẫn Cài đặt Thủ công SD-WAN Service (`sd-wan`)

> [!NOTE]
> *Hiện tại chưa phát triển đóng gói `.deb` cho `sd-wan` service, nên ta sẽ sử dụng phương án thủ công trước. Khi nào phát triển xong `.deb` thì sẽ cập nhật lại.*

### Cấu trúc thư mục bàn giao cho Developer:
Thư mục `sd-wan/` bàn giao cho nhà phát triển chứa sẵn các tệp:
- `sd-wan` (File nhị phân thực thi)
- `mwan_kmod.ko` (Kernel Module)
- `libscrypt.so` (Thư viện chia sẻ)
- `sd-wan.service` (File dịch vụ Systemd)
- `Makefile` (Kịch bản nạp cài đặt)
- Thư mục con `linux-headers/` (Chứa 4 tệp gói `.deb` nạp Kernel Headers 5.19 offline).

---

### Bước 1: Kiểm tra & Cài đặt Linux Kernel Headers (Quy trình Offline)

1. **Kiểm tra liên kết Build Kernel Headers trên thiết bị:**
   ```bash
   ls -l /lib/modules/$(uname -r)/build
   ```

2. **Trường hợp CHƯA CÓ thư mục `build` (Chưa nạp đúng Kernel Headers 5.19):**
   * **1.1 Cài đặt các gói Kernel Headers offline:**
     Truy cập vào thư mục bàn giao và cài đặt 4 gói `.deb` trong thư mục `linux-headers`:
     ```bash
     sudo dpkg -i linux-headers/*.deb
     ```
   * **1.2 Cấu hình GRUB để ưu tiên khởi động Kernel 5.19:**
     Chỉnh sửa tệp cấu hình `/etc/default/grub`:
     ```bash
     sudo vi /etc/default/grub
     ```
     Thêm/Sửa lại dòng cấu hình:
     ```env
     GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 5.19.0-051900-generic"
     ```
   * **1.3 Cập nhật GRUB và khởi động lại thiết bị:**
     ```bash
     sudo update-grub
     sudo reboot
     ```
   * **1.4 Kiểm tra lại sau khi máy khởi động lại:**
     Sau khi thiết bị khởi động lại, kiểm tra lại liên kết build:
     ```bash
     ls -l /lib/modules/$(uname -r)/build
     ```
     *(Đảm bảo kết quả hiển thị liên kết trỏ đúng tới thư mục Kernel Headers).*

---

### Bước 2: Thực thi Cài đặt Dịch vụ qua `Makefile`

Khi thư mục `build` Kernel Headers đã có sẵn:

1. **Chạy lệnh nạp toàn bộ các tệp nhị phân, thư viện và Kernel Module vào vị trí chuẩn:**
   ```bash
   sudo make install
   ```

2. **Cài đặt và Đăng ký Dịch vụ Systemd (`sd-wan.service`):**
   ```bash
   sudo make install-service
   sudo systemctl enable --now sd-wan
   ```

---

### Bước 3: Kiểm tra Trạng thái Dịch vụ

Khởi động lại và kiểm tra xem dịch vụ `sd-wan` đã hoạt động thành công hay chưa:
```bash
sudo systemctl restart sd-wan
sudo systemctl status sd-wan
```

---

## 6. Troubleshooting Khi Cài Đặt SD-WAN

### 1. Lỗi `libscrypt.so: cannot open shared object file: No such file or directory`
- **Nguyên nhân:** Thư mục `/usr/local/lib/sd-wan` chưa được nạp vào cache bộ liên kết động.
- **Khắc phục:**
  ```bash
  echo "/usr/local/lib/sd-wan" | sudo tee /etc/ld.so.conf.d/sd-wan.conf
  sudo ldconfig
  ```

### 2. Lỗi `ExecStartPre` hoặc Kernel Module `mwan_kmod.ko` không nạp được
- **Nguyên nhân:** Tệp `/usr/local/lib/modules/mwan_kmod.ko` chưa được chép đúng vị trí hoặc do thiết bị chưa được nạp đúng phiên bản Kernel Headers.
- **Khắc phục:**
  > [!TIP]
  > Bạn nên quay lại **[Bước 1: Kiểm tra & Cài đặt Linux Kernel Headers](#bước-1-kiểm-tra--cài-đặt-linux-kernel-headers-quy-trình-offline)** ở Mục 5 để kiểm tra xem thiết bị đã nạp đúng Kernel Headers 5.19 (thư mục `/lib/modules/$(uname -r)/build`) hay chưa.

  Nếu liên kết Kernel Headers đã đầy đủ mà vẫn bị lỗi, hãy thực hiện kiểm tra theo các bước sau:
  1. Kiểm tra sự tồn tại của tệp module:
     ```bash
     ls -l /usr/local/lib/modules/mwan_kmod.ko
     ```
  2. Thử nạp trực tiếp module vào Kernel để kiểm tra log chi tiết:
     ```bash
     sudo insmod /usr/local/lib/modules/mwan_kmod.ko
     dmesg | tail -n 20
     ```

### 3. Dịch vụ `sd-wan.service` báo lỗi `Failed to start`
- **Nguyên nhân:** Thiếu file cấu hình biến môi trường hoặc không kết nối được PostgreSQL / Vault.
- **Khắc phục:**
  1. Xem log chi tiết dịch vụ:
     ```bash
     journalctl -u sd-wan -n 50 --no-pager
     ```
  2. Kiểm tra xem file biến môi trường `/etc/sd-wan/sd-wan.env` hoặc `.env` đã được tạo và chứa đúng thông số kết nối CSDL / Vault hay chưa.
