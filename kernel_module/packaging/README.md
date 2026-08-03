# Binary-only Debian package

Build on the same OS family, CPU architecture, and kernel release as the
target device:

```bash
make package VERSION=1.0.0
```

The output package is written to `dist/`. During every build, the runtime
library cache `kernel_module/lib/` is refreshed with `libscrypt.so` and all
non-core runtime dependencies required by the daemon. The package is assembled
from that directory and contains `sd-wan`, `mwan_kmod.ko`, the systemd unit,
an environment-file example, and those libraries. Source code is not included.
The target device can therefore install the package while offline.

Install on a device running the exact kernel shown in the package name:

```bash
sudo apt install ./sd-wan_1.0.0_amd64_linux-<kernel-release>.deb
sudo install -D -m 600 /usr/share/sd-wan/sd-wan.env.example /etc/sd-wan/sd-wan.env
sudoedit /etc/sd-wan/sd-wan.env
sudo systemctl enable --now sd-wan
```

`mwan_kmod.ko` is kernel-specific. Build a separate package for every target
kernel release and CPU architecture. Secure Boot systems also require the
module to be signed and enrolled before `modprobe` can load it.
