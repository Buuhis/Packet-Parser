# Offline PQC keygen package

Run `make package VERSION=1.0.0` on the build machine. The resulting package
contains `pqc`, all runtime libraries cached in `lib/`, and `pqc.service`. It
does not contain source code or `/opt/.env`; the target device must already
have `/opt/.env`.
