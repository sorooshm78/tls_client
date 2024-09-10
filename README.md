# tls_client
The client adds a custom TLS extension header

## Usage
### Install OpenSSL
On Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install libssl-dev
```

### Cert
Put cert and change cert path in client.cpp
```
const char* cert_path = "../cert/server.crt";
```

### Build
```bash
mkdir build
cd build
cmake ..
make
```

### Run
```bash
./client <server_ip> <port> <extension_type> <extension_data>
```

