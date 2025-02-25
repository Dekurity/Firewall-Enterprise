# Enterprise Firewall

🔥 Sebuah solusi firewall komprehensif menggunakan eBPF, machine learning, dan integrasi threat intelligence untuk mengamankan jaringan Anda dengan efisien.

## Fitur

1. **Optimalisasi eBPF**: Memanfaatkan Extended Berkeley Packet Filter (eBPF) untuk filtering paket yang efisien.
2. **Machine Learning**: Mendeteksi anomali jaringan menggunakan model Isolation Forest dan Random Forest.
3. **Integrasi Threat Intelligence**: Terintegrasi dengan OTX AlienVault untuk memblokir IP yang dikenal berbahaya.
4. **Sinkronisasi Cloud Firewall**: Menyinkronkan aturan firewall di AWS, Azure, dan GCP.
5. **Rate Limiting dan Proteksi Brute Force**: Menerapkan rate limiting dan proteksi brute force untuk upaya login.
6. **Proteksi CSRF dan Keamanan API**: Melindungi dari serangan CSRF dan mengamankan API dengan autentikasi JWT.
7. **Pemblokiran GeoIP**: Memblokir akses dari negara tertentu menggunakan GeoIP2.

## Prasyarat

- Python 3.x
- pip
- Linux dengan kernel yang kompatibel untuk eBPF/XDP
- Elasticsearch

## Instalasi

1. **Clone Repositori**

   ```bash
   git clone https://github.com/your-repo/enterprise-firewall.git
   cd enterprise-firewall
   ```

2. **Install Dependensi**

   ```bash
   pip install -r requirements.txt
   ```

3. **Buat File Konfigurasi**

   Buat file berikut di `/etc/firewall/`:

   - `config.yaml`
   - `rules.yaml`
   - `gcp_credentials.json`
   - `firewall_filter.c`

   Contoh isi file tersedia di direktori `config_examples`.

4. **Jalankan Firewall**

   Pastikan untuk menjalankan firewall sebagai root atau dengan sudo:

   ```bash
   sudo python3 firewall.py
   ```

## Konfigurasi

### config.yaml

```yaml
jwt_secret: "supersecretkey"
admin_user: "admin"
admin_pw_hash: "$2b$12$XXXXXXXXXXXXXXXXXXXXXXX"  # Hash bcrypt dari password admin
network_interface: "eth0"

# Elasticsearch Logging
elasticsearch_host: "http://localhost:9200"

# API Key untuk threat intelligence
otx_api_key: "your-otx-api-key"

# AWS Config
aws_access_key: "your-aws-access-key"
aws_secret_key: "your-aws-secret-key"
aws_region: "us-east-1"
aws_sg_id: "sg-XXXXXXXX"

# Azure Config
azure_sub_id: "your-azure-subscription-id"
azure_resource_group: "your-resource-group"
azure_nsg_name: "your-nsg-name"

# GCP Config
gcp_project_id: "your-gcp-project-id"
gcp_cred_path: "/etc/firewall/gcp_credentials.json"
```

### rules.yaml

```yaml
filtering:
  - protocol: "TCP"
    src_ip: "any"
    dest_ip: "192.168.1.1"
    dest_port: 22
    action: "allow"

  - protocol: "UDP"
    src_ip: "any"
    dest_ip: "192.168.1.1"
    dest_port: 53
    action: "allow"

  - protocol: "TCP"
    src_ip: "any"
    dest_ip: "any"
    dest_port: 80
    action: "deny"

nat:
  - type: "masquerade"
    src_ip: "192.168.1.0/24"
    dest_ip: "any"

security_policies:
  - name: "SSH Rate Limit"
    protocol: "TCP"
    port: 22
    rate_limit: "5 per minute"
```

### gcp_credentials.json

```json
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "XXXXXXXXXXXXXXXXXXXX",
  "private_key": "-----BEGIN PRIVATE KEY-----\nXXXXX\n-----END PRIVATE KEY-----\n",
  "client_email": "your-service-account@your-project-id.iam.gserviceaccount.com",
  "client_id": "123456789012345678901",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/your-service-account@your-project-id.iam.gserviceaccount.com"
}
```

### firewall_filter.c

```c
#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

BPF_HASH(block_table, u32, u32);

int xdp_filter(struct __sk_buff *skb) {
    struct iphdr *ip = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
    
    u32 *blocked = block_table.lookup(&ip->saddr);
    if (blocked) {
        return XDP_DROP;
    }
    return XDP_PASS;
}
```

## API Endpoints

1. **Login**
   - **Endpoint:** `/api/login`
   - **Method:** `POST`
   - **Body:**
     ```json
     {
       "username": "admin",
       "password": "yourpassword"
     }
     ```

2. **Blokir IP**
   - **Endpoint:** `/api/block`
   - **Method:** `POST`
   - **Headers:** `Authorization: Bearer <your_jwt_token>`
   - **Body:**
     ```json
     {
       "ip": "192.168.1.100"
     }
     ```

3. **Dapatkan Statistik**
   - **Endpoint:** `/api/stats`
   - **Method:** `GET`
   - **Headers:** `Authorization: Bearer <your_jwt_token>`

## Lisensi

Proyek ini dilisensikan di bawah MIT License - lihat file [LICENSE](LICENSE) untuk detail lebih lanjut.

## Kontributor

- [Dekurity](https://github.com/dekurity)

## Penghargaan

- [OTX AlienVault](https://otx.alienvault.com/)
- [Elasticsearch](https://www.elastic.co/)
- [Flask](https://flask.palletsprojects.com/)
