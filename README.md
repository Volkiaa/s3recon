# s3recon

Cloud storage misconfiguration scanner. Discovers publicly accessible S3-compatible buckets associated with a target domain and tests them for list, read, and write access.

## Supported Providers

- AWS S3
- Google Cloud Storage (GCS)
- Scaleway Object Storage
- DigitalOcean Spaces
- Backblaze B2

## How It Works

The scanner runs four discovery phases before probing candidates concurrently:

1. **HTML scraping** — fetches the target's homepage and extracts S3 URLs from the response body
2. **TLS certificate SANs** — inspects the domain's TLS cert and checks each SAN for storage endpoints
3. **Subdomain DNS probing** — resolves common storage-related subdomains (e.g. `assets.example.com`) and checks for S3 CNAME targets or listing responses
4. **Bucket name generation** — generates bucket name variants from the company name and probes them across all supported providers and regions

Each candidate is then checked for:

| Access | Method | Severity |
|--------|--------|----------|
| LIST   | GET `/` → parse S3 XML listing | MEDIUM |
| READ   | GET first listed object | HIGH |
| WRITE  | PUT probe file + immediate DELETE | CRITICAL |

## Installation

```bash
git clone <repo>
cd s3recon
go build -o s3recon .
```

Requires Go 1.22+.

## Usage

```
s3recon -target <domain> [options]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | *(required)* | Target domain (e.g. `example.com`) |
| `-w` | `30` | Number of concurrent workers |
| `-v` | `false` | Verbose: print each candidate as it is queued |
| `-json` | `false` | Output findings as JSON (progress goes to stderr) |

### Examples

```bash
# Basic scan
s3recon -target example.com

# More workers for faster scans
s3recon -target example.com -w 50

# JSON output, pipe to jq
s3recon -target example.com -json | jq '.findings[]'

# Verbose mode to see all candidates
s3recon -target example.com -v
```

## Output

### Terminal (default)

Color-coded findings with severity, provider, discovery source, access flags, object count, and a ready-to-use PoC `curl` command.

```
  [CRITICAL] Finding #1
  URL:       https://example-prod.s3.amazonaws.com/
  Provider:  AWS S3
  Source:    generated
  LIST:      YES ✗
  READ:      YES ✗
  WRITE:     YES ✗
  Objects:   42 objects (e.g. backups/db-2024-01-01.sql.gz)

  PoC:
  curl -s "https://example-prod.s3.amazonaws.com/" | grep -oP '(?<=<Key>)[^<]+'
```

### JSON (`-json`)

```json
{
  "target": "example.com",
  "candidates_checked": 1240,
  "finding_count": 1,
  "findings": [
    {
      "url": "https://example-prod.s3.amazonaws.com/",
      "provider": "AWS S3",
      "source": "generated",
      "severity": "CRITICAL",
      "can_list": true,
      "can_read": true,
      "can_write": true,
      "object_count": 42,
      "objects": [...]
    }
  ]
}
```

## Severity Levels

| Level | Condition |
|-------|-----------|
| `CRITICAL` | Public write access |
| `HIGH` | Public list + read access |
| `MEDIUM` | Public list access only |
| `INFO` | Bucket exists but no access |

## Legal

Only scan targets you own or have explicit written permission to test. Unauthorized scanning may violate computer fraud laws and cloud provider terms of service.
