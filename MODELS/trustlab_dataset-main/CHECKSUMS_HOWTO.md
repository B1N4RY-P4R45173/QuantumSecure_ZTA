# Data Integrity Verification - Checksums

To ensure data integrity and detect any corruption during download or transfer, we recommend generating and verifying checksums for all dataset files.

## Generating Checksums

### On Linux/Mac/Git Bash:

```bash
# Generate SHA256 checksums for all data files
cd Datasets
find . -name "*.csv.gz*" -type f -exec sha256sum {} \; > ../CHECKSUMS_SHA256.txt

# Generate MD5 checksums (alternative)
find . -name "*.csv.gz*" -type f -exec md5sum {} \; > ../CHECKSUMS_MD5.txt
```

### On Windows PowerShell:

```powershell
# Generate SHA256 checksums
Get-ChildItem -Path "Datasets" -Recurse -Filter "*.csv.gz*" |
  ForEach-Object {
    $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
    "$hash  $($_.FullName)"
  } | Out-File -FilePath "CHECKSUMS_SHA256.txt"

# Generate MD5 checksums (alternative)
Get-ChildItem -Path "Datasets" -Recurse -Filter "*.csv.gz*" |
  ForEach-Object {
    $hash = (Get-FileHash -Path $_.FullName -Algorithm MD5).Hash
    "$hash  $($_.FullName)"
  } | Out-File -FilePath "CHECKSUMS_MD5.txt"
```

### Using Python:

```python
import hashlib
import os
from pathlib import Path

def generate_checksums(directory="Datasets", algorithm="sha256"):
    """Generate checksums for all .csv.gz files in the dataset."""

    checksums = []
    hash_func = hashlib.sha256 if algorithm == "sha256" else hashlib.md5

    for filepath in Path(directory).rglob("*.csv.gz*"):
        if filepath.is_file():
            with open(filepath, 'rb') as f:
                file_hash = hash_func()
                # Read file in chunks to handle large files
                while chunk := f.read(8192):
                    file_hash.update(chunk)

                checksums.append(f"{file_hash.hexdigest()}  {filepath}")
                print(f"Processed: {filepath.name}")

    # Save to file
    output_file = f"CHECKSUMS_{algorithm.upper()}.txt"
    with open(output_file, 'w') as f:
        f.write('\n'.join(checksums))

    print(f"\nChecksums saved to: {output_file}")
    return checksums

# Generate SHA256 checksums
generate_checksums(algorithm="sha256")

# Generate MD5 checksums (optional)
generate_checksums(algorithm="md5")
```

## Verifying Checksums

### On Linux/Mac/Git Bash:

```bash
# Verify SHA256 checksums
sha256sum -c CHECKSUMS_SHA256.txt

# Verify MD5 checksums
md5sum -c CHECKSUMS_MD5.txt
```

Expected output:
```
Datasets/Benign/Benign.csv.gz.001: OK
Datasets/Benign/Benign.csv.gz.002: OK
...
```

### On Windows PowerShell:

```powershell
# Verify SHA256 checksums
Get-Content "CHECKSUMS_SHA256.txt" | ForEach-Object {
    $hash, $file = $_ -split '  '
    $computed = (Get-FileHash -Path $file -Algorithm SHA256).Hash
    if ($computed -eq $hash) {
        Write-Host "$file : OK" -ForegroundColor Green
    } else {
        Write-Host "$file : FAILED" -ForegroundColor Red
    }
}
```

### Using Python:

```python
import hashlib
from pathlib import Path

def verify_checksums(checksum_file="CHECKSUMS_SHA256.txt", algorithm="sha256"):
    """Verify checksums against a checksum file."""

    hash_func = hashlib.sha256 if algorithm == "sha256" else hashlib.md5

    with open(checksum_file, 'r') as f:
        checksums = [line.strip().split('  ') for line in f if line.strip()]

    all_ok = True
    for expected_hash, filepath in checksums:
        filepath = Path(filepath)

        if not filepath.exists():
            print(f"❌ {filepath.name}: FILE NOT FOUND")
            all_ok = False
            continue

        # Compute hash
        file_hash = hash_func()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                file_hash.update(chunk)

        computed_hash = file_hash.hexdigest()

        if computed_hash == expected_hash:
            print(f"✅ {filepath.name}: OK")
        else:
            print(f"❌ {filepath.name}: FAILED")
            print(f"   Expected: {expected_hash}")
            print(f"   Computed: {computed_hash}")
            all_ok = False

    if all_ok:
        print("\n✅ All checksums verified successfully!")
    else:
        print("\n⚠️  Some checksums failed verification. Files may be corrupted.")

    return all_ok

# Verify checksums
verify_checksums("CHECKSUMS_SHA256.txt", algorithm="sha256")
```

## Expected Checksums

Once generated, the CHECKSUMS_SHA256.txt file will contain entries like:

```
a1b2c3d4e5f6...  Datasets/Benign/Benign.csv.gz.001
f6e5d4c3b2a1...  Datasets/Benign/Benign.csv.gz.002
...
```

## Important Notes

1. **Generate checksums ONCE** when you first create/download the complete dataset
2. **Verify checksums** after any file transfer, download, or storage migration
3. **Save checksum files** alongside your dataset for future verification
4. **Do NOT modify data files** after generating checksums, or verification will fail
5. For split files (e.g., Benign.csv.gz.001, .002, etc.), verify each part individually

## Troubleshooting

**If verification fails:**
- Check if the file was modified or corrupted during transfer
- Re-download the specific file that failed
- Ensure you're using the same checksum algorithm (SHA256 vs MD5)
- Verify file paths match exactly (case-sensitive on Linux/Mac)

## Distribution with Dataset

**For Dataset Publishers:**
When distributing this dataset, include a pre-generated CHECKSUMS_SHA256.txt file so users can verify data integrity immediately after download.

Generate it with:
```bash
cd trustlab_dataset-main
find Datasets -name "*.csv.gz*" -type f | sort | xargs sha256sum > CHECKSUMS_SHA256.txt
```

**For Dataset Users:**
Always verify checksums before using the data in research to ensure you're working with uncorrupted files.

---

**Questions or issues with checksum verification?**
Contact: antonio.villafranca@upct.es

---

*TRUST Lab - Universidad Politécnica de Cartagena (UPCT)*
*Data Integrity Best Practices*
