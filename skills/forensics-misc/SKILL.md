name: forensics-misc
description: CTF forensics / steganography / traffic analysis — identify the file type, extract hidden data from images (LSB/EXIF/PNG chunks), audio (spectrogram), files (binwalk/steghide/polyglots), and text (zero-width/whitespace); plus pcap analysis and strings-based flag hunting. Use on misc/forensics challenges where a file or capture hides the flag.
---

# CTF Forensics / Steganography / Traffic

Authorized CTF/assessment use. The flag is hidden in a file or capture. Workflow: identify → extract → decode. Tools do the heavy lifting; the skill is knowing which to reach for per file type.

## 1. Identify first

```bash
file mystery          # what is it really?
binwalk mystery       # nested files/archive inside?
strings -n 6 mystery  # obvious flag / embedded text?
xxd mystery | head    # magic bytes
```
A renamed file, an appended zip, or a modified image are the usual tricks.

## 2. Image steganography

```bash
zsteg img.png -a                       # LSB + all known PNG/BMP patterns
exiftool img.jpg                       # EXIF metadata (comment/flag)
strings img.png                        # text chunks
binwalk -e img.png                     # appended data
# PNG dimension tricks: a corrupt IHDR width/height hides a flag region — fix the dimensions
# JPEG DCT / palette / alpha-channel hides are less common but try steghide:
steghide extract -sf img.jpg
```

## 3. Audio / other media

```bash
# spectrogram hides text/flag in the frequency image
sox -n spec.png spectrogram -r < audio.wav   # render a spectrogram and read it
# DTMF / morse in audio → decode with multimon-ng / audacity
```

## 4. File & text steganography

```bash
binwalk -e file          # extract embedded archives/images
steghide extract -sf file
# text: zero-width chars, trailing whitespace, homoglyphs → decode with a zero-width decoder
# polyglot: one file valid as two formats (jpg+zip, png+py) → open with the OTHER format
```

## 5. Traffic analysis (pcap)

```bash
tshark -r cap.pcap -Y http -T fields -e http.request.uri   # URLs (flag in a path?)
tshark -r cap.pcap --export-objects http,out              # extract files (a zip/flag inside)
tshark -r cap.pcap -Y ftp -T fields -e ftp.request.arg     # FTP creds / transfers
strings cap.pcap | grep -i flag                            # raw flag bytes
# DNS exfil / icmp tunnels → follow the stream, reassemble
```

## 6. Disk / memory

```bash
strings dump.raw | grep -i flag       # memory/disk flag
volatility -f mem.raw imageinfo → pslist / filescan / dumpfiles
# deleted files / slack space: foremost / testdisk on the disk image
```

## Cross-cutting
- **`file` + `binwalk` + `strings` first, always** — half of forensics flags are just `strings`.
- **Match the tool to the file type** — zsteg for PNG, exiftool for JPEG, spectrogram for audio, tshark for pcap.
- **Extracted data is usually encoded** — after extraction, run it through the decode layers (base64/rot/hex) from crypto-ctf.
