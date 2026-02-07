# inbox_pipeline — Repair + Split + Extract + Sanitize Betterbird/Thunderbird INBOX (mbox-ish)

This repo contains a single Python script, `inbox_pipeline.py`, that fixes and processes Thunderbird/Betterbird IMAP-store `INBOX` files (mbox-like), especially the annoying case where message separator lines are malformed as:

Many mbox converters/importers choke on that because they expect a “real” mbox separator line like:

This tool repairs those separators, optionally splits the mailbox into smaller parts, extracts messages to `.eml`, and sanitizes them for analysis.

---

## What it does

### 1) Repair malformed separators
- Detects lines that are exactly `From ` followed by newline (no address/date).
- Looks ahead through headers and generates a standard-ish mbox separator using:
  - `Return-Path` (for an address)
  - `Date` (for a timestamp)
- Writes a repaired `.mbox` file.

### 2) Optional split (recommended for huge files)
- Splits the repaired mbox into parts at true message boundaries.
- Default part size: **512 MB** (configurable).

### 3) Extract `.eml`
- Extracts each message into individual files:
  - `msg_0000001.eml`, `msg_0000002.eml`, etc.

### 4) Sanitize `.eml`
- Drops attachments (including base64/binary payload parts).
- Keeps only:
  - `text/plain`
  - `text/html`
- Redacts:
  - Email addresses
  - Phone numbers
- Strips signatures/footers (heuristics, best-effort).
- Logs failures to `_sanitize_failures.txt` and continues.

---

## Important privacy note

Even after redaction, email bodies may still include sensitive info (names, addresses, claim numbers, policy IDs, etc.). Skim sanitized output before sharing.

---

## Requirements

- Python **3.10+** recommended (works great on Python 3.11)
- No third-party dependencies (standard library only)

Check Python:

```bash
python --version

Quick start
PowerShell (multi-line with backticks)

python C:\Temp\inbox_pipeline.py `
  --input "G:\PATH\TO\INBOX" `
  --out   "G:\OUTPUT\SANITIZED_OUT" `
  --part-mb 512

Command Prompt (cmd.exe)

One line:

python C:\Temp\inbox_pipeline.py --input "G:\PATH\TO\INBOX" --out "G:\OUTPUT\SANITIZED_OUT" --part-mb 512

Or with cmd line continuation using caret ^:

python C:\Temp\inbox_pipeline.py ^
  --input "G:\PATH\TO\INBOX" ^
  --out "G:\OUTPUT\SANITIZED_OUT" ^
  --part-mb 512

Script options
Flag	Meaning
--input	Path to your INBOX / mbox file (required)
--out	Output directory (required)
--part-mb	Split part size in MB (default: 512). Ignored if --no-split
--no-split	Skip splitting; extract directly from repaired mbox
--no-txt	Do not generate sanitized .txt outputs

Examples:

No split:

python inbox_pipeline.py --input "G:\...\INBOX" --out "G:\OUT" --no-split

No .txt output:

python inbox_pipeline.py --input "G:\...\INBOX" --out "G:\OUT" --no-txt

Output layout

The script creates timestamped outputs inside your --out directory:

SANITIZED_OUT/
  repaired_YYYYMMDD_HHMMSS.mbox
  parts_YYYYMMDD_HHMMSS/                (if split enabled)
    INBOX_part0001.mbox
    INBOX_part0002.mbox
    ...
  eml_raw_YYYYMMDD_HHMMSS/
    msg_0000001.eml
    msg_0000002.eml
    ...
  eml_sanitized_YYYYMMDD_HHMMSS/
    msg_0000001.eml
    msg_0000002.eml
    _sanitize_failures.txt              (only if any failed)
  txt_sanitized_YYYYMMDD_HHMMSS/        (unless --no-txt)
    msg_0000001.txt
    msg_0000002.txt

Troubleshooting
“Unrecognized arguments: `”

You used PowerShell backticks in cmd.exe.

    If your prompt looks like PS C:\...> → PowerShell ✅ backticks work

    If your prompt looks like C:\...> → cmd.exe ✅ use one line or ^

“Converters don’t see messages”

If your INBOX has separators like a bare From line with no metadata, many tools refuse to treat it as valid mbox. This script repairs that by generating proper From addr date separator lines.
Some emails fail sanitization

Look at:

eml_sanitized_YYYYMMDD_HHMMSS/_sanitize_failures.txt

The script logs failures and continues.
Signature stripping isn’t perfect

Correct. Signatures are chaos. The script catches common cases:

    -- signature delimiter

    “Sent from my iPhone/Android”

    common disclaimers/footers
    But not everything.

License (MIT)

MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
