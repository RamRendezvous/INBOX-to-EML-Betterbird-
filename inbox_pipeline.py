#!/usr/bin/env python3
"""
inbox_pipeline.py

One-script pipeline for Thunderbird/Betterbird IMAP-store mbox-like files where
message separators may be malformed as: "From " + CRLF (nothing else).

Pipeline:
1) Repair malformed mbox separators into valid "From addr timestamp" lines.
2) (Optional) Split repaired mbox into size-limited parts.
3) Extract each message to .eml
4) Sanitize each .eml:
   - Keep only text/plain and text/html parts
   - Drop attachments (including base64 blobs / binary parts)
   - Redact email addresses + phone numbers
   - Remove signatures (heuristics)

Extras:
- Robust header handling:
  * Does NOT copy MIME structure headers (prevents multipart errors)
  * Cleans CR/LF from headers (prevents "address parts cannot contain CR or LF")
- Sanitizer logs failures and continues.

Works on Windows. Streaming-based: does NOT load 6GB into memory.

USAGE (PowerShell):
  python C:\Temp\inbox_pipeline.py `
    --input "G:\...\INBOX" `
    --out "G:\OUT" `
    --part-mb 512

USAGE (cmd.exe):
  python C:\Temp\inbox_pipeline.py --input "G:\...\INBOX" --out "G:\OUT" --part-mb 512
"""

import argparse
import os
import re
import time
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from email.utils import parsedate_to_datetime


# ----------------------------
# Redaction + signature tools
# ----------------------------

EMAIL_RE = re.compile(
    r"""(?ix)
    \b
    [a-z0-9._%+\-]+
    @
    [a-z0-9.\-]+\.[a-z]{2,}
    \b
    """
)

# Phone-ish patterns (US-centric but catches many variants)
PHONE_RE = re.compile(
    r"""(?x)
    (?:
        (?:\+?\d{1,3}[\s\-\.])?          # country code
        (?:\(?\d{3}\)?[\s\-\.])          # area code
        \d{3}[\s\-\.]\d{4}               # local
        (?:\s*(?:x|ext\.?)\s*\d{1,6})?   # extension
    )
    """
)

SIGNATURE_CUE_RE = re.compile(
    r"""(?im)
    ^\s*(--\s*$|__\s*$|—\s*$|-\s*$)\s*$|
    ^\s*sent\s+from\s+my\s+|
    ^\s*sent\s+from\s+iphone|
    ^\s*sent\s+from\s+android|
    ^\s*get\s+outlook\s+for\s+|
    ^\s*this\s+message\s+and\s+any\s+attachments\s+|
    ^\s*confidentiality\s+notice|
    ^\s*disclaimer
    """
)

FOOTER_START_RE = re.compile(
    r"""(?im)
    ^\s*(confidentiality\s+notice|disclaimer|this\s+email|privileged|intended\s+only)\b
    """
)


def redact_text(s: str) -> str:
    s = EMAIL_RE.sub("[REDACTED_EMAIL]", s)
    s = PHONE_RE.sub("[REDACTED_PHONE]", s)
    return s


def strip_signature_plain(text: str) -> str:
    lines = text.splitlines()
    cut_idx = None

    for i, line in enumerate(lines):
        if SIGNATURE_CUE_RE.search(line):
            cut_idx = i
            break

    if cut_idx is None:
        closing_re = re.compile(r"(?im)^\s*(thanks|thank you|regards|best|sincerely|cheers)[,!\s]*$")
        for i in range(max(0, len(lines) - 25), len(lines)):
            if closing_re.match(lines[i] or ""):
                tail = lines[i + 1 :]
                if 1 <= len(tail) <= 12:
                    cut_idx = i
                    break

    if cut_idx is None:
        for i in range(max(0, len(lines) - 60), len(lines)):
            if FOOTER_START_RE.search(lines[i] or ""):
                cut_idx = i
                break

    if cut_idx is not None:
        lines = lines[:cut_idx]

    while lines and not lines[-1].strip():
        lines.pop()

    return "\n".join(lines)


def strip_signature_html(html: str) -> str:
    h = html
    hl = h.lower()

    cut_points = []
    for marker in ["<hr", '<div class="gmail_signature', "sent from my", "get outlook for"]:
        idx = hl.find(marker)
        if idx != -1:
            cut_points.append(idx)

    if cut_points:
        h = h[: min(cut_points)]

    h = re.sub(
        r"(?is)<(div|p)[^>]*>\s*(confidentiality notice|disclaimer|this message and any attachments).*?</\1>",
        "",
        h,
    )
    return h


# ----------------------------
# Mbox repair + split + extract
# ----------------------------

def parse_date_header(date_value: str) -> str:
    fallback = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    if not date_value:
        return fallback
    try:
        dt = parsedate_to_datetime(date_value)
        if dt is None:
            return fallback
        return dt.strftime("%a %b %d %H:%M:%S %Y")
    except Exception:
        return fallback


RETURN_PATH_RE = re.compile(r"(?im)^Return-Path:\s*(.+?)\s*$")
DATE_RE = re.compile(r"(?im)^Date:\s*(.+?)\s*$")


def make_from_line(headers_block: str) -> str:
    addr = "unknown"
    m = RETURN_PATH_RE.search(headers_block)
    if m:
        rp = m.group(1).strip()
        mm = re.search(r"<([^>]+)>", rp)
        if mm:
            addr = mm.group(1).strip()
        else:
            addr = rp.strip()

    date_val = ""
    m2 = DATE_RE.search(headers_block)
    if m2:
        date_val = m2.group(1).strip()
    stamp = parse_date_header(date_val)

    return f"From {addr} {stamp}"


def repair_mbox(input_path: str, repaired_path: str) -> int:
    fixed = 0
    with open(input_path, "rb") as fin, open(repaired_path, "wb") as fout:
        while True:
            line = fin.readline()
            if not line:
                break

            if line in (b"From \r\n", b"From \n", b"From \r"):
                headers = []
                peek_lines = []
                for _ in range(2000):
                    nxt = fin.readline()
                    if not nxt:
                        break
                    peek_lines.append(nxt)
                    headers.append(nxt.decode("utf-8", errors="replace"))
                    if nxt in (b"\r\n", b"\n", b"\r"):
                        break

                headers_block = "".join(headers)
                from_line = make_from_line(headers_block).encode("utf-8") + b"\r\n"
                fout.write(from_line)
                for pl in peek_lines:
                    fout.write(pl)
                fixed += 1
            else:
                fout.write(line)

            if fixed and fixed % 5000 == 0:
                print(f"[repair] fixed separators: {fixed}", flush=True)

    return fixed


def split_mbox(repaired_path: str, parts_dir: str, part_mb: int) -> list[str]:
    os.makedirs(parts_dir, exist_ok=True)
    part_size = part_mb * 1024 * 1024

    part_paths: list[str] = []
    part_idx = 1

    def new_part_path(i: int) -> str:
        return os.path.join(parts_dir, f"INBOX_part{i:04d}.mbox")

    out_path = new_part_path(part_idx)
    fout = open(out_path, "wb")
    part_paths.append(out_path)
    bytes_in_part = 0

    msg_buf = bytearray()
    have_any = False

    def flush_message():
        nonlocal msg_buf, bytes_in_part, fout, out_path, part_idx, part_paths
        if not msg_buf:
            return
        msg_bytes = bytes(msg_buf)

        if bytes_in_part > 0 and (bytes_in_part + len(msg_bytes) > part_size):
            fout.flush()
            fout.close()
            part_idx += 1
            out_path = new_part_path(part_idx)
            fout = open(out_path, "wb")
            part_paths.append(out_path)
            bytes_in_part = 0

        fout.write(msg_bytes)
        bytes_in_part += len(msg_bytes)
        msg_buf = bytearray()

    with open(repaired_path, "rb") as fin:
        while True:
            line = fin.readline()
            if not line:
                break

            if line.startswith(b"From "):
                if have_any:
                    flush_message()
                have_any = True

            msg_buf.extend(line)

    flush_message()
    fout.flush()
    fout.close()

    return part_paths


def extract_eml_from_mbox(mbox_path: str, out_dir: str, start_index: int = 0) -> int:
    os.makedirs(out_dir, exist_ok=True)
    idx = start_index
    buf_lines: list[bytes] = []
    started = False

    def write_message(lines: list[bytes], msg_index: int):
        if not lines:
            return
        if lines[0].startswith(b"From "):
            lines = lines[1:]
        path = os.path.join(out_dir, f"msg_{msg_index:07d}.eml")
        with open(path, "wb") as f:
            f.write(b"".join(lines))

    with open(mbox_path, "rb") as fin:
        while True:
            line = fin.readline()
            if not line:
                break

            if line.startswith(b"From "):
                if started:
                    idx += 1
                    write_message(buf_lines, idx)
                    buf_lines = []
                else:
                    started = True

            if started:
                buf_lines.append(line)

    if started and buf_lines:
        idx += 1
        write_message(buf_lines, idx)

    return idx - start_index


# ----------------------------
# EML sanitize (attachments gone)
# ----------------------------

def is_attachment(part) -> bool:
    cd = part.get_content_disposition()
    filename = part.get_filename()
    ctype = part.get_content_type()

    if cd == "attachment" or filename:
        return True
    if ctype.startswith(("application/", "image/", "audio/", "video/")):
        return True
    return False


def keep_part(part) -> bool:
    if is_attachment(part):
        return False
    return part.get_content_type() in ("text/plain", "text/html")


def get_part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")


# Copy only "safe" headers; do NOT copy MIME structure headers.
SAFE_HEADERS = [
    "Date", "From", "To", "Cc", "Bcc", "Reply-To",
    "Subject", "Message-ID", "In-Reply-To", "References",
]

def clean_header_value(v: str) -> str:
    v = v.replace("\r", " ").replace("\n", " ")
    v = re.sub(r"\s+", " ", v).strip()
    return redact_text(v)


def sanitize_eml_bytes(eml_bytes: bytes) -> tuple[bytes, str]:
    """
    Return (sanitized_eml_bytes, best_plain_text)

    Guaranteed output is either:
      - text/plain
      - multipart/alternative (plain + html)
    and never ends up as multipart/mixed.
    Also avoids CR/LF in headers and avoids copying MIME structure headers.
    """
    msg = BytesParser(policy=policy.default).parsebytes(eml_bytes)

    out = EmailMessage()

    # Copy only safe headers, cleaned. Skip malformed ones.
    for hk in SAFE_HEADERS:
        if hk in msg:
            try:
                out[hk] = clean_header_value(str(msg[hk]))
            except Exception:
                pass

    text_parts: list[str] = []
    html_parts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            if keep_part(part):
                content = get_part_text(part)
                if part.get_content_type() == "text/plain":
                    text_parts.append(content)
                elif part.get_content_type() == "text/html":
                    html_parts.append(content)
    else:
        if keep_part(msg):
            content = get_part_text(msg)
            if msg.get_content_type() == "text/plain":
                text_parts.append(content)
            elif msg.get_content_type() == "text/html":
                html_parts.append(content)

    text_parts = [redact_text(strip_signature_plain(t)) for t in text_parts]
    html_parts = [redact_text(strip_signature_html(h)) for h in html_parts]

    best_plain = ""
    if text_parts:
        best_plain = "\n\n-----\n\n".join([t for t in text_parts if t.strip()])
    elif html_parts:
        tmp = re.sub(r"(?is)<br\s*/?>", "\n", html_parts[0])
        tmp = re.sub(r"(?is)</p\s*>", "\n\n", tmp)
        tmp = re.sub(r"(?is)<[^>]+>", "", tmp)
        best_plain = tmp

    if text_parts and html_parts:
        out.set_content(best_plain if best_plain.strip() else "[Text content removed/empty after cleaning.]")
        html_blob = "\n<br><hr><br>\n".join([h for h in html_parts if h.strip()])
        if not html_blob.strip():
            html_blob = "[HTML content removed/empty.]"
        out.add_alternative(html_blob, subtype="html")

    elif text_parts:
        out.set_content(best_plain if best_plain.strip() else "[Text content removed/empty after cleaning.]")

    elif html_parts:
        out.set_content(best_plain if best_plain.strip() else "[No plain text part available; HTML kept.]")
        html_blob = "\n<br><hr><br>\n".join([h for h in html_parts if h.strip()])
        if not html_blob.strip():
            html_blob = "[HTML content removed/empty.]"
        out.add_alternative(html_blob, subtype="html")

    else:
        out.set_content("[No text parts kept. Attachments and non-text parts removed.]")
        best_plain = out.get_content()

    return out.as_bytes(policy=policy.default), best_plain


def sanitize_eml_dir(src_dir: str, dst_dir: str, txt_dir: str | None = None) -> int:
    os.makedirs(dst_dir, exist_ok=True)
    if txt_dir:
        os.makedirs(txt_dir, exist_ok=True)

    n = 0
    failed = 0
    fail_log = os.path.join(dst_dir, "_sanitize_failures.txt")

    with open(fail_log, "w", encoding="utf-8", errors="replace") as log:
        for name in sorted(os.listdir(src_dir)):
            if not name.lower().endswith(".eml"):
                continue
            src_path = os.path.join(src_dir, name)

            try:
                with open(src_path, "rb") as f:
                    b = f.read()
                sanitized_bytes, best_plain = sanitize_eml_bytes(b)

                dst_path = os.path.join(dst_dir, name)
                with open(dst_path, "wb") as f:
                    f.write(sanitized_bytes)

                if txt_dir:
                    txt_path = os.path.join(txt_dir, os.path.splitext(name)[0] + ".txt")
                    with open(txt_path, "w", encoding="utf-8", errors="replace") as tf:
                        tf.write(best_plain)

                n += 1
                if n % 500 == 0:
                    print(f"[sanitize] processed {n} emails...", flush=True)

            except Exception as e:
                failed += 1
                log.write(f"{name}\t{type(e).__name__}: {e}\n")

    if failed:
        print(f"[sanitize] WARNING: {failed} emails failed to sanitize. See: {fail_log}")

    return n


# ----------------------------
# Main
# ----------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Path to INBOX / mbox file")
    ap.add_argument("--out", required=True, help="Output directory")
    ap.add_argument("--part-mb", type=int, default=512, help="Split part size (MB). Ignored if --no-split")
    ap.add_argument("--no-split", action="store_true", help="Do not split; extract EML directly from repaired mbox")
    ap.add_argument("--no-txt", action="store_true", help="Do not create txt_sanitized outputs")
    args = ap.parse_args()

    in_path = os.path.abspath(args.input)
    out_root = os.path.abspath(args.out)
    os.makedirs(out_root, exist_ok=True)

    stamp = time.strftime("%Y%m%d_%H%M%S")
    repaired_path = os.path.join(out_root, f"repaired_{stamp}.mbox")
    parts_dir = os.path.join(out_root, f"parts_{stamp}")
    eml_raw_dir = os.path.join(out_root, f"eml_raw_{stamp}")
    eml_s_dir = os.path.join(out_root, f"eml_sanitized_{stamp}")
    txt_dir = None if args.no_txt else os.path.join(out_root, f"txt_sanitized_{stamp}")

    print(f"Input:        {in_path}")
    print(f"Output root:  {out_root}")
    print(f"Repair out:   {repaired_path}")

    print("\n[1/4] Repairing mbox separators...")
    fixed = repair_mbox(in_path, repaired_path)
    print(f"[repair] fixed separators: {fixed}")

    if args.no_split:
        print("\n[2/4] Skipping split (using repaired mbox as-is).")
        mbox_sources = [repaired_path]
    else:
        print(f"\n[2/4] Splitting repaired mbox into ~{args.part_mb}MB parts...")
        mbox_sources = split_mbox(repaired_path, parts_dir, args.part_mb)
        print(f"[split] wrote {len(mbox_sources)} parts to: {parts_dir}")

    print("\n[3/4] Extracting .eml files...")
    msg_index = 0
    for i, mbox_path in enumerate(mbox_sources, 1):
        wrote = extract_eml_from_mbox(mbox_path, eml_raw_dir, start_index=msg_index)
        msg_index += wrote
        print(f"[extract] part {i}/{len(mbox_sources)} -> extracted {wrote} messages (total {msg_index})")

    print("\n[4/4] Sanitizing EML (remove attachments + redact emails/phones + strip signatures)...")
    n = sanitize_eml_dir(eml_raw_dir, eml_s_dir, txt_dir=txt_dir)
    print(f"[sanitize] sanitized {n} emails")
    print("\nDONE.")
    print(f"Sanitized EML: {eml_s_dir}")
    if txt_dir:
        print(f"Sanitized TXT: {txt_dir}")
    print(f"Repaired mbox:  {repaired_path}")
    if not args.no_split:
        print(f"Mbox parts:     {parts_dir}")


if __name__ == "__main__":
    main()
