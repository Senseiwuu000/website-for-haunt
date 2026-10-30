#!/usr/bin/env python3
"""Build test fixtures for the scanner. Not part of the site build."""

import io
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = os.path.join(ROOT, ".tmp")
os.makedirs(TMP, exist_ok=True)

real_jar = os.path.join(TMP, "commons-lang3.jar")
with zipfile.ZipFile(real_jar) as jar:
    string_utils = jar.read("org/apache/commons/lang3/StringUtils.class")
    number_utils = jar.read("org/apache/commons/lang3/math/NumberUtils.class")

# --- second-level nested jar ------------------------------------------------
inner2 = io.BytesIO()
with zipfile.ZipFile(inner2, "w", zipfile.ZIP_DEFLATED) as jar:
    jar.writestr("note.txt", "second stage lives here")

# --- first-level nested jar -------------------------------------------------
inner1 = io.BytesIO()
with zipfile.ZipFile(inner1, "w", zipfile.ZIP_DEFLATED) as jar:
    jar.writestr("dev/aurora/Nested.class", number_utils)
    jar.writestr("lib/deeper.jar", inner2.getvalue())

manifest = "\r\n".join([
    "Manifest-Version: 1.0",
    "Main-Class: dev.aurora.Boot",
    "Premain-Class: dev.aurora.Agent",
    "Class-Path: https://cdn.example.net/stage.jar",
    "",
])

suspicious_config = """
{
  "endpoint": "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz",
  "fallback": "http://45.13.22.9/stage2.jar",
  "mirror": "https://catbox.moe/abc123.jar"
}
"""

shell = "powershell -nop -w hidden -enc SQBFAFgA"
runkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
roaming = r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
exfil = "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"

out = os.path.join(TMP, "suspect.jar")
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as jar:
    jar.writestr("META-INF/MANIFEST.MF", manifest)
    jar.writestr("META-INF/NETMASK.SF", "Signature-Version: 1.0\r\n")
    jar.writestr("dev/aurora/Boot.class", string_utils)
    jar.writestr("dev/aurora/Agent.class", number_utils)
    jar.writestr("dev/aurora/NotAClass.class", "this is definitely not java bytecode")
    jar.writestr("lib/loader.jar", inner1.getvalue())
    jar.writestr("bin/payload.exe", b"MZ" + b"\x00" * 64)
    jar.writestr("assets/texture.png.exe", b"MZ" + b"\x00" * 32)
    jar.writestr("data/settings.json", suspicious_config)
    jar.writestr("data/run.bat", "\r\n".join([shell, runkey, roaming, exfil]))
    jar.writestr("data/empty.bin", b"")
    for index in range(30):
        jar.writestr(f"dev/aurora/a{index}.class", string_utils)

print(out)
