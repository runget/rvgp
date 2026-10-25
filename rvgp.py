#!/usr/bin/env python3
import argparse
import hashlib
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ImportError:
    sys.exit("error: Python 3.11+ required (tomllib)")

MAGIC = b"RVGP\0\0\0\0"
VERSION = 1
HEADER_SIZE = 128
META_MEMBERS = ("metadata.cfg", "icon.png", "LICENSE")

ARCH_CANONICAL = {
    "x86_64": "x86_64", "amd64": "x86_64",
    "i386": "i386", "i486": "i386", "i586": "i386", "i686": "i386",
    "aarch64": "arm", "arm64": "arm",
    "armv7l": "armeabi", "armv6l": "armeabi",
}


def die(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def canonical_arch(machine: str) -> str:
    return ARCH_CANONICAL.get(machine, machine)


def sha256_file(path: Path) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def write_header(f, meta_size: int, payload_size: int,
                 meta_hash: bytes, payload_hash: bytes) -> None:
    header = struct.pack(
        "<8sIIQQQQ32s32s16s",
        MAGIC, VERSION, 0,
        HEADER_SIZE, meta_size,
        HEADER_SIZE + meta_size, payload_size,
        meta_hash, payload_hash,
        b"\0" * 16,
    )
    assert len(header) == HEADER_SIZE
    f.write(header)


def read_header(f) -> dict:
    raw = f.read(HEADER_SIZE)
    if len(raw) != HEADER_SIZE:
        die(f"file too small ({len(raw)} bytes, need {HEADER_SIZE})")
    (magic, version, _flags,
     meta_off, meta_size, payload_off, payload_size,
     meta_hash, payload_hash, _reserved) = struct.unpack(
        "<8sIIQQQQ32s32s16s", raw
    )
    if magic != MAGIC:
        die(f"bad magic {magic!r} (not a .rvgp file)")
    if version != VERSION:
        die(f"unsupported format version {version} (expected {VERSION})")
    return {
        "meta_off": meta_off, "meta_size": meta_size,
        "payload_off": payload_off, "payload_size": payload_size,
        "meta_hash": meta_hash, "payload_hash": payload_hash,
    }


def build_metadata_ar(src: Path, dst: Path) -> None:
    subprocess.run(
        ["ar", "rcsD", str(dst), *META_MEMBERS],
        cwd=str(src), check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )


def build_payload_squashfs(content_dir: Path, dst: Path) -> None:
    subprocess.run(
        ["mksquashfs", str(content_dir), str(dst),
         "-comp", "zstd", "-Xcompression-level", "6",
         "-noappend", "-no-progress", "-keep-as-directory"],
        check=True, stdout=subprocess.DEVNULL,
    )


def cmd_pack(args) -> None:
    src = Path(args.input).resolve()
    out = Path(args.output).resolve()

    if not src.is_dir():
        die(f"{src} is not a directory")
    for f in META_MEMBERS:
        if not (src / f).exists():
            die(f"missing {f} in {src}")

    content_dir = src / "content"
    if not content_dir.is_dir():
        die(f"missing content/ directory in {src}")

    arch_dirs = sorted(p.name for p in content_dir.iterdir() if p.is_dir())
    if not arch_dirs:
        die("content/ has no architecture subdirectories")

    try:
        meta = tomllib.loads((src / "metadata.cfg").read_text(encoding="utf-8"))
    except Exception as e:
        die(f"invalid metadata.cfg: {e}")

    if meta.get("rvgp_version") != VERSION:
        die(f"rvgp_version must be {VERSION}, got {meta.get('rvgp_version')!r}")
    for key in ("id", "name", "version"):
        if not meta.get(key):
            die(f"metadata.cfg missing '{key}'")

    runtimes = meta.get("runtime", {})
    if not runtimes:
        die("metadata.cfg has no [runtime.*] sections")

    for arch in arch_dirs:
        if arch not in runtimes:
            die(f"content/{arch}/ exists but no [runtime.{arch}] in metadata.cfg")
    for arch in runtimes:
        if arch not in arch_dirs:
            die(f"[runtime.{arch}] in metadata.cfg but no content/{arch}/ directory")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        meta_ar = tmp / "metadata.a"
        payload_sqfs = tmp / "payload.sqfs"

        print("[1/2] building metadata.a (ar, no compression)")
        build_metadata_ar(src, meta_ar)

        print("[2/2] building payload.sqfs (squashfs, zstd -6)")
        build_payload_squashfs(content_dir, payload_sqfs)

        meta_size = meta_ar.stat().st_size
        payload_size = payload_sqfs.stat().st_size
        meta_hash = sha256_file(meta_ar)
        payload_hash = sha256_file(payload_sqfs)

        print(f"      arch: {', '.join(arch_dirs)}")
        print(f"      metadata: {meta_size:,} bytes")
        print(f"      payload:  {payload_size:,} bytes")
        print(f"      writing {out}")

        with open(out, "wb") as f:
            write_header(f, meta_size, payload_size, meta_hash, payload_hash)
            f.write(meta_ar.read_bytes())
            f.write(payload_sqfs.read_bytes())

    print(f"done: {out} ({out.stat().st_size:,} bytes)")


def read_metadata(rvgp_path: Path, header: dict) -> dict:
    with open(rvgp_path, "rb") as f:
        f.seek(header["meta_off"])
        meta_bytes = f.read(header["meta_size"])

    if len(meta_bytes) != header["meta_size"]:
        die("metadata region truncated (file corrupted?)")
    if hashlib.sha256(meta_bytes).digest() != header["meta_hash"]:
        die("metadata checksum mismatch (file corrupted)")

    with tempfile.NamedTemporaryFile(suffix=".a", delete=False) as tmp:
        tmp.write(meta_bytes)
        tmp_path = Path(tmp.name)

    try:
        try:
            cfg_bytes = subprocess.check_output(
                ["ar", "p", str(tmp_path), "metadata.cfg"],
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            die("ar not found (install: sudo apt install binutils)")
        except subprocess.CalledProcessError as e:
            die(f"failed to read metadata.cfg: {e.stderr.decode().strip()}")
    finally:
        tmp_path.unlink()

    try:
        return tomllib.loads(cfg_bytes.decode("utf-8"))
    except tomllib.TOMLDecodeError as e:
        die(f"invalid metadata.cfg: {e}")


def check_run_deps() -> None:
    if shutil.which("squashfuse") is None:
        die("squashfuse not found\n       install: sudo apt install squashfuse fuse3")
    if shutil.which("fusermount") is None and shutil.which("fusermount3") is None:
        die("fusermount not found\n       install: sudo apt install fuse3")


def mount_payload(rvgp_path: Path, offset: int, mountpoint: Path) -> None:
    result = subprocess.run(
        ["squashfuse", "-o", f"offset={offset}",
         str(rvgp_path), str(mountpoint)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        die(
            f"squashfuse failed (rc={result.returncode})\n"
            f"       stderr: {result.stderr.strip() or '(empty)'}"
        )


def unmount(mountpoint: Path) -> None:
    for cmd in ("fusermount3", "fusermount"):
        if shutil.which(cmd) is None:
            continue
        r = subprocess.run([cmd, "-u", str(mountpoint)],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return
    subprocess.run(["umount", str(mountpoint)], capture_output=True)


def list_dir(path: Path) -> str:
    if not path.exists():
        return "(does not exist)"
    items = sorted(p.name for p in path.iterdir())
    return ", ".join(items) if items else "(empty)"


def cmd_run(args) -> None:
    def info(msg: str) -> None:
        if not args.quiet:
            print(msg)

    rvgp_path = Path(args.file).resolve()
    if not rvgp_path.is_file():
        die(f"{rvgp_path} not found or not a file")

    check_run_deps()

    with open(rvgp_path, "rb") as f:
        header = read_header(f)

    meta = read_metadata(rvgp_path, header)

    machine = args.arch or platform.machine()
    arch = canonical_arch(machine)

    info(f"game: {meta.get('name', '?')} {meta.get('version', '')}".rstrip())
    info(f"host: {machine}  ->  arch: {arch}")

    runtimes = meta.get("runtime", {})
    if not runtimes:
        die("metadata.cfg has no [runtime.*] sections")
    if arch not in runtimes:
        die(
            f"no [runtime.{arch}] in metadata.cfg\n"
            f"       available: {', '.join(runtimes.keys())}\n"
            f"       hint: use --arch <name> to force a different arch"
        )

    runtime = runtimes[arch]
    exec_parts = list(runtime.get("exec", []))
    if not exec_parts:
        die(f"[runtime.{arch}].exec is empty")

    mnt = Path(tempfile.mkdtemp(prefix="rvgp-"))
    exit_code = 1
    mounted = False

    try:
        info(f"mounting payload -> {mnt}")
        mount_payload(rvgp_path, header["payload_off"], mnt)
        mounted = True

        arch_dir = None
        for candidate in (mnt / "content" / arch, mnt / arch):
            if candidate.is_dir():
                arch_dir = candidate
                break
        if arch_dir is None:
            die(
                f"no content for '{arch}' inside .rvgp\n"
                f"       searched: content/{arch}/, {arch}/\n"
                f"       root contains: {list_dir(mnt)}\n"
                f"       hint: rebuild with current rvgp pack"
            )

        resolved = []
        for part in exec_parts:
            if part.startswith("./"):
                part = str(arch_dir / part[2:])
            elif part.startswith("/"):
                die(f"[runtime.{arch}].exec has absolute path: {part}")
            else:
                part = part.replace("{content_dir}", str(arch_dir))
                part = part.replace("{arch_dir}", str(arch_dir))
            resolved.append(part)

        first = resolved[0]
        if "/" in first:
            exe = Path(first)
            if not exe.exists():
                die(
                    f"executable not found: {first}\n"
                    f"       {arch_dir} contains: {list_dir(arch_dir)}"
                )
        else:
            if shutil.which(first) is None:
                die(f"command not found in PATH: {first}")

        env = os.environ.copy()

        lib_paths = [str(arch_dir)]
        if env.get("LD_LIBRARY_PATH"):
            lib_paths.append(env["LD_LIBRARY_PATH"])
        env["LD_LIBRARY_PATH"] = ":".join(lib_paths)

        env.update(runtime.get("env", {}))

        info(f"$ {' '.join(resolved)}")
        info(f"  cwd: {arch_dir}")

        exit_code = subprocess.run(
            resolved, cwd=str(arch_dir), env=env
        ).returncode

    except KeyboardInterrupt:
        info("\ninterrupted")
        exit_code = 130
    finally:
        if mounted:
            if args.keep_mounted:
                info(f"note: left mounted at {mnt}")
            else:
                unmount(mnt)
                try:
                    mnt.rmdir()
                except OSError:
                    pass

    sys.exit(exit_code)


def main() -> None:
    p = argparse.ArgumentParser(prog="rvgp")
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("pack", help="pack directory into .rvgp")
    pp.add_argument("input")
    pp.add_argument("-o", "--output", required=True)
    pp.set_defaults(func=cmd_pack)

    pr = sub.add_parser("run", help="run game from .rvgp")
    pr.add_argument("file")
    pr.add_argument("--arch", help="force architecture (x86_64, i386, arm, armeabi)")
    pr.add_argument("--keep-mounted", action="store_true",
                    help="do not unmount after exit")
    pr.add_argument("-q", "--quiet", action="store_true",
                    help="suppress informational output")
    pr.set_defaults(func=cmd_run)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
