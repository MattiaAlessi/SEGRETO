from __future__ import annotations
import glob
import os
import shutil
import subprocess
import sys
import time
from statistics import median

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

_COLOR = sys.stdout.isatty()
if _COLOR and os.name == "nt":
    os.system("")


def c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text

def bold(t): return c("1", t)
def green(t): return c("32", t)
def yellow(t): return c("33", t)
def red(t): return c("31", t)
def dim(t): return c("90", t)
def rust(t): return c("38;5;209", t)
def sodium(t): return c("38;5;39", t)


REQUIRED_FUNCS = ["random_bytes", "encrypt", "decrypt", "x25519_keypair",
                  "x25519_shared_secret", "ed25519_keypair", "ed25519_sign",
                  "ed25519_verify", "argon2id_key", "blake2b"]
def module_ok():
    check = ("import crypto_core as cc; "
             "missing = [f for f in %r if not hasattr(cc, f)]; "
             "print(','.join(missing))" % REQUIRED_FUNCS)
    r = subprocess.run([sys.executable, "-c", check], capture_output=True, text=True)
    if r.returncode != 0:
        return False
    missing = r.stdout.strip()
    if missing:
        print(f"installed crypto_core is outdated (missing: {missing.replace(',', ', ')})")
        return False
    return True





def run_ok(cmd):
    return subprocess.run(cmd, shell=True).returncode == 0

def pip_like_install(spec, force=True):
    py = f'"{sys.executable}"'
    f = "--force-reinstall " if force else ""
    if run_ok(f"{py} -m pip install {f}{spec}"):
        return True
    if run_ok("uv --version"):
        print("no pip in this environment, using uv...")
        if run_ok(f'uv pip install --python "{sys.executable}" {f}{spec}'):
            return True
    print("bootstrapping pip with ensurepip...")
    subprocess.run(f"{py} -m ensurepip --upgrade", shell=True)
    return run_ok(f"{py} -m pip install {f}{spec}")





def extract_wheel(wheel):
    import zipfile
    import sysconfig
    site = sysconfig.get_paths()["purelib"]
    for p in glob.glob(os.path.join(site, "crypto_core*")):
        if os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
        else:
            os.remove(p)
    with zipfile.ZipFile(wheel) as z:
        z.extractall(site)
    print(f"extracted wheel into {site}")


def build_and_install():
    if not run_ok(f'"{sys.executable}" -m maturin --version'):
        print("installing maturin...")
        if not pip_like_install("maturin", force=False):
            sys.exit("cannot install maturin: no pip or uv available in this environment")
    r = subprocess.run(f'"{sys.executable}" -m maturin build --release',
                       cwd=os.path.join(ROOT, "crypto_core"), shell=True)
    if r.returncode != 0:
        sys.exit("build failed")
    wheels = sorted(glob.glob(os.path.join(ROOT, "crypto_core", "target", "wheels", "*.whl")),
                    key=os.path.getmtime)
    if not wheels:
        sys.exit("no wheel found after build")
    print(f"installing {os.path.basename(wheels[-1])}...")
    if pip_like_install(f'"{wheels[-1]}"'):
        return
    print("pip/uv unavailable: extracting the wheel manually...")
    extract_wheel(wheels[-1])


def ensure_module(force=False):
    if not force and module_ok():
        return
    print("crypto_core missing or outdated: building it now (maturin, release)...")
    build_and_install()
    if not module_ok():
        sys.exit("crypto_core still not usable after rebuild")

ensure_module(force="--rebuild" in sys.argv)

def ensure_deps():
    missing = []
    for mod, pkg in (("nacl", "pynacl"), ("matplotlib", "matplotlib")):
        r = subprocess.run([sys.executable, "-c", f"import {mod}"],
                           capture_output=True)
        if r.returncode != 0:
            missing.append(pkg)
    if missing:
        print(f"installing missing Python packages: {', '.join(missing)}...")
        if not pip_like_install(" ".join(missing)):
            sys.exit(f"could not install: {' '.join(missing)}")


ensure_deps()

import nacl.bindings
import nacl.encoding
import nacl.hash
import nacl.public
import nacl.pwhash
import nacl.signing
import nacl.utils

import crypto_core as cc

RESULTS = [] 
def bench_us(fn, *, repeat=5, min_duration=0.4):
    fn() 
    t0 = time.perf_counter()
    fn()
    single = max(time.perf_counter() - t0, 1e-9)
    number = max(1, min(int(min_duration / single), 100_000))

    times = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        for _ in range(number):
            fn()
        times.append((time.perf_counter() - t0) / number)
    return median(times) * 1e6


def fmt_us(us):
    return f"{us / 1000:.2f} ms" if us >= 1000 else f"{us:.2f} us"


def record(cat, label, rust_us, nacl_us):
    RESULTS.append((cat, label, rust_us, nacl_us))
    winner, speedup = (("Rust", nacl_us / rust_us) if rust_us < nacl_us
                       else ("PyNaCl", rust_us / nacl_us))
    wcol = rust if winner == "Rust" else sodium
    print(f"  {green('OK')}  {label:<38} Rust {rust(fmt_us(rust_us)):>11}   "
          f"PyNaCl {sodium(fmt_us(nacl_us)):>11}   {bold(wcol(f'{winner} {speedup:.1f}x'))}")


def section(title):
    print()
    print(bold(f"--- {title} " + "-" * max(0, 70 - len(title))))

def cross_check():
    section("Do Rust and PyNaCl agree?")
    checks = []

    def check(name, a, b):
        checks.append((name, a == b))

    # AEAD
    key, nonce, msg = os.urandom(32), os.urandom(24), b"secret test message" * 10
    ct_r = cc.encrypt(key, nonce, msg)
    ct_n = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(msg, None, nonce, key)
    check("AEAD ciphertext identical", ct_r, ct_n)
    check("Rust decrypts PyNaCl ciphertext", cc.decrypt(key, nonce, ct_n), msg)
    check("PyNaCl decrypts Rust ciphertext",
          nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ct_r, None, nonce, key), msg)
    bad = bytearray(ct_r)
    bad[0] ^= 1
    try:
        cc.decrypt(key, nonce, bytes(bad))
        check("Tampered ciphertext rejected", False, True)
    except Exception:
        check("Tampered ciphertext rejected", True, True)

    # X25519
    sk1, pk1 = cc.x25519_keypair()
    sk2, pk2 = cc.x25519_keypair()
    nsk = nacl.public.PrivateKey(sk1)
    check("X25519 same public key", bytes(nsk.public_key), pk1)
    check("X25519 same shared secret",
          cc.x25519_shared_secret(sk1, pk2),
          nacl.bindings.crypto_scalarmult(bytes(nsk), bytes(nacl.public.PublicKey(pk2))))

    # Ed25519
    sk, pk = cc.ed25519_keypair()
    msg2 = b"hello"
    nsig = bytes(nacl.signing.SigningKey(sk).sign(msg2).signature)
    check("Ed25519 same signature", cc.ed25519_sign(sk, msg2), nsig)
    check("Ed25519 verifies other backend", cc.ed25519_verify(pk, msg2, nsig), True)

    # Argon2id + BLAKE2b
    salt = os.urandom(16)
    check("Argon2id same derived key",
          cc.argon2id_key(b"password", salt),
          bytes(nacl.pwhash.argon2id.kdf(32, b"password", salt,
                                         opslimit=3, memlimit=64 * 1024 * 1024)))
    data = os.urandom(123)
    check("BLAKE2b same hash", cc.blake2b(data, 32),
          bytes(nacl.hash.blake2b(data, digest_size=32,
                                  encoder=nacl.encoding.RawEncoder)))

    for name, ok in checks:
        print(f"  {green('OK') if ok else red('FAIL')}  {name}")
    if not all(ok for _, ok in checks):
        sys.exit(red("Cross-check FAILED: backends disagree, benchmark cancelled."))
    print(f"\n  {green(bold('All checks passed: the two backends are bit-for-bit equivalent.'))}")


def run_benchmarks(quick):
    section("Speed: Rust vs PyNaCl (median of 5 runs)")
    print(dim("  both are native code called from Python, so the overhead is the same"))

    for size, label in [(64, "64 B (chat msg)"), (256, "256 B"), (4096, "4 KiB")] + \
                       ([] if quick else [(65536, "64 KiB")]):
        key, nonce, msg = os.urandom(32), os.urandom(24), os.urandom(size)

        def r():
            cc.decrypt(key, nonce, cc.encrypt(key, nonce, msg))

        def s():
            ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(msg, None, nonce, key)
            nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, None, nonce, key)

        record("aead", f"AEAD encrypt+decrypt ({label})", bench_us(r), bench_us(s))

    # X25519
    sk_r, pk_r = cc.x25519_keypair()
    sk_n = nacl.public.PrivateKey.generate()
    record("x25519", "X25519 keypair generation",
           bench_us(lambda: cc.x25519_keypair()),
           bench_us(lambda: nacl.public.PrivateKey.generate()))
    record("x25519", "X25519 shared secret (DH)",
           bench_us(lambda: cc.x25519_shared_secret(sk_r, pk_r)),
           bench_us(lambda: nacl.bindings.crypto_scalarmult(
               sk_n.encode(), sk_n.public_key.encode())))

    # Ed25519
    for size, label in [(64, "64 B"), (4096, "4 KiB")]:
        sk_r, pk_r = cc.ed25519_keypair()
        sk_n = nacl.signing.SigningKey.generate()
        msg = os.urandom(size)
        sig_r = cc.ed25519_sign(sk_r, msg)
        sig_n = sk_n.sign(msg).signature
        record("ed25519", f"Ed25519 sign ({label})",
               bench_us(lambda: cc.ed25519_sign(sk_r, msg)),
               bench_us(lambda: sk_n.sign(msg)))
        record("ed25519", f"Ed25519 verify ({label})",
               bench_us(lambda: cc.ed25519_verify(pk_r, msg, sig_r)),
               bench_us(lambda: sk_n.verify_key.verify(msg, sig_n)))

    # Argon2id
    pw, salt = b"a-correct-password", os.urandom(16)
    record("argon2", "Argon2id key derivation (64 MiB)",
           bench_us(lambda: cc.argon2id_key(pw, salt), repeat=3, min_duration=1.0),
           bench_us(lambda: nacl.pwhash.argon2id.kdf(32, pw, salt, opslimit=3,
                                                     memlimit=64 * 1024 * 1024),
                    repeat=3, min_duration=1.0))

    # BLAKE2b
    for size, label in [(64, "64 B"), (4096, "4 KiB")] + \
                       ([] if quick else [(65536, "64 KiB")]):
        data = os.urandom(size)
        record("blake2b", f"BLAKE2b hash ({label})",
               bench_us(lambda: cc.blake2b(data, 32)),
               bench_us(lambda: nacl.hash.blake2b(data, digest_size=32,
                                                  encoder=nacl.encoding.RawEncoder)))

def make_chart(path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker

    n = len(RESULTS)
    labels = [f"{label}" for _, label, _, _ in RESULTS]
    rust_vals = [r for _, _, r, _ in RESULTS]
    nacl_vals = [s for _, _, _, s in RESULTS]
    y = list(range(n))[::-1]

    fig, ax = plt.subplots(figsize=(11, 0.55 * n + 2.5))
    h = 0.38
    ax.barh([v + h / 2 for v in y], rust_vals, height=h, color="#dea584",
            label="crypto_core (Rust)")
    ax.barh([v - h / 2 for v in y], nacl_vals, height=h, color="#3776ab",
            label="PyNaCl (libsodium)")
    for yi, rv, nv in zip(y, rust_vals, nacl_vals):
        ax.text(rv * 1.12, yi + h / 2, fmt_us(rv), va="center", fontsize=8, color="#8a5a2b")
        ax.text(nv * 1.12, yi - h / 2, fmt_us(nv), va="center", fontsize=8, color="#28517a")

    ax.set_xscale("log")
    ax.set_xlim(0.2, max(max(rust_vals), max(nacl_vals)) * 12)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=9)
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: f"{v/1000:g} ms" if v >= 1000 else f"{v:g} us"))
    ax.set_xlabel("time per operation (lower is better, log scale)")
    ax.set_title("crypto_core (Rust) vs PyNaCl (libsodium)", fontsize=13, fontweight="bold")
    ax.grid(axis="x", which="both", alpha=0.25)
    ax.legend(loc="lower right")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    fig.show()
    plt.close(fig)


def open_image(path):
    if sys.platform == "win32":
        os.startfile(path)  
    elif sys.platform == "darwin":
        subprocess.run(["open", path])
    else:
        subprocess.run(["xdg-open", path])

def main():
    quick = "--quick" in sys.argv
    print(bold("Benchmark: crypto_core (Rust) vs PyNaCl (libsodium)"))
    print(dim(f"Python {sys.version.split()[0]}  PyNaCl {nacl.__version__}  "
              f"crypto_core {getattr(cc, '__version__', '0.1.0')}"))

    cross_check()
    run_benchmarks(quick)


    rust_wins = sum(1 for _, _, r, s in RESULTS if r < s)
    total = len(RESULTS)
    print()
    print(bold(f"Final score: Rust {rust_wins} - {total - rust_wins} PyNaCl  (of {total} benchmarks)"))
    for cat, label, r, s in RESULTS:
        if r < s:
            print(f"  {rust('Rust'):<7} {speedup(r, s):>7}  {label}")
        else:
            print(f"  {sodium('PyNaCl'):<7} {speedup(s, r):>7}  {label}")

    chart = os.path.join(HERE, "results_chart.png")
    try:
        make_chart(chart)
        print(f"\nChart saved: {os.path.relpath(chart, ROOT)}")
        open_image(chart)
    except Exception as e:
        print(yellow(f"Chart not generated: {e}"))


def speedup(winner_us, loser_us):
    return f"{loser_us / winner_us:.1f}x"


if __name__ == "__main__":
    main()
