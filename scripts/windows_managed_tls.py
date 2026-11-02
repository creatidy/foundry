"""Bounded Docker Desktop TLS volume primitive; not wired into first-run yet.

The Docker daemon, its administrators, and the independently verified image
are trusted. No private key bytes leave the volume or the helper containers.
"""

import json
import re
import secrets
import subprocess


_LABEL = "com.creatidy.foundry.tls"
_INIT = r'''
import json, os, stat, subprocess, sys
p, image, nonce = sys.argv[1:]
root = '/tls'
s = os.lstat(root)
if not stat.S_ISDIR(s.st_mode) or (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) != (0, 0, 0o755) or os.listdir(root):
    sys.exit(2)
os.umask(0o077)
result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-noenc',
    '-keyout', root+'/server.key', '-out', root+'/server.crt', '-days', '365',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
    '-addext', 'basicConstraints=critical,CA:FALSE'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
if result.returncode:
    sys.exit(3)
for name in ('server.key', 'server.crt'):
    path = root+'/'+name
    s = os.lstat(path)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != 0:
        sys.exit(4)
    os.chown(path, 0, 10001, follow_symlinks=False)
    os.chmod(path, 0o440, follow_symlinks=False)
marker = json.dumps({'project':p, 'image':image, 'nonce':nonce}, sort_keys=True).encode('ascii')
fd = os.open(root+'/identity.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o440)
with os.fdopen(fd, 'wb') as f:
    f.write(marker)
    f.flush()
    os.fsync(f.fileno())
os.chown(root+'/identity.json', 0, 10001, follow_symlinks=False)
os.chmod(root+'/identity.json', 0o440, follow_symlinks=False)
os.chown(root, 0, 10001, follow_symlinks=False)
os.chmod(root, 0o750, follow_symlinks=False)
'''

_VERIFY = r'''
import json, os, stat, subprocess, sys
root = '/tls'
s = os.lstat(root)
if not stat.S_ISDIR(s.st_mode) or (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)) != (0,10001,0o750):
    sys.exit(2)
if set(os.listdir(root)) != {'server.key','server.crt','identity.json'}:
    sys.exit(3)
for name in ('server.key','server.crt','identity.json'):
    s = os.lstat(root+'/'+name)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)) != (0,10001,0o440):
        sys.exit(4)
with open(root+'/identity.json', encoding='ascii') as f:
    marker = json.load(f)
with open(root+'/server.crt', encoding='ascii') as f:
    cert = f.read(1048577)
if len(cert) > 1048576 or cert.count('-----BEGIN CERTIFICATE-----') != 1:
    sys.exit(5)
def openssl(*args):
    return subprocess.run(['openssl', *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
if openssl('x509','-in',root+'/server.crt','-pubkey','-noout') != openssl('pkey','-in',root+'/server.key','-pubout'):
    sys.exit(6)
openssl('verify','-CAfile',root+'/server.crt','-verify_ip','127.0.0.1','-purpose','sslserver',root+'/server.crt')
print(json.dumps({'identity':marker, 'certificate':cert}))
'''


class ManagedTlsError(RuntimeError):
    """The named resource must be inspected manually; it was not removed."""


def _run(args, *, quiet=False):
    return subprocess.run(args, check=True, text=True, timeout=120,
                          stdout=subprocess.DEVNULL if quiet else subprocess.PIPE,
                          stderr=subprocess.DEVNULL).stdout


def _check_input(project, image, name, nonce):
    if (not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project) or
            not re.fullmatch(r"sha256:[a-f0-9]{64}", image) or
            not re.fullmatch(r"[a-f0-9]{32}", nonce) or name != "foundry-tls-" + nonce):
        raise ValueError("invalid managed TLS identity")


def _inspect(project, image, name, nonce, allowed_consumer=None):
    _check_input(project, image, name, nonce)
    volumes = json.loads(_run(["docker", "volume", "inspect", name]))
    labels = {_LABEL: "1", _LABEL + ".project": project, _LABEL + ".image": image,
              _LABEL + ".nonce": nonce}
    if (len(volumes) != 1 or volumes[0]["Name"] != name or volumes[0]["Driver"] != "local" or
            volumes[0].get("Options") not in (None, {}) or volumes[0].get("Labels") != labels):
        raise ValueError("managed TLS volume identity mismatch")
    consumers = _run(["docker", "container", "ls", "--all", "--filter", "volume=" + name, "--quiet"]).splitlines()
    if consumers and (allowed_consumer is None or len(consumers) != 1 or
                      not allowed_consumer.startswith(consumers[0])):
        raise ValueError("managed TLS volume has existing consumers")


def _container(image, name, *, writable):
    mount = "type=volume,src=" + name + ",dst=/tls,volume-nocopy"
    if not writable:
        mount += ",readonly"
    args = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--pids-limit", "64", "--tmpfs", "/data:rw,noexec,nosuid,size=1m",
            "--mount", mount, "--user", "0:0" if writable else "10001:10001", "--entrypoint", "python"]
    if writable:
        args += ["--cap-add", "CHOWN"]
    return args + [image, "-c", _INIT if writable else _VERIFY]


def verify_tls_volume(project, image, name, nonce, allowed_consumer=None):
    """Return only the public certificate after strict identity and custody checks."""
    _inspect(project, image, name, nonce, allowed_consumer)
    data = json.loads(_run(_container(image, name, writable=False)))
    if data.get("identity") != {"project": project, "image": image, "nonce": nonce}:
        raise ValueError("managed TLS marker mismatch")
    cert = data.get("certificate")
    if not isinstance(cert, str) or len(cert) > 1048576 or cert.count("-----BEGIN CERTIFICATE-----") != 1:
        raise ValueError("invalid managed TLS certificate")
    return cert


def initialize_tls_volume(project, image):
    """Create and initialize one uniquely named volume; never remove on failure.

    The caller must have established the local Docker Desktop target and image
    provenance first. The returned name and nonce identify the owned volume.
    """
    nonce = secrets.token_hex(16)
    name = "foundry-tls-" + nonce
    _check_input(project, image, name, nonce)
    labels = {_LABEL: "1", _LABEL + ".project": project, _LABEL + ".image": image,
              _LABEL + ".nonce": nonce}
    try:
        existing = _run(["docker", "volume", "ls", "--quiet"]).splitlines()
        if name in existing:
            raise ValueError("generated TLS volume name already exists")
        args = ["docker", "volume", "create", "--driver", "local"]
        for key, value in labels.items():
            args += ["--label", key + "=" + value]
        if _run(args + [name]).strip() != name:
            raise ValueError("unexpected created volume name")
        _inspect(project, image, name, nonce)
        _run(_container(image, name, writable=True) + [project, image, nonce], quiet=True)
        cert = verify_tls_volume(project, image, name, nonce)
        return name, nonce, cert
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        raise ManagedTlsError("Managed TLS initialization failed; inspect volume " + name + " before manual cleanup") from exc
