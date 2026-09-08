"""Where CMSIS-SVD files come from.

Two sources: a directory an analyst already has, and the upstream database,
fetched on demand. Reading is expressed as "list locators, read one" so the
matcher does not care which it got.

The upstream clone deliberately has no working tree. Checked out, that
database is about six gigabytes of XML; the packed objects are twenty-four
megabytes, and every file can be read straight out of them. Silently filling
a home directory with six gigabytes to answer an optional question would not
be a reasonable thing to do to somebody.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

#: The upstream database.
UPSTREAM = "https://github.com/cmsis-svd/cmsis-svd-data.git"
#: Environment variable naming a directory to use instead of fetching.
SVD_DIR_ENVIRONMENT = "RAW2ELF_SVD_DIR"
#: Directory names to look for while walking up from the working directory.
_REPO_HINTS = ("cmsis-svd-data/data", "third_party/cmsis-svd-data/data", "svd")
#: How long to wait for the fetch before giving up on it.
FETCH_TIMEOUT = 600
#: Read requests sent to git at a time. Small enough that a chunk fits a pipe
#: buffer, so writing it can never block on replies nobody is reading yet.
REQUEST_CHUNK = 256


@dataclass(frozen=True)
class SvdEntry:
    """One SVD file, wherever it lives."""

    locator: str
    vendor: str
    name: str


class SvdSource:
    """A collection of SVD files that can be listed and read."""

    #: Stable identity, used to key the parsed index cache.
    identity: str = ""
    #: How to describe this source to a person.
    description: str = ""

    def entries(self) -> list[SvdEntry]:
        raise NotImplementedError

    def read(self, locator: str) -> Optional[str]:
        raise NotImplementedError

    def signature(self) -> str:
        """Changes when the underlying content changes."""
        return self.identity


class DirectorySource(SvdSource):
    """SVD files in a directory tree the analyst already has."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.identity = f"dir:{self.root.resolve()}"
        self.description = str(self.root)

    def entries(self) -> list[SvdEntry]:
        return [
            SvdEntry(locator=str(path), vendor=path.parent.name, name=path.stem)
            for path in sorted(self.root.rglob("*.svd"))
        ]

    def read(self, locator: str) -> Optional[str]:
        try:
            return Path(locator).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def signature(self) -> str:
        files = sorted(self.root.rglob("*.svd"))
        newest = max((path.stat().st_mtime_ns for path in files), default=0)
        return f"{self.identity}:{len(files)}:{newest}"


class GitSource(SvdSource):
    """The upstream database, cloned without a working tree.

    Files are read out of the packed objects, so the cache stays small.  A
    single long-lived ``git cat-file --batch`` would be faster still, but one
    process per read keeps this simple and the index is built once.
    """

    def __init__(self, cache: Path, revision: str = "HEAD") -> None:
        self.cache = Path(cache)
        self.revision = revision
        self.identity = f"git:{UPSTREAM}"
        self.description = f"{UPSTREAM} (cached in {self.cache})"
        self._head: Optional[str] = None

    # -- fetching ---------------------------------------------------------

    @property
    def present(self) -> bool:
        return (self.cache / "HEAD").is_file() or (self.cache / ".git").exists()

    def fetch(self, log=None) -> bool:
        """Clone the database if it is not already cached."""
        if self.present:
            return True
        if not _have_git():
            if log:
                log("git is not available, so the CMSIS-SVD database cannot be fetched")
            return False
        self.cache.parent.mkdir(parents=True, exist_ok=True)
        if log:
            log(f"fetching the CMSIS-SVD database from {UPSTREAM} (first run only)")
        staging = self.cache.with_name(self.cache.name + ".partial")
        _remove(staging)
        try:
            subprocess.run(
                [
                    "git", "clone",
                    "--depth", "1",
                    "--no-checkout",
                    "--quiet",
                    UPSTREAM,
                    str(staging),
                ],
                check=True,
                capture_output=True,
                timeout=FETCH_TIMEOUT,
                env=dict(os.environ, GIT_TERMINAL_PROMPT="0"),
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
            _remove(staging)
            if log:
                log(f"could not fetch the CMSIS-SVD database: {_reason(error)}")
            return False
        # Move into place only once complete, so an interrupted fetch does
        # not leave a half-database that later runs would trust.
        staging.replace(self.cache)
        return True

    # -- reading ----------------------------------------------------------

    def _git(self, *arguments: str, text: bool = True):
        return subprocess.run(
            ["git", "-C", str(self.cache), *arguments],
            check=True,
            capture_output=True,
            text=text,
        )

    def head(self) -> str:
        if self._head is None:
            try:
                self._head = self._git("rev-parse", self.revision).stdout.strip()
            except (subprocess.CalledProcessError, OSError):
                self._head = ""
        return self._head

    def entries(self) -> list[SvdEntry]:
        try:
            listing = self._git("ls-tree", "-r", self.revision, "--name-only").stdout
        except (subprocess.CalledProcessError, OSError):
            return []
        found: list[SvdEntry] = []
        for line in listing.splitlines():
            if not line.endswith(".svd"):
                continue
            parts = line.split("/")
            found.append(
                SvdEntry(
                    locator=line,
                    vendor=parts[-2] if len(parts) > 1 else "",
                    name=parts[-1][: -len(".svd")],
                )
            )
        return found

    def read(self, locator: str) -> Optional[str]:
        try:
            blob = self._git("cat-file", "blob", f"{self.revision}:{locator}", text=False).stdout
        except (subprocess.CalledProcessError, OSError):
            return None
        return blob.decode("utf-8", errors="replace")

    def read_all(self) -> Iterator[tuple[SvdEntry, str]]:
        """Stream every file through one ``git cat-file`` process.

        Spawning a process per file would dominate the cost of building the
        index; batching turns roughly two thousand reads into one.

        Requests go in fixed-size chunks, and each chunk's replies are drained
        before the next is sent. Writing every request up front deadlocks:
        the request outgrows the pipe buffer, so this side blocks writing
        while git blocks writing replies into a buffer nobody is reading.
        """
        found = self.entries()
        if not found:
            return
        try:
            process = subprocess.Popen(
                ["git", "-C", str(self.cache), "cat-file", "--batch"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            return
        assert process.stdin and process.stdout
        try:
            for start in range(0, len(found), REQUEST_CHUNK):
                chunk = found[start : start + REQUEST_CHUNK]
                process.stdin.write(
                    "".join(f"{self.revision}:{item.locator}\n" for item in chunk).encode()
                )
                process.stdin.flush()
                for entry in chunk:
                    header = process.stdout.readline()
                    if not header:
                        return
                    pieces = header.split()
                    if len(pieces) < 3:
                        continue  # "<name> missing"
                    payload = process.stdout.read(int(pieces[2]))
                    process.stdout.read(1)  # the newline after each blob
                    yield entry, payload.decode("utf-8", errors="replace")
        except (BrokenPipeError, OSError):
            return
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass
            process.stdout.close()
            process.wait()

    def signature(self) -> str:
        return f"{self.identity}:{self.head()}"


# -- discovery -------------------------------------------------------------


def default_cache_directory() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "raw2elf"


def local_source(explicit: Optional[str] = None) -> Optional[SvdSource]:
    """A directory of SVD files the analyst already has, if there is one."""
    if explicit:
        candidate = Path(explicit).expanduser()
        return DirectorySource(candidate) if candidate.is_dir() else None
    environment = os.environ.get(SVD_DIR_ENVIRONMENT)
    if environment and Path(environment).expanduser().is_dir():
        return DirectorySource(Path(environment).expanduser())
    for directory in [Path.cwd(), *Path.cwd().parents]:
        for hint in _REPO_HINTS:
            candidate = directory / hint
            if candidate.is_dir():
                return DirectorySource(candidate)
    try:
        import cmsis_svd  # noqa: PLC0415 - optional dependency probed lazily

        packaged = Path(cmsis_svd.__file__).parent / "data"
        if packaged.is_dir():
            return DirectorySource(packaged)
    except Exception:  # pragma: no cover - absence is the normal case
        pass
    home = Path.home() / ".cmsis-svd" / "data"
    return DirectorySource(home) if home.is_dir() else None


def open_source(
    explicit: Optional[str] = None, allow_fetch: bool = True, log=None
) -> Optional[SvdSource]:
    """Find SVD data, fetching the upstream database if nothing local exists."""
    local = local_source(explicit)
    if local is not None:
        return local
    if explicit or not allow_fetch:
        return None
    source = GitSource(default_cache_directory() / "cmsis-svd-data")
    return source if source.fetch(log=log) else None


def _have_git() -> bool:
    from shutil import which

    return which("git") is not None


def _remove(path: Path) -> None:
    from shutil import rmtree

    if path.exists():
        rmtree(path, ignore_errors=True)


def _reason(error: Exception) -> str:
    output = getattr(error, "stderr", None)
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    if output:
        return output.strip().splitlines()[-1]
    return str(error)
