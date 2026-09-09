"""An interactive session for working through a firmware image.

The command line answers one question per invocation. Working out an awkward
dump is not one question: it is opening the file, seeing what the format
detector made of it, trying a part number, looking at what the base recovery
weighed, changing your mind, and looking again. Doing that as a series of
shell invocations re-reads and re-analyses the image every time.

This keeps the image and its analysis in memory, so overriding something and
looking again is immediate. Everything it does is available as flags too, and
``info`` prints the equivalent command line, so a session is a way of arriving
at an invocation rather than a replacement for one.
"""

from __future__ import annotations

import cmd
import os
import shlex
import sys
import traceback
from pathlib import Path
from typing import Any, Optional, TextIO

from . import __version__
from . import input as ingest
from .arch.registry import backend_names, describe, probe_all
from .core.hypothesis import RecoveryRefused
from .core.options import OptionError, Options
from .core.reference import Access, ReferenceKind
from .report import console, interactive, manifest

#: Settings ``set`` understands, with how to read their values.
SETTINGS: dict[str, str] = {
    "base": "runtime load address (hex or decimal)",
    "entry": "entry point address",
    "vector-offset": "file offset of the entry structure",
    "image": "which candidate program to reconstruct",
    "arch": f"architecture backend: auto, {', '.join(backend_names())}",
    "mcu": "part number, as much of it as you can read",
    "svd": "an SVD file or directory to match against",
    "svd-symbols": "none, peripherals or registers",
    "minimum-confidence": "refuse below this confidence, 0..1",
    "input-format": f"force a parser: {', '.join(ingest.format_names())}",
    "split-sections": "on or off",
    "keep-padding": "on or off",
}

#: Topics that need no analysis, and so never ask anything.
LIGHT_TOPICS = ("images",)

#: Topics ``show`` understands.
TOPICS = (
    "summary",
    "base",
    "entry",
    "images",
    "regions",
    "startup",
    "mmio",
    "references",
    "symbols",
    "mcu",
    "sections",
    "evidence",
    "passes",
    "warnings",
)


class Palette:
    """Minimal styling, disabled where it would be noise."""

    def __init__(self, stream: TextIO) -> None:
        self.enabled = (
            hasattr(stream, "isatty")
            and stream.isatty()
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM", "") != "dumb"
        )

    def _wrap(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def heading(self, text: str) -> str:
        return self._wrap(text, "1")

    def dim(self, text: str) -> str:
        return self._wrap(text, "2")

    def good(self, text: str) -> str:
        return self._wrap(text, "32")

    def bad(self, text: str) -> str:
        return self._wrap(text, "31")

    def note(self, text: str) -> str:
        return self._wrap(text, "36")


class Shell(cmd.Cmd):
    """The interactive session."""

    def __init__(
        self,
        options: Optional[Options] = None,
        stream: Optional[TextIO] = None,
        stdin: Optional[TextIO] = None,
    ) -> None:
        super().__init__(stdin=stdin or sys.stdin)
        self.stream = stream if stream is not None else sys.stdout
        self.paint = Palette(self.stream)
        self.options = options or Options()
        self.options.fetch_svd = True
        self.path: Optional[Path] = None
        self.image = None
        self.reconstruction = None
        #: Set when an override invalidates the analysis in hand.
        self.stale = False
        self.use_rawinput = stdin is None
        self.prompt = self.paint.dim("raw2elf> ")

    # -- plumbing ---------------------------------------------------------

    def say(self, message: str = "") -> None:
        print(message, file=self.stream)

    def fail(self, message: str) -> None:
        self.say(self.paint.bad(f"error: {message}"))

    def emptyline(self) -> bool:
        return False

    def default(self, line: str) -> None:
        # A topic name on its own reads like a command, so treat it as one:
        # "images" is what someone types, not "show images".
        word, _, rest = line.partition(" ")
        if word.lower() in TOPICS:
            return self.do_show(f"{word} {rest}".strip())
        self.fail(f"unknown command {word!r}; try 'help'")
        return None

    def onecmd(self, line: str) -> Any:
        """Never let one bad command end the session."""
        try:
            return super().onecmd(line)
        except (OptionError, ingest.ParseError, ValueError) as error:
            self.fail(str(error))
        except RecoveryRefused as error:
            self.say(console.refusal(error))
        except KeyboardInterrupt:
            self.say("(interrupted)")
        except Exception as error:  # noqa: BLE001 - a session outlives a bug
            self.fail(f"{type(error).__name__}: {error}")
            if self.options.verbose:
                traceback.print_exc(file=self.stream)
        return None

    # -- state ------------------------------------------------------------

    def _need_image(self) -> bool:
        if self.image is None:
            self.fail("nothing open; use 'open <file>'")
            return False
        return True

    def _analysis(self, quiet: bool = False):
        """The current analysis, running it if it is missing or stale."""
        if not self._need_image():
            return None
        if self.reconstruction is not None and not self.stale:
            return self.reconstruction
        if not quiet:
            self.say(self.paint.dim("analysing..."))
        from .reconstruct import reconstruct

        session = interactive.TerminalSession(stream=self.stream)
        options = _copy_options(self.options)
        options.interaction = session
        self.reconstruction = reconstruct(self.image, options)
        self.stale = False
        return self.reconstruction

    # -- commands ---------------------------------------------------------

    def do_open(self, arg: str) -> None:
        """open <file> -- read a firmware dump and detect its format."""
        parts = shlex.split(arg)
        if len(parts) != 1:
            self.fail("usage: open <file>")
            return
        path = Path(parts[0]).expanduser()
        if not path.is_file():
            self.fail(f"{path} is not a file")
            return
        self.image = ingest.load(path, input_format=self.options.input_format)
        self.path = path
        self.reconstruction = None
        self.stale = False
        label = self.image.metadata.get("label", self.image.source_format)
        self.say(
            f"{self.paint.good(path.name)}  {label}, "
            f"{_size(self.image.size)} in {len(self.image.segments)} segment(s)"
        )
        for note in self.image.metadata.get("notes", []):
            self.say(self.paint.dim(f"  note: {note}"))

    def do_info(self, arg: str) -> None:
        """info -- what is open, what is set, and the equivalent command."""
        if self.path is None:
            self.say("nothing open")
        else:
            self.say(f"{self.paint.heading('file')}     {self.path}")
            self.say(
                f"{self.paint.heading('input')}    "
                f"{self.image.metadata.get('label', self.image.source_format)}, "
                f"{_size(self.image.size)}"
            )
        overrides = _overrides(self.options)
        self.say(self.paint.heading("settings") + ("" if overrides else "  (none set)"))
        for name, value in overrides.items():
            self.say(f"  {name:<20} {value}")
        state = (
            "not analysed"
            if self.reconstruction is None
            else ("stale, will re-run" if self.stale else "current")
        )
        self.say(f"{self.paint.heading('analysis')} {state}")
        if self.path is not None:
            self.say()
            self.say(self.paint.dim("equivalent command:"))
            self.say(f"  {self._command_line()}")

    def do_set(self, arg: str) -> None:
        """set <setting> <value> -- override something. 'set' alone lists them."""
        parts = shlex.split(arg)
        if not parts:
            for name, help_text in SETTINGS.items():
                current = _overrides(self.options).get(name, "")
                marker = self.paint.good(current) if current else self.paint.dim("unset")
                self.say(f"  {name:<20} {marker:<28} {self.paint.dim(help_text)}")
            return
        if len(parts) < 2:
            self.fail(f"usage: set {parts[0]} <value>")
            return
        _apply(self.options, parts[0], " ".join(parts[1:]))
        self.stale = True
        self.say(f"  {parts[0]} = {' '.join(parts[1:])}")

    def complete_set(self, text, line, begin, end):
        return [name for name in SETTINGS if name.startswith(text)]

    def do_unset(self, arg: str) -> None:
        """unset <setting> -- go back to inferring it. 'unset all' clears everything."""
        name = arg.strip()
        if name == "all":
            fresh = Options()
            for field in ("base", "entry", "vector_offset", "image", "mcu", "svd", "arch",
                          "input_format", "split_sections"):
                setattr(self.options, field, getattr(fresh, field))
            self.options.minimum_confidence = fresh.minimum_confidence
            self.stale = True
            self.say("  all settings cleared")
            return
        if name not in SETTINGS:
            self.fail(f"unknown setting {name!r}; 'set' lists them")
            return
        _apply(self.options, name, None)
        self.stale = True
        self.say(f"  {name} cleared")

    def complete_unset(self, text, line, begin, end):
        return [name for name in (*SETTINGS, "all") if name.startswith(text)]

    def do_detect(self, arg: str) -> None:
        """detect -- what each input parser made of the file."""
        if not self._need_image():
            return
        raw = self.path.read_bytes()
        for detection in ingest.detect(raw):
            mark = self.paint.good("<-") if detection.parser.name == self.image.source_format else "  "
            self.say(
                f"  {detection.parser.name:<12} {detection.sniff.confidence:.2f} {mark}  "
                f"{self.paint.dim(detection.sniff.detail)}"
            )

    def do_probe(self, arg: str) -> None:
        """probe -- how each architecture backend scores the image."""
        if not self._need_image():
            return
        for result in probe_all(self.image):
            self.say(f"  {result.backend:<20} {result.confidence:.2f}")
            for item in result.evidence[:6]:
                self.say(f"       {_evidence(self.paint, item)}")

    def do_arch(self, arg: str) -> None:
        """arch -- list the architecture backends."""
        for name, description in describe():
            self.say(f"  {name:<20} {description}")

    def do_run(self, arg: str) -> None:
        """run -- analyse the image now, asking if anything cannot be decided."""
        self.stale = True
        if self._analysis() is not None:
            self.say()
            self.do_show("summary")

    do_analyse = do_run

    def do_show(self, arg: str) -> None:
        """show <topic> -- see part of the analysis. 'show' alone lists topics."""
        topic = (arg.strip() or "summary").lower()
        if topic in ("topics", "?"):
            self.say("  " + "  ".join(TOPICS))
            return
        if topic not in TOPICS:
            self.fail(f"unknown topic {topic!r}; try: {', '.join(TOPICS)}")
            return
        if topic in LIGHT_TOPICS:
            # A look, not a decision: these come from a partial pipeline with
            # nothing to ask about, so glancing at the programs in a dump
            # never triggers an analysis or a prompt.
            getattr(self, f"_show_{topic}")(None)
            return
        result = self._analysis()
        if result is None:
            return
        getattr(self, f"_show_{topic}")(result)

    def complete_show(self, text, line, begin, end):
        return [name for name in TOPICS if name.startswith(text)]

    def do_why(self, arg: str) -> None:
        """why [word] -- the evidence behind a conclusion.

        'why base' lists the candidate load addresses with what supported and
        contradicted each. Any other word searches the evidence log for it,
        which is how to ask about whatever the architecture in play happens
        to call things.
        """
        subject = arg.strip().lower()
        result = self._analysis()
        if result is None:
            return
        if subject in ("", "base"):
            listing = console.base_candidates(result)
            self.say(listing or "  nothing to weigh")
            return
        matches = [
            item
            for item in result.context.evidence
            if subject in item.kind.lower() or subject in item.explanation.lower()
        ]
        if not matches:
            self.say(self.paint.dim(f"  no evidence mentions {subject!r}"))
            return
        for item in matches:
            self.say(f"  {_evidence(self.paint, item)}")

    def complete_why(self, text, line, begin, end):
        """Complete from the words the evidence actually used this run."""
        words = {"base"}
        if self.reconstruction is not None:
            words |= {item.kind.lower() for item in self.reconstruction.context.evidence}
        return sorted(word for word in words if word.startswith(text))

    def do_write(self, arg: str) -> None:
        """write [file] -- write the ELF, and the manifest beside it."""
        result = self._analysis()
        if result is None:
            return
        if not result.elf:
            self.fail("no ELF was produced")
            return
        target = Path(shlex.split(arg)[0]) if arg.strip() else self.path.with_suffix(".elf")
        target.write_bytes(result.elf)
        self.say(f"  {self.paint.good(str(target))}  {len(result.elf)} bytes")
        report = target.with_suffix("").with_suffix(".raw2elf.json")
        report.write_text(manifest.dumps(result) + "\n")
        self.say(f"  {self.paint.good(str(report))}")

    def completenames(self, text, *ignored):
        """Complete commands and bare topic names alike."""
        commands = {name[3:] for name in self.get_names() if name.startswith("do_")}
        return sorted(word for word in commands | set(TOPICS) if word.startswith(text))

    def do_quit(self, arg: str) -> bool:
        """quit -- leave."""
        return True

    do_exit = do_quit

    def do_EOF(self, arg: str) -> bool:
        self.say()
        return True

    # -- show topics ------------------------------------------------------

    def _show_summary(self, result) -> None:
        self.say(console.summary(result))

    def _show_base(self, result) -> None:
        base = result.context.get("runtime_base")
        confidence = result.context.get("base_confidence") or 0.0
        self.say(f"  base       0x{base:08x}   confidence {confidence:.2f}")
        self.say(self.paint.dim("  'why base' shows what was weighed"))

    def _show_entry(self, result) -> None:
        entry = result.context.get("entry")
        if entry is None:
            self.say("  no entry point recovered")
            return
        encoded = result.backend.encode_code_pointer(entry)
        self.say(f"  entry      0x{entry:08x}" + (f"   (ELF e_entry 0x{encoded:08x})" if encoded != entry else ""))
        for label, value in result.backend.report_rows(result.context):
            self.say(f"  {label.lower():<10} {value}")

    def _show_images(self, result) -> None:
        candidates, backend = self._candidate_images()
        self.say(console.images(candidates, backend))

    def _candidate_images(self):
        """The programs in the dump, without committing to an analysis."""
        if self.reconstruction is not None and not self.stale:
            context = self.reconstruction.context
            return context.get("candidate_images") or [], self.reconstruction.backend.name

        from .analysis.carving import ImageDiscovery, PaddingDetection
        from .core.pipeline import AnalysisContext, Pipeline
        from .reconstruct import select_backend

        options = _copy_options(self.options)
        options.interaction = None  # looking, not choosing
        backend, _confidence, _probes = select_backend(self.image, options)
        context = AnalysisContext(image=self.image, backend=backend, options=options)
        Pipeline([PaddingDetection(), ImageDiscovery()]).run(context)
        return context.get("candidate_images") or [], backend.name

    def _show_regions(self, result) -> None:
        memory = result.context.get("memory_map")
        for region in memory or []:
            self.say(
                f"  {region.kind.value:<6} 0x{region.start:08x}-0x{region.end:08x}  "
                f"{_size(region.size):>8}  {region.name}"
            )

    def _show_startup(self, result) -> None:
        state = result.context.get("startup_state")
        if state is None or not state.initializations:
            self.say("  nothing recovered")
            return
        for item in state.initializations:
            size = item.resolved_size or 0
            where = f"0x{item.source:08x} -> " if item.source is not None else ""
            self.say(f"  {item.kind.value:<5} {where}0x{item.destination:08x}  {_size(size)}")

    def _show_mmio(self, result) -> None:
        for reference in (result.context.get("mmio_accesses") or [])[:200]:
            self.say(
                f"  0x{reference.value:08x}  {reference.access.value:<5} "
                f"{str(reference.width or ''):>3}  {self.paint.dim(reference.source_text)}"
            )

    def _show_references(self, result) -> None:
        references = result.context.get("references")
        for kind, count in sorted((references.counts_by_kind() if references else {}).items()):
            self.say(f"  {kind:<12} {count}")

    def _show_symbols(self, result) -> None:
        symbols = result.context.get("symbols")
        for symbol in (symbols.named() if symbols else []):
            self.say(f"  0x{symbol.value:08x}  {symbol.name:<28} {self.paint.dim(symbol.origin)}")

    def _show_mcu(self, result) -> None:
        mcu = result.context.get("mcu")
        if mcu is None:
            self.say("  not identified")
            return
        self.say(f"  {mcu['label']}   confidence {mcu['match'].confidence:.2f}")
        for candidate in (result.context.get("mcu_candidates") or [])[1:6]:
            self.say(self.paint.dim(f"    also {candidate.device.name} ({candidate.confidence:.2f})"))

    def _show_sections(self, result) -> None:
        for section in result.context.get("elf_sections") or []:
            self.say(f"  {section['name']:<12} {section['address']}  {section['size']:>8} bytes")

    def _show_evidence(self, result) -> None:
        for item in result.context.evidence:
            self.say(f"  {_evidence(self.paint, item)}")

    def _show_passes(self, result) -> None:
        for outcome in result.result.outcomes:
            colour = {"ok": self.paint.good, "skipped": self.paint.dim}.get(
                outcome.status, self.paint.bad
            )
            detail = f"  {outcome.detail}" if outcome.detail else ""
            self.say(f"  {outcome.name:<22} {colour(outcome.status)}{self.paint.dim(detail)}")

    def _show_warnings(self, result) -> None:
        for warning in result.context.warnings or ["none"]:
            self.say(f"  {warning}")

    # -- helpers ----------------------------------------------------------

    def _command_line(self) -> str:
        parts = ["raw2elf", str(self.path)]
        for name, value in _overrides(self.options).items():
            parts.append(f"--{name}" if value == "on" else f"--{name} {value}")
        return " ".join(parts)


def _apply(options: Options, name: str, value: Optional[str]) -> None:
    """Set or clear one setting, by the name the shell uses for it."""
    field = name.replace("-", "_")
    if value is None:
        setattr(options, field, None if field != "minimum_confidence" else 0.5)
        if field in ("split_sections",):
            options.split_sections = False
        return
    if field in ("base", "entry", "vector_offset"):
        setattr(options, field, int(value, 0))
    elif field == "image":
        options.image = int(value, 0)
    elif field == "minimum_confidence":
        number = float(value)
        if not 0.0 <= number <= 1.0:
            raise ValueError("minimum-confidence must be between 0 and 1")
        options.minimum_confidence = number
    elif field == "svd_symbols":
        if value not in ("none", "peripherals", "registers"):
            raise ValueError("svd-symbols must be none, peripherals or registers")
        options.svd_symbols = value
    elif field == "input_format":
        if value not in ingest.format_names():
            raise ValueError(f"input-format must be one of {', '.join(ingest.format_names())}")
        options.input_format = value
    elif field in ("split_sections",):
        options.split_sections = value in ("on", "yes", "true", "1")
    elif field == "keep_padding":
        options.extra["trim_padding"] = value not in ("on", "yes", "true", "1")
    elif field in ("arch", "mcu", "svd"):
        setattr(options, field, value)
    else:  # pragma: no cover - SETTINGS and this stay in step
        raise ValueError(f"unknown setting {name!r}")


def _overrides(options: Options) -> dict[str, str]:
    """The settings that differ from what the tool would do on its own."""
    found: dict[str, str] = {}
    for name, field in (
        ("base", "base"),
        ("entry", "entry"),
        ("vector-offset", "vector_offset"),
        ("image", "image"),
        ("mcu", "mcu"),
        ("svd", "svd"),
        ("input-format", "input_format"),
    ):
        value = getattr(options, field)
        if value is None:
            continue
        found[name] = f"0x{value:x}" if isinstance(value, int) and name != "image" else str(value)
    if options.arch != "auto":
        found["arch"] = options.arch
    if options.svd_symbols != "peripherals":
        found["svd-symbols"] = options.svd_symbols
    if options.minimum_confidence != 0.5:
        found["minimum-confidence"] = f"{options.minimum_confidence:g}"
    if options.split_sections:
        found["split-sections"] = "on"
    if options.extra.get("trim_padding") is False:
        found["keep-padding"] = "on"
    return found


def _copy_options(options: Options) -> Options:
    from dataclasses import replace

    copied = replace(options)
    copied.extra = dict(options.extra)
    return copied


def _evidence(paint: Palette, item) -> str:
    text = str(item)
    return paint.good(text) if item.supports else paint.bad(text)


def _size(count: int) -> str:
    from .core.util import human_size

    return human_size(count)


BANNER = """raw2elf {version} -- interactive session

  open <file>     read a firmware dump        show <topic>   see the analysis
  set <k> <v>     override something          why base       what was weighed
  probe / images  look before analysing       write [file]   emit the ELF

'help' lists everything, 'help <command>' explains one. Ctrl-D to leave.
"""


def run(argv: Optional[list[str]] = None, options: Optional[Options] = None) -> int:
    """Start a session. Returns a process exit code."""
    shell = Shell(options=options)
    shell.say(shell.paint.heading(BANNER.format(version=__version__)))
    if argv:
        shell.onecmd(f"open {shlex.quote(argv[0])}")
    try:
        shell.cmdloop(intro="")
    except KeyboardInterrupt:
        shell.say()
    return 0
