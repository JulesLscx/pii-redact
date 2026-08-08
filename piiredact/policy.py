"""Which tools may receive real values back, and which must not.

Restoring tokens inside tool arguments is what preserves functionality: the
model reasons over ``[EMAIL_0001]``, the ``write_file`` call that follows lands
the *real* address on disk. But the same mechanism pointed at a search engine
would hand the real address to a third party — a worse outcome than the one
this plugin exists to prevent.

So restoration is scoped by destination:

* **local tools** (files, shell, local search, notes) — restored, because the
  data never leaves the machine and the user is asking for real work on real
  data;
* **egress tools** (web search, fetch, browser, third-party APIs) — never
  restored; they run on tokens, which is usually what you want anyway
  (searching for ``[PERSON_0003]`` is meaningless, so the agent learns to
  search for the generic part of the question instead).

Both lists are name-pattern based rather than host-specific, so the same policy
applies whether the host calls it ``web_search`` (Hermes), ``WebSearch``
(Claude Code) or ``browser.navigate`` (OpenCode).
"""

from __future__ import annotations

import re
from typing import FrozenSet, Iterable, Pattern, Tuple

#: Substrings that mark a tool as sending data off the machine. Matched
#: case-insensitively against the tool name with underscores/dots/dashes
#: normalised away, so ``web_search``/``WebSearch``/``web.search`` all hit.
EGRESS_MARKERS: Tuple[str, ...] = (
    "websearch",
    "webfetch",
    "webread",
    "fetchurl",
    "httprequest",
    "httpget",
    "httppost",
    "browser",
    "playwright",
    "puppeteer",
    "firecrawl",
    "browserbase",
    "curl",
    "search_web",
    "googlesearch",
    "ddgs",
    "duckduckgo",
    "brave",
    "tavily",
    "exa",
    "perplexity",
    "upload",
    "publish",
    "webhook",
    "slack",
    "discord",
    "telegram",
    "twitter",
    "linkedin",
    "notion",
    "jira",
    "github",
    "gitlab",
)

#: Tools that are explicitly *local* even though their name looks like egress
#: (e.g. a local HTTP call to 127.0.0.1 is out of scope here, but a local
#: git command is not egress at all).
LOCAL_OVERRIDES: Tuple[str, ...] = (
    "git_status",
    "git_diff",
    "git_log",
)

_NORMALISE_RE: Pattern[str] = re.compile(r"[^a-z0-9]+")


def normalise_tool_name(name: str) -> str:
    """Lowercase and strip separators so naming styles compare equal."""
    return _NORMALISE_RE.sub("", (name or "").lower())


def is_egress_tool(
    name: str,
    extra_egress: Iterable[str] = (),
    forced_local: Iterable[str] = (),
) -> bool:
    """True when *name* looks like it sends data to a third party."""
    normalised = normalise_tool_name(name)
    if not normalised:
        return False
    for allow in forced_local:
        if normalise_tool_name(allow) == normalised:
            return False
    for allow in LOCAL_OVERRIDES:
        if normalise_tool_name(allow) == normalised:
            return False
    for marker in tuple(EGRESS_MARKERS) + tuple(extra_egress):
        marker_key = normalise_tool_name(marker)
        if marker_key and marker_key in normalised:
            return True
    return False


def should_restore_args(
    name: str,
    egress_extra: FrozenSet[str] = frozenset(),
    local_extra: FrozenSet[str] = frozenset(),
) -> bool:
    """True when a tool's arguments may be de-pseudonymised before it runs."""
    return not is_egress_tool(name, egress_extra, local_extra)


#: Argument names that must never be rewritten: they are correlation ids and
#: control fields, and a rule matching five digits inside one would silently
#: break the host's tool-call bookkeeping.
PROTECTED_ARG_KEYS: FrozenSet[str] = frozenset(
    {
        "tool_call_id",
        "tool_use_id",
        "call_id",
        "id",
        "session_id",
        "task_id",
        "turn_id",
        "api_request_id",
        "request_id",
        "message_id",
        "thread_id",
        "run_id",
        "type",
        "role",
        "name",
        "model",
    }
)
