# SPDX-FileCopyrightText: 2026 Ian Pilcher <arequipeno@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-or-later


"""Parse RFC 9110 ``WWW-Authenticate`` headers."""


import collections.abc
import dataclasses
import types
import typing


__version__ = "0.1.0"

__all__ = ("Challenge", "parse")


#===============================================================================
#
#   _ListPointer - Utility class for scanning sequences (strings or token list)
#
#===============================================================================

class _ListPointer[T, S=None]:
    """A "pointer" to a position (index) in list or other sequence.

    Sequence items are accessed with subscript notation.  If ``lp`` is a
    :class:`_ListPointer`, ``lp[0]`` returns the sequence item at the pointer's
    current position, ``lp[-1]`` returns the preceding sequence item, ``lp[2]``
    retrieves the sequence item two positions after the current position, etc.
    If the requested position is outside the current range of the sequence, the
    sentinel value is returned.

    Note:
        List pointers are not restricted to the valid range of the sequence.  A
        pointer can be created or moved to a position outside the sequence's
        range.  An in-range position can also become out-of-range (or vice
        versa) if the sequence is modified.

    Args:
        seq: The sequence.
        position: Index of the item to reference.  (Default ``0``.)
        sentinel: The value returned when the item at a position outside the
            current range of the sequence is accessed.  (Default ``None``.)
    """

    @typing.overload
    def __init__(
            self,
            seq: collections.abc.Sequence[T],
            position: int=0,
            *,
            sentinel: None=None
    ) -> None:
        ...

    @typing.overload
    def __init__(
            self,
            seq: collections.abc.Sequence[T],
            position: int=0,
            *,
            sentinel: S
    ) -> None:
        ...

    def __init__(
            self,
            seq: collections.abc.Sequence[T],
            position: int=0,
            *,
            sentinel: typing.Any=None
    ):
        self._seq: typing.Final = seq
        self._sentinel: typing.Final[S] = sentinel
        self._index = position

    def __getitem__(self, offset: int) -> T | S:
        """Get the item that is :arg:`offset` positions from this pointer's
        position.

        Args:
            offset: Offset from the pointer's position to the requested
                position.  A positive offset reprepresents a position later in
                the sequence; a negative offset represents an earlier position.

        Returns:
            The sequence item that is :arg:`offset` positions from the pointer's
            current position.  If the requested position is outside the current
            range of the underlying sequence, the sentinel value is returned.
        """
        i = self._index + offset
        if 0 <= i < len(self._seq):
            return self._seq[i]
        else:
            return self._sentinel

    def advance(self, steps: int) -> None:
        """Move the position of this pointer forward in the sequence.

        Args:
            steps: The number of positions by which to advance the pointer.
                (If negative, the pointer will be moved backwards.)

        Note:
            This may move the pointer outside the current range of the sequence.
        """
        self._index += steps

    def backup(self, steps: int) -> None:
        """Move the position of this pointer backwards in the sequence.

        Args:
            steps: the number of positions by which to move the pointer
                backwards.  (If negative, the pointer will be advanced.)

        Note:
            This may move the pointer outside the current range of the sequence.
        """
        self._index -= steps

    def __add__(self, other: int) -> types.NotImplementedType:
        return NotImplemented

    def __sub__(self, other: int) -> types.NotImplementedType:
        return NotImplemented

    def __iadd__(self, steps: int) -> typing.Self:
        """Move the position of this pointer forward in the sequence.

        Args:
            steps: The number of positions by which to advance the pointer.
                (If negative, the pointer will be moved backwards.)

        Note:
            This may move the pointer outside the current range of the sequence.
        """
        if not isinstance(steps, int):
            return NotImplemented
        self._index += steps
        return self

    def __isub__(self, steps: int) -> typing.Self:
        """Move the position of this pointer backwards in the sequence.

        Args:
            steps: the number of positions by which to move the pointer
                backwards.  (If negative, the pointer will be advanced.)

        Note:
            This may move the pointer outside the current range of the sequence.
        """
        if not isinstance(steps, int):
            return NotImplemented
        self._index -= steps
        return self

    @property
    def position(self) -> int:
        """The pointer's current position (index) within the sequence.

        This value may be outside the valid range of the sequence, including
        negative values.
        """
        return self._index

    @property
    def after(self) -> int:
        """The number of items in the sequence after the pointer's current
        position.

        If the current position of the pointer is past the end of the sequence,
        this value will be negative.  If its position is before the beginning of
        the sequence, this value will be greater than or equal to the length of
        the sequence.
        """
        return len(self._seq) - self._index - 1

    @property
    def before(self) -> int:
        """The number of items in the sequence before the pointer's current
        position.

        If the current position of the pointer is past the end of the sequence,
        this value will be greater than or equal to the length of the sequence.
        If its position is before the beginning of the sequence, this value will
        be negative.
        """
        return self._index

    @property
    def valid(self) -> bool:
        """Is the pointer's current position within the valid range of the
        sequence?
        """
        return 0 <= self._index < len(self._seq)

    class IterState[_T, _S=None](typing.NamedTuple):
        """Yielded by :meth:`enumerate` for each iteration step."""

        step: int
        """Current iteration step (starting at :meth:`enumerate`'s :arg:`start`
        value).
        """

        current: _T
        """The item in the sequence at the current pointer position."""

        ptr: _ListPointer[_T, _S]
        """The :class:`_ListPointer` controlling the iteration."""

    @classmethod
    @typing.overload
    def enumerate(
            cls,
            seq: collections.abc.Sequence[T],
            start: int=0,
            *,
            sentinel: None=None
    ) -> collections.abc.Iterator[IterState[T, None]]:
        ...

    @classmethod
    @typing.overload
    def enumerate(
            cls,
            seq: collections.abc.Sequence[T],
            start: int=0,
            *,
            sentinel: S
    ) -> collections.abc.Iterator[IterState[T, S]]:
        ...

    @classmethod
    def enumerate(
            cls,
            seq: collections.abc.Sequence[T],
            start: int=0,
            *,
            sentinel: typing.Any=None
    ) -> collections.abc.Iterator[IterState[T, typing.Any]]:
        """Iterate over a sequence with a :class:`_ListPointer`.

        The :class:`~_ListPointer.IterState` object yielded by the returned
        iterator provides access to the controlling :class:`_ListPointer`.  The
        position of the pointer can be modified (using ``+=`` or ``-=``), which
        will affect the next item yielded by the iterator.

        Args:
            seq: The sequence to be scanned.
            start: The initial value of the iteration counter
                (:attr:`IterState.step`).  (Does not affect the position in
                :arg:`seq` at which iteration begins.)
            sentinel: The sentinel value of the controlling
                :class:`_ListPointer`.

        Yields:
            An :class:`~_ListPointer.IterState` that represents the current
                iteration state.
        """
        ptr = _ListPointer(seq, sentinel=sentinel)
        count = start
        # ptr or seq can be modified at any time
        while 0 <= (i := ptr._index) < len(seq):
            yield cls.IterState(count, seq[i], ptr)
            ptr._index += 1
            count += 1


#===============================================================================
#
#   _Token class hierarchy
#
#===============================================================================

class _Token:
    """Parent class of all token types.

    Args:
        value: The (unescaped) text of the token.
    """

    def __init__(self, value: str) -> None:
        self.value = value

    def __eq__(self, other: object) -> bool:
        # Strict type match: a _QuotedString is never equal to an
        # _UnquotedString, even with the same value.
        if type(self) is not type(other):
            return NotImplemented
        # Cast required because Mypy is stupid
        return self.value == typing.cast(_Token, other).value

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.value!r})"


class _Separator(_Token):
    """Commas and (some) equals signs.

    Subclasses are singletons.
    """

    __instances: dict[type[typing.Self], typing.Self] = {}
    """Singleton instances."""

    def __new__(cls) -> typing.Self:
        """Make subclasses singletons."""
        instance = cls.__instances.get(cls)
        if instance is None:
            instance = super().__new__(cls)
            cls.__instances[cls] = instance
        return instance

    def __eq__(self, other: object) -> bool:
        """Use identity equality for singletons."""
        return other is self


class _Comma(_Separator):
    """A tokenized comma (``,``)."""

    def __init__(self) -> None:
        super().__init__(",")


class _Equals(_Separator):
    """A tokenized equals sign separator (``=``).

    Equals signs are also used as :class:`_Token68` padding, so not all of them
    will be tokenized as this class.
    """

    def __init__(self) -> None:
        super().__init__("=")


class _String(_Token):
    """A quoted or unquoted string."""
    pass


class _QuotedString(_String):
    """A quoted string."""

    def __init__(self, value: str) -> None:
        # Valid decoded quoted-string content is HTAB, SP, VCHAR, and obs-text
        # (RFC 9110); reject the C0 controls (except HTAB) and DEL.
        for c in value:
            if (c < " " and c != "\t") or c == "\x7f":
                raise ValueError(
                    f"Invalid character {c!r} in quoted string: {value!r}"
                )
        super().__init__(value)


class _UnquotedString(_String):
    """An un-quoted (single word) string."""

    TCHAR: typing.Final = frozenset(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!#$%&'*+-.^_`|~"
    )
    """Characters allowed in a scheme, parameter name, or unquoted parameter
    value.
    """

    def __init__(self, value: str) -> None:
        if not value or not frozenset(value).issubset(self.TCHAR):
            raise ValueError(f"Invalid unquoted string: {value!r}")
        super().__init__(value)


class _Token68(_Token):
    """``token68`` data.

    See also:
      * `RFC 7235`_

    .. _RFC 7235: https://datatracker.ietf.org/doc/html/rfc7235#section-2.1
    """

    Token68_CHARS = frozenset(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "-._~+/"
    )
    """``token68`` characters, before any trailing '=' padding (RFC 9110)."""

    __VALIDATED: typing.Final = object()
    """\"Secret\" token used by :meth:`parse` to skip validation in
    :meth:`__init__`.
    """

    @classmethod
    def _has_shape(cls, value: str) -> bool:
        """Whether ``value`` is one or more token68 characters followed by only
        trailing ``=`` padding (the character shape of an RFC 9110 token68)."""
        body = value.rstrip("=")
        return bool(body) and frozenset(body).issubset(cls.Token68_CHARS)

    def __init__(self, value: str, *, _validated: object=None) -> None:
        if _validated is not self.__VALIDATED and not self._has_shape(value):
            raise ValueError(f"Invalid token68: {value!r}")
        super().__init__(value)

    @classmethod
    def parse(cls, value: str) -> typing.Self | None:
        """Attempt to parse :arg:`value` as ``token68`` data.

        Args:
            value: The text to be parsed.

        Returns:
            A new :class:`_Token68` if :arg:`value` is valid ``token68`` data,
            otherwise ``None``.
        """
        if not cls._has_shape(value):
            return None
        return cls(value, _validated=cls.__VALIDATED)


class _Unprocessed(_Token):
    """Text whose token type is not yet known."""
    pass


_COMMA: typing.Final = _Comma()
"""The :class:`_Comma` singleton."""

_EQUALS: typing.Final = _Equals()
"""The :class:`_Equals` singleton."""


#===============================================================================
#
#   Multi-stage tokenization/parsing
#
#   Each stage produces a list[_Token] that is consumed by the next stage.
#
#   Step 1: Quoted strings (_parse_quoted_strings)
#   Step 2: Whitespace (_parse_whitespace)
#   Step 3: Commas (_parse_commas)
#   Step 4: Equals signs (_parse_equals)
#   Step 5: Remaining unprocessed (_parse_unprocessed)
#   Step 6: Structural parsing (_parse_challenges)
#
#===============================================================================

#-------------------------------------------------------------------------------
#
#   Step 1: Identify and tokenize quoted strings
#
#-------------------------------------------------------------------------------

def _parse_quoted_string(hdr: str, start: int) -> tuple[_QuotedString, int]:
    """Parse a single quoted string (helper for :func:`_parse_quoted_strings`).

    Args:
        hdr: The header being parsed.
        start: The position in :arg:`hdr` of the first character of the quoted
            string's contents (immediately after the opening quote).

    Returns:
        A tuple containing the parsed, unescaped :class:`_QuotedString` and the
        position (in :arg:`hdr`) of the first character after the closing
        quote.

    Raises:
        ValueError If the quoted string or an escape sequence is not terminated.
    """
    chars: list[str] = []
    it = enumerate(hdr[start:], start=start)
    for pos, c in it:
        if c == "\\":
            try:
                _, c = next(it)
            except StopIteration:
                raise ValueError(
                    f"Unterminated escape sequence in header: {hdr!r}"
                )
            chars.append(c)
        elif c == '"':
            return _QuotedString("".join(chars)), pos + 1
        else:
            chars.append(c)
    raise ValueError(f"Unterminated quoted string in header: {hdr!r}")


def _parse_quoted_strings(hdr: str) -> list[_Token]:
    """Split a header value into its quoted strings and everything else.

    Scans ``hdr`` left to right, recognizing RFC 9110 quoted-strings.  A
    backslash inside a quoted string escapes the following character, so an
    escaped ``\\"`` does not end the string.

    Args:
        hdr: The header value to scan.

    Returns:
        A list alternating (as the input dictates) between :class:`_Unprocessed`
        tokens, holding the raw text outside of any quoted string (to be
        tokenized further in later steps), and :class:`_QuotedString` tokens,
        whose value is the unescaped content, with the surrounding quotes
        removed and every escape sequence (``\\X``) resolved to ``X``.

    Raises:
        ValueError: If a quoted string or escape sequence is not terminated, or
            contains an invalid character.
    """
    tokens: list[_Token] = []
    hdr_len = len(hdr)
    pos = 0
    while pos < hdr_len:
        quote_pos = hdr.find('"', pos)
        if quote_pos == -1:
            tokens.append(_Unprocessed(hdr[pos:]))
            break
        if quote_pos > pos:
            tokens.append(_Unprocessed(hdr[pos:quote_pos]))
        qs, pos = _parse_quoted_string(hdr, quote_pos + 1)
        tokens.append(qs)
    return tokens


#-------------------------------------------------------------------------------
#
#   Step 2: Identify and discard whitespace
#
#-------------------------------------------------------------------------------

_WHITESPACE = " \t"
"""Whitespace characters (OWS / BWS = *( SP / HTAB ), per RFC 9110)."""


def _parse_whitespace(tokens: collections.abc.Sequence[_Token]) -> list[_Token]:
    """Split each :class:`_Unprocessed` token at whitespace, discarding it.

    Runs of whitespace (space and horizontal tab, per RFC 9110's OWS/BWS) are
    removed, splitting each :class:`_Unprocessed` token into the non-whitespace
    runs around them.  Tokens that are already classified
    (:class:`_QuotedString`) are passed through unchanged.

    Args:
        tokens: The tokens produced by :func:`_parse_quoted_strings`.

    Returns:
        A new token list, with unprocessed regions split around any whitespace,
        which is discarded.
    """
    result: list[_Token] = []
    for token in tokens:
        if not isinstance(token, _Unprocessed):
            result.append(token)
            continue
        # First, replace all tabs with spaces
        value = token.value.replace("\t", " ")
        # Now split on spaces and discard empty strings from consecutive spaces
        chunks = [c for c in value.split(" ") if c]
        # Finally add each chunk to the result as an _Unprocessed
        result.extend(_Unprocessed(c) for c in chunks)
    return result


#-------------------------------------------------------------------------------
#
#   Step 3: Identify, tokenize, and combine commas
#
#-------------------------------------------------------------------------------

def _parse_commas(tokens: collections.abc.Sequence[_Token]) -> list[_Token]:
    """Split commas out of each :class:`_Unprocessed` token.

    Each comma becomes the :const:`_COMMA` object; the text between commas
    remains :class:`_Unprocessed` for later steps.  Consecutive commas are
    combined, and any comma at the beginning of the token list is removed.
    Tokens that have already been classified (:class:`_QuotedString`) are passed
    through unchanged.

    Args:
        tokens: The tokens produced by :func:`_parse_whitespace`.

    Returns:
        A new token list with unprocessed regions split around any commas,
        which are represented in the list as the :const:`_COMMA` object.
    """
    result: list[_Token] = []
    for token in tokens:
        if not isinstance(token, _Unprocessed) or "," not in token.value:
            result.append(token)
            continue
        first, *rest = token.value.split(",")
        # Process anything before the first comma
        if first:
            result.append(_Unprocessed(first))
        # Everything else was preceded by a comma, so (maybe) add one
        for part in rest:
            # Collapse sequential commas to just one
            if result and result[-1] is not _COMMA:
                result.append(_COMMA)
            # Skip empty parts (created by sequential commas)
            if part:
                result.append(_Unprocessed(part))
    return result


#-------------------------------------------------------------------------------
#
#   Step 4: Identify and tokenize equals separators and *padded* token68
#           challenge data
#
#-------------------------------------------------------------------------------

def _parse_equals(tokens: collections.abc.Sequence[_Token]) -> list[_Token]:
    """Resolve ``=`` within each :class:`_Unprocessed` token.

    An ``=`` is either an authentication parameter separator (:const:`_EQUALS`)
    or trailing padding of a (:class:`_Token68`).  If an unprocessed token is
    immediately followed by a comma (or the end of the token list), and it is
    valid ``token68`` data (see :meth:`_Token68.parse`), it is categorized as a
    :class:`_Token68`.  Otherwise, it is split around any equals signs, which
    are tokenized as :const:`_EQUALS`.

    Note:
        An unpadded token68 (e.g. ``abc`` with no ``=``) is lexically identical
        to a scheme, a name, or an unquoted value, so it is left
        :class:`_Unprocessed` for :func:`_parse_unprocessed` to classify.

    Args:
        tokens: The tokens produced by :func:`_parse_commas`.

    Returns:
        A new token list with ``=`` resolved into :const:`_EQUALS` and
        :class:`_Token68` tokens.
    """
    result: list[_Token] = []
    for _, token, ptr in _ListPointer.enumerate(tokens):
        if not isinstance(token, _Unprocessed) or "=" not in token.value:
            result.append(token)
            continue
        # Check for valid token68 data followed by a comma (or end of list)
        if ptr[1] in (_COMMA, None):
            token68 = _Token68.parse(token.value)
            if token68 is not None:
                result.append(token68)
                continue
        for i, part in enumerate(token.value.split("=")):
            # Insert equals tokens between split parts (not before the first)
            if i > 0:
                result.append(_EQUALS)
            # If a part is empty, because of consecutive equals signs, skip it
            if part:
                result.append(_Unprocessed(part))
    return result


#-------------------------------------------------------------------------------
#
#   Step 5: Identify and tokenize remaining unprocessed tokens as either
#           unquoted strings or unpadded token68 challenge data
#
#-------------------------------------------------------------------------------

def _parse_unprocessed(
        tokens: collections.abc.Sequence[_Token]
) -> list[_Token]:
    """Classify remaining :class:`_Unprocessed` tokens as
    :class:`_UnquotedString` or :class:`_Token68`.

    An unprocessed token is classified as a :class:`_Token68` or an
    :class:`_UnquotedString` by examining its adjacent tokens.

      * If the preceding token is an unquoted string (an :class:`_Unprocessed`
        in :arg:`tokens`) and the next token is :const:`_COMMA` or the end of
        the token list, then the unprocessed token is classified as a
        :class:`_Token68`, and an exception is raised if it does not contain
        valid ``token68`` data.

        Note that if the preceding token is an :class:`_Unprocessed` in
        :arg:`tokens`, then it must have been classified as an
        :class:`_UnquotedString`, because the token being examined is not a
        comma (or the end of the list).

      * Otherwise, the unprocessed token is classified as an
        :class:`_UnquotedString`.

    Args:
        tokens: The tokens produced by :func:`_parse_equals`.

    Returns:
        A new token list with all tokens classified (no remaining
        :class:`_Unprocessed` tokens).

    Raises:
        ValueError: If a token classified as a :class:`_Token68` or
            :class:`_UnquotedString` contains characters invalid for that type.
    """
    result: list[_Token] = []
    for _, token, ptr in _ListPointer.enumerate(tokens):
        if not isinstance(token, _Unprocessed):
            result.append(token)
            continue
        # We're iterating through tokens (not result), so an unquoted string
        # would have been an _Unprocessed.  (If ptr[-1] was an _Unprocessed, it
        # can't be a _Token68, because it isn't followed by a comma or the end of
        # the list.)
        if isinstance(ptr[-1], _Unprocessed) and ptr[1] in (_COMMA, None):
            result.append(_Token68(token.value))
        else:
            result.append(_UnquotedString(token.value))
    return result


#-------------------------------------------------------------------------------
#
#   Step 6: Parse the tokens into challenges, parameters, and token68 data
#
#-------------------------------------------------------------------------------

def _parse_params(ptr: _ListPointer[_Token]) -> dict[str, str]:
    """Parse challenge parameters (helper for :func:`__parse_challenge`).

    After each comma, this function checks 2 positions ahead for an equals
    sign.  If one is found, the comma separates parameters.  If no comma is
    found the comma separates challenges.

    When this function returns, :arg:`ptr` points to the scheme of the next
    challenge or to a position beyond the end of the token list.

    Args:
        ptr: Points to the first parameter name.

    Returns:
        The challenge as a dictionary.  Parameter names (keys) are normalized to
        lowercase.

    Raises:
        ValueError: If an invalid structure is found.
    """
    params: dict[str, str] = {}
    while ptr.valid:
        # Parse the parameter at ptr
        if not isinstance(ptr[0], _UnquotedString):
            raise ValueError(f"Expected parameter name; got {ptr[0]}")
        name = ptr[0].value
        if ptr[1] is not _EQUALS:
            raise ValueError(
                f"Expected '=' after parameter name ({name}); got {ptr[1]}"
            )
        if not isinstance(ptr[2], _String):
            raise ValueError(f"Expected value after '{name}='; got {ptr[2]}")
        lname = name.lower()
        if lname in params:
            raise ValueError(f"Duplicate parameter name: {name}")
        params[lname] = ptr[2].value
        # What's next (if anything)?
        if ptr[3] not in (_COMMA, None):
            raise ValueError(f"Expected comma after parameter; got {ptr[3]}")
        ptr += 4  # advance past param & comma (possibly past end of list)
        if ptr[1] is not _EQUALS:
            break
    return params


def _parse_challenge(ptr: _ListPointer[_Token]) -> Challenge:
    """Parse an authentication challenge (helper for :func:`_parse_challenges`).

    When this function returns, :arg:`ptr` points to the scheme of the next
    challenge or to a position beyond the end of the token list.

    Args:
        ptr: Points to the challenge scheme.

    Raises:
        ValueError: If an invalid structure is found.
    """
    if not isinstance(ptr[0], _UnquotedString):
        raise ValueError(f"Expected auth scheme; got {ptr[0]}")
    scheme = ptr[0].value
    if ptr[1] in (_COMMA, None):
        # Bare challenge
        ptr += 2  # advance past comma (or past end of list)
        return Challenge(scheme)
    if isinstance(ptr[1], _Token68):
        token68 = ptr[1].value
        # Challenge with token68 data
        if ptr[2] not in (_COMMA, None):
            raise ValueError(f"Expected comma after token data; got {ptr[2]}")
        ptr += 3  # advance past token & comma (maybe past end of list)
        return Challenge(scheme, token=token68)
    # Challenge with parameters
    ptr += 1  # advance to first parameter name
    return Challenge(scheme, params=_parse_params(ptr))


def _parse_challenges(
        tokens: collections.abc.Sequence[_Token]
) -> list[Challenge]:
    """Parse a fully tokenized header into its challenges.

    Args:
        tokens: The tokens produced by :func:`_parse_unprocessed`.

    Returns:
        The challenges, in the order they appear in the header.

    Raises:
        ValueError: If the tokens do not form a valid sequence of challenges.
    """
    challenges: list[Challenge] = []
    ptr = _ListPointer(tokens)
    while ptr.valid:
        challenges.append(_parse_challenge(ptr))
    return challenges


#===============================================================================
#
#   Put it all together
#
#===============================================================================

@dataclasses.dataclass
class Challenge:
    """A single parsed ``WWW-Authenticate`` challenge.

    A challenge that carries data sets exactly one of :attr:`token` (a token68
    credential) or :attr:`params` (auth parameters); a bare scheme leaves both
    ``None``.  The :attr:`scheme` and every parameter name are normalized to
    lowercase (both are case-insensitive per RFC 9110); the token68 credential
    and parameter values are left as received, as they are case-sensitive.

    Raises:
        ValueError: If :arg:`token` and :arg:`params` are both specified.
    """

    scheme: str
    """The authentication scheme (normalized to lowercase)."""

    token: str | None = dataclasses.field(default=None, kw_only=True)
    """Authentication scheme ``token68`` data, if any."""

    params: dict[str, str] | None = dataclasses.field(
        default=None, kw_only=True
    )
    """Authentication scheme parameters, if any.

    Parameters names are normalized to lowercase.
    """

    def __post_init__(self) -> None:
        if self.token is not None and self.params is not None:
            raise ValueError(
                f"Challenge ({self.scheme}) has both token and parameters"
            )
        self.scheme = self.scheme.lower()


def parse(hdr: str) -> list[Challenge]:
    """Parse a ``WWW-Authenticate`` header.

    Args:
        hdr: The contents of the header (or multiple ``WWW-Authenticate``
            headers separated by commas).

    Returns:
        A list of parsed authentication challenges.

    Raises:
        ValueError: If the header contents are not valid.
    """
    tokens = _parse_quoted_strings(hdr)
    tokens = _parse_whitespace(tokens)
    tokens = _parse_commas(tokens)
    tokens = _parse_equals(tokens)
    tokens = _parse_unprocessed(tokens)
    return _parse_challenges(tokens)


# kate: tab-width 8; indent-width 4; replace-tabs on;
