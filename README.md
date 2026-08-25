<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# WWW-Authenticate Parser (`wwwauth`)

Copyright 2026 Ian Pilcher <<arequipeno@gmail.com>>

This a parser for `WWW-Authenticate` HTTP headers, as defined in
[RFC 9110](https://datatracker.ietf.org/doc/html/rfc9110#section-11.6.1).

## License

This repository uses multiple licenses.

* The library itself ([`wwwauth.py`](wwwauth.py)) is distributed under the
  [GNU Lesser General Public License (LGPL), version 3](lgpl-3.0.txt).

* The GNU licenses ([`lgpl-3.0.txt`](lgpl-3.0.txt) and
  [`gpl-3.0.txt`](gpl-3.0.txt)) are copyrighted by the Free Software Foundation,
  Inc.  Verbatim copies can be freely distributed, but no changes are allowed.

* All other files in the repository, including this README, are distributed
  under the [GNU General Public License (GPL), version 3](gpl-3.0.txt).

## Installation

The library consists of a single module, `wwwauth.py`.  Simply copy the file to
a directory in your Python path.

## Usage

The API is extremely simple.  A header string is passed to the `parse` function
and a list of `Challenge` objects is returned.  (If the string is not a valid
`WWW-Authenticate` header, a `ValueError` is raised.

```python
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
    ...
  ```

A `Challenge` object has 1
mandatory and 2 optional (and mutually exclusive) fields.

* `scheme` (*str*) &ndash; The authentication scheme of the challenge,
  normalized to all lowercase (`basic`, `bearer`, `digest`, `negotiate`, etc.).

* `token` (*str | None*) &ndash; Set if the `WWW-Authenticate` header included
  `token68` data for the challenge.  The token data is not decoded or otherwise
  modified.

* `params` (*dict[str, str] | None*) &ndash; Set if the `WWW-Authenticate`
  header included parameters for the challenge.  Parameter names (but not
  values) are normalized to all lowercase.

`scheme` is set in all `Challenge` objects.  One of `token` or `params` **may**
be set.

```python
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
    ...
```

## Example

```python
>>> import wwwauth
>>>
>>> challenges = wwwauth.parse(
... 'Bearer token68date===, '
... 'Bearer realm="https://foo.bar",SCOPE="baz", '
... 'BareChallenge,'
... )
>>>
>>> for c in challenges:
...     print(c)
...
Challenge(scheme='bearer', token='token68date===', params=None)
Challenge(scheme='bearer', token=None, params={'realm': 'https://foo.bar', 'scope': 'baz'})
Challenge(scheme='barechallenge', token=None, params=None)
```

Note that the challenge types and parameter names have all been normalized to
all lowercase.

## Notes

* As required by
  [RFC 9110](https://datatracker.ietf.org/doc/html/rfc9110#section-5.6.1.2),
  whitespace and extra commas within the header string are ignored.

* The parser only parses the structure of the`WWW-Authenticate` header itself.
  It does not validate the individual challenges within the header.  For
  example, the **Basic** authentication scheme does not accept token68 data, but
  this library will parse and return such an invalid challenge.

  ```python
  >>> wwwauth.parse('basic kfjdfjkfddkfjdj==')
  [Challenge(scheme='basic', token='kfjdfjkfddkfjdj==', params=None)]
  ```

* An incomplete authentication parameter list may be parsed as token68 data.

  ```python
  >>> wwwauth.parse('basic realm=')
  [Challenge(scheme='basic', token='realm=', params=None)]
  ```

  Although surprising, this is correct, because `realm=` is valid token68 data.
