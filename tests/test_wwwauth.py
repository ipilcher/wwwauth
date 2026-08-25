# SPDX-FileCopyrightText: 2026 Ian Pilcher <arequipeno@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for the wwwauth module (WWW-Authenticate header parser).

Covers:
  - Challenge dataclass unit tests
  - parse() unit tests (bare scheme, token68, auth-params, multiple challenges,
    whitespace)
  - Full-pipeline tests derived from RFC 9110 and real-world usage
  - Property-based tests via Hypothesis
"""

import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

# The implementation lives one level up from this file.
sys.path.insert(0, str(Path(__file__).parent.parent))

import wwwauth
from wwwauth import Challenge, parse

# Private API
from wwwauth import (
    _COMMA,
    _EQUALS,
    _WHITESPACE,
    _Comma,
    _Equals,
    _ListPointer,
    _QuotedString,
    _Separator,
    _String,
    _Token,
    _Token68,
    _Unprocessed,
    _UnquotedString,
    _parse_challenge,
    _parse_challenges,
    _parse_commas,
    _parse_equals,
    _parse_params,
    _parse_quoted_string,
    _parse_quoted_strings,
    _parse_unprocessed,
    _parse_whitespace,
)


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# RFC 9110 §5.6.2 tchar (token characters)
_TCHAR = "!#$%&'*+-.^_`|~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

# RFC 9110 §11.2 token68 body characters (before optional trailing '=')
_T68_BODY = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/"

# A valid HTTP token (suitable as a scheme or param name)
token_st = st.text(alphabet=_TCHAR, min_size=1, max_size=20)

# A valid token68 value (body + optional '=' padding)
token68_st = st.builds(
    lambda body, pad: body + "=" * pad,
    body=st.text(alphabet=_T68_BODY, min_size=1, max_size=30),
    pad=st.integers(min_value=0, max_value=3),
)

# Printable ASCII safe inside double quotes (no '"' or '\')
quoted_value_st = st.text(
    alphabet=st.characters(
        min_codepoint=0x20,
        max_codepoint=0x7E,
        blacklist_characters='"\\',
    ),
    min_size=0,
    max_size=40,
)


# ---------------------------------------------------------------------------
# Unit tests: Challenge dataclass
# ---------------------------------------------------------------------------

class TestChallenge:
    def test_bare_scheme_defaults(self):
        c = Challenge("Bearer")
        assert c.scheme == "bearer"
        assert c.token is None
        assert c.params is None

    def test_scheme_with_token(self):
        c = Challenge("Bearer", token="dGVzdA==")
        assert c.scheme == "bearer"
        assert c.token == "dGVzdA=="
        assert c.params is None

    def test_scheme_with_params(self):
        c = Challenge("Basic", params={"realm": "example"})
        assert c.scheme == "basic"
        assert c.token is None
        assert c.params == {"realm": "example"}

    def test_both_token_and_params_raises(self):
        with pytest.raises(ValueError):
            Challenge("Bearer", token="abc", params={"realm": "test"})

    def test_scheme_normalized_uppercase(self):
        assert Challenge("BEARER").scheme == "bearer"

    def test_scheme_normalized_mixed(self):
        assert Challenge("BeArEr").scheme == "bearer"

    def test_scheme_already_lowercase(self):
        assert Challenge("bearer").scheme == "bearer"

    def test_param_values_case_preserved(self):
        c = Challenge("Basic", params={"realm": "MyRealm"})
        assert c.params["realm"] == "MyRealm"

    def test_token_value_case_preserved(self):
        token = "dGVzdA=="
        assert Challenge("Bearer", token=token).token == token

    def test_equality_bare(self):
        assert Challenge("bearer") == Challenge("BEARER")

    def test_equality_with_token(self):
        assert Challenge("bearer", token="abc") == Challenge("Bearer", token="abc")

    def test_equality_with_params(self):
        assert (
            Challenge("basic", params={"realm": "test"})
            == Challenge("Basic", params={"realm": "test"})
        )

    def test_inequality_different_scheme(self):
        assert Challenge("bearer") != Challenge("basic")

    def test_inequality_different_params(self):
        assert (
            Challenge("basic", params={"realm": "a"})
            != Challenge("basic", params={"realm": "b"})
        )

    def test_inequality_token_vs_no_token(self):
        assert Challenge("bearer", token="x") != Challenge("bearer")

    def test_inequality_params_vs_no_params(self):
        assert Challenge("basic", params={"realm": "x"}) != Challenge("basic")


# ---------------------------------------------------------------------------
# Unit tests: parse() — bare scheme
# ---------------------------------------------------------------------------

class TestParseBareScheme:
    def test_simple(self):
        assert parse("Bearer") == [Challenge("bearer")]

    def test_uppercase(self):
        assert parse("BEARER")[0].scheme == "bearer"

    def test_lowercase(self):
        assert parse("bearer")[0].scheme == "bearer"

    def test_mixed_case(self):
        assert parse("BeArEr")[0].scheme == "bearer"

    def test_single_char(self):
        result = parse("A")
        assert result == [Challenge("a")]

    def test_returns_list(self):
        assert isinstance(parse("Bearer"), list)

    def test_returns_challenge_instances(self):
        assert all(isinstance(c, Challenge) for c in parse("Bearer"))

    def test_no_token_no_params(self):
        c = parse("Bearer")[0]
        assert c.token is None
        assert c.params is None

    def test_scheme_with_tchar_chars(self):
        # '+', '-', '_', '.' are all valid tchar
        result = parse("My-Scheme")
        assert result[0].scheme == "my-scheme"


# ---------------------------------------------------------------------------
# Unit tests: parse() — token68
# ---------------------------------------------------------------------------

class TestParseToken68:
    def test_base64_with_padding(self):
        result = parse("Bearer dGVzdA==")
        assert result[0].token == "dGVzdA=="
        assert result[0].params is None

    def test_base64_no_padding(self):
        result = parse("Bearer dGVzdA")
        assert result[0].token == "dGVzdA"

    def test_token68_all_special_chars(self):
        # All body chars: ALPHA, DIGIT, - . _ ~ + /
        result = parse("Negotiate abc-def.ghi_jkl~mno+pqr/stu===")
        assert result[0].token == "abc-def.ghi_jkl~mno+pqr/stu==="

    def test_token68_scheme_normalized(self):
        result = parse("NEGOTIATE AAAA")
        assert result[0].scheme == "negotiate"
        assert result[0].token == "AAAA"

    def test_token68_value_case_preserved(self):
        result = parse("Bearer AbCdEfGh")
        assert result[0].token == "AbCdEfGh"

    def test_token68_only_padding_is_invalid(self):
        # '=' alone has no body chars — not valid token68
        with pytest.raises(ValueError):
            parse("Bearer =")

    def test_token68_params_is_none(self):
        assert parse("Bearer dGVzdA==")[0].params is None


# ---------------------------------------------------------------------------
# Unit tests: parse() — auth-params
# ---------------------------------------------------------------------------

class TestParseAuthParams:
    def test_single_quoted_param(self):
        result = parse('Basic realm="example"')
        assert result[0].params == {"realm": "example"}

    def test_single_unquoted_param(self):
        result = parse("Basic realm=example")
        assert result[0].params == {"realm": "example"}

    def test_multiple_params(self):
        result = parse('Basic realm="example", charset="UTF-8"')
        assert result[0].params == {"realm": "example", "charset": "UTF-8"}

    def test_param_name_case_insensitive(self):
        result = parse('Basic Realm="example"')
        assert "realm" in result[0].params
        assert result[0].params["realm"] == "example"

    def test_param_value_case_preserved(self):
        result = parse('Basic realm="MyRealm"')
        assert result[0].params["realm"] == "MyRealm"

    def test_empty_quoted_string(self):
        result = parse('Basic realm=""')
        assert result[0].params == {"realm": ""}

    def test_quoted_string_with_spaces(self):
        result = parse('Basic realm="My Protected Realm"')
        assert result[0].params == {"realm": "My Protected Realm"}

    def test_quoted_string_escaped_quote(self):
        result = parse(r'Basic realm="My \"Realm\""')
        assert result[0].params == {"realm": 'My "Realm"'}

    def test_quoted_string_escaped_backslash(self):
        result = parse(r'Basic realm="C:\\path"')
        assert result[0].params == {"realm": "C:\\path"}

    def test_token_is_none_when_params_present(self):
        assert parse('Basic realm="x"')[0].token is None

    def test_many_params(self):
        hdr = 'Digest realm="r", nonce="n", algorithm=MD5, qop="auth", opaque="o"'
        result = parse(hdr)
        p = result[0].params
        assert p["realm"] == "r"
        assert p["nonce"] == "n"
        assert p["algorithm"] == "MD5"
        assert p["qop"] == "auth"
        assert p["opaque"] == "o"

    def test_bws_before_equals(self):
        result = parse('Basic realm ="example"')
        assert result[0].params == {"realm": "example"}

    def test_bws_after_equals(self):
        result = parse('Basic realm= "example"')
        assert result[0].params == {"realm": "example"}

    def test_bws_both_sides(self):
        result = parse('Basic realm = "example"')
        assert result[0].params == {"realm": "example"}


# ---------------------------------------------------------------------------
# Unit tests: parse() — multiple challenges
# ---------------------------------------------------------------------------

class TestParseMultipleChallenges:
    def test_two_bare_schemes(self):
        result = parse("Bearer, Basic")
        assert len(result) == 2
        assert result[0].scheme == "bearer"
        assert result[1].scheme == "basic"

    def test_three_bare_schemes(self):
        result = parse("Bearer, Basic, Negotiate")
        assert len(result) == 3
        assert [c.scheme for c in result] == ["bearer", "basic", "negotiate"]

    def test_params_then_bare(self):
        result = parse('Basic realm="example", Bearer')
        assert len(result) == 2
        assert result[0] == Challenge("basic", params={"realm": "example"})
        assert result[1] == Challenge("bearer")

    def test_bare_then_params(self):
        result = parse('Bearer, Basic realm="example"')
        assert len(result) == 2
        assert result[0] == Challenge("bearer")
        assert result[1] == Challenge("basic", params={"realm": "example"})

    def test_two_parameterised_schemes(self):
        result = parse('Basic realm="a", Bearer realm="b"')
        assert len(result) == 2
        assert result[0].params["realm"] == "a"
        assert result[1].params["realm"] == "b"

    def test_token68_then_bare(self):
        result = parse("Bearer dGVzdA==, Basic")
        assert len(result) == 2
        assert result[0].token == "dGVzdA=="
        assert result[1].scheme == "basic"

    def test_two_token68_challenges(self):
        result = parse("Bearer dGVzdA==, Negotiate AAAA")
        assert len(result) == 2
        assert result[0].token == "dGVzdA=="
        assert result[1].token == "AAAA"

    def test_same_scheme_twice(self):
        result = parse('Bearer realm="a", Bearer realm="b"')
        assert len(result) == 2
        assert result[0].params["realm"] == "a"
        assert result[1].params["realm"] == "b"

    def test_extra_spaces_between_challenges(self):
        result = parse("Bearer,  Basic")
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Unit tests: parse() — whitespace
# ---------------------------------------------------------------------------

class TestParseWhitespace:
    def test_leading_spaces(self):
        assert parse("  Bearer")[0].scheme == "bearer"

    def test_trailing_spaces(self):
        assert parse("Bearer  ")[0].scheme == "bearer"

    def test_tabs_as_whitespace(self):
        result = parse("Bearer\tdGVzdA")
        assert result[0].token == "dGVzdA"


# ---------------------------------------------------------------------------
# Unit tests: parse() — invalid inputs
# ---------------------------------------------------------------------------

class TestParseInvalid:
    @pytest.mark.parametrize("hdr,reason", [
        ('=', "bare '=' is not a valid token character"),
        ('"quoted"', "leading quote is not a valid scheme start"),
        ('Basic realm="unclosed', "unclosed quoted string"),
        ('(invalid)', "leading '(' is not a valid token character"),
        ('Basic realm!=', "no value after equals sign"),
        ('Basic realm!=,', "comma immediately after equals sign (no value)"),
        ('Basic realm=value extra', "junk token after unquoted param value"),
        ('Bearer dGVzdA== extra', "junk token after token68 data"),
        ('Basic realm="a", realm="b"', "duplicate param name (same case)"),
        ('Basic realm="a", Realm="b"', "duplicate param name (different case)"),
    ])
    def test_raises_value_error(self, hdr, reason):
        with pytest.raises(ValueError, match=None):
            parse(hdr)


# ---------------------------------------------------------------------------
# Full-pipeline tests: RFC 9110 and real-world scenarios
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_http_basic_auth(self):
        result = parse('Basic realm="Protected Area"')
        assert len(result) == 1
        c = result[0]
        assert c.scheme == "basic"
        assert c.params == {"realm": "Protected Area"}
        assert c.token is None

    def test_http_digest_auth(self):
        hdr = (
            'Digest realm="example.com", qop="auth,auth-int", '
            'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
            'opaque="5ccc069c403ebaf9f0171e9517f40e41"'
        )
        result = parse(hdr)
        assert len(result) == 1
        c = result[0]
        assert c.scheme == "digest"
        assert c.params["realm"] == "example.com"
        assert c.params["qop"] == "auth,auth-int"
        assert c.params["nonce"] == "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        assert c.params["opaque"] == "5ccc069c403ebaf9f0171e9517f40e41"

    def test_oauth2_bearer_bare(self):
        assert parse("Bearer") == [Challenge("bearer")]

    def test_oauth2_bearer_with_realm(self):
        result = parse('Bearer realm="https://api.example.com/"')
        assert result[0].scheme == "bearer"
        assert result[0].params["realm"] == "https://api.example.com/"

    def test_oauth2_bearer_error_response(self):
        hdr = (
            'Bearer realm="example", error="invalid_token", '
            'error_description="The access token expired"'
        )
        result = parse(hdr)
        assert result[0].params["error"] == "invalid_token"
        assert result[0].params["error_description"] == "The access token expired"

    def test_negotiate_bare(self):
        result = parse("Negotiate")
        assert result[0].scheme == "negotiate"
        assert result[0].token is None
        assert result[0].params is None

    def test_negotiate_with_gssapi_token(self):
        gss = "YIIBmgYJKoZIhvcSAQICAQBuggGJMIIBha"
        result = parse(f"Negotiate {gss}")
        assert result[0].scheme == "negotiate"
        assert result[0].token == gss

    def test_multiple_schemes_server(self):
        hdr = 'Bearer realm="api.example.com", Basic realm="api.example.com"'
        result = parse(hdr)
        assert len(result) == 2
        assert {c.scheme for c in result} == {"bearer", "basic"}

    def test_hoba_scheme(self):
        hdr = 'HOBA realm="example.com", challenge="abc123", max-age=300'
        result = parse(hdr)
        assert result[0].scheme == "hoba"
        assert result[0].params["realm"] == "example.com"
        assert result[0].params["challenge"] == "abc123"
        assert result[0].params["max-age"] == "300"

    def test_scram_sha256(self):
        result = parse('SCRAM-SHA-256 realm="example"')
        assert result[0].scheme == "scram-sha-256"
        assert result[0].params["realm"] == "example"

    def test_combined_headers_simulation(self):
        # Servers may send multiple WWW-Authenticate headers; clients combine them
        hdr = 'Basic realm="example", Bearer realm="example"'
        result = parse(hdr)
        assert len(result) == 2

    def test_all_challenge_fields_correct(self):
        result = parse('Basic realm="Test Realm", charset="UTF-8"')
        c = result[0]
        assert c.scheme == "basic"
        assert c.token is None
        assert isinstance(c.params, dict)
        assert c.params == {"realm": "Test Realm", "charset": "UTF-8"}

    def test_challenge_with_numeric_param_value(self):
        result = parse("Bearer max-age=3600")
        assert result[0].params["max-age"] == "3600"

    def test_scheme_name_with_hyphen(self):
        # Hyphen is a valid tchar; many registered schemes contain one
        result = parse("SCRAM-SHA-512")
        assert result[0].scheme == "scram-sha-512"

    def test_digest_with_unquoted_algorithm(self):
        # algorithm= value is a token (unquoted) per practice
        hdr = 'Digest realm="example.com", algorithm=SHA-256, nonce="abc"'
        result = parse(hdr)
        assert result[0].params["algorithm"] == "SHA-256"

    def test_parse_returns_only_challenges(self):
        # parse() returns a list; every element must be a Challenge
        result = parse('Bearer, Basic realm="x", Negotiate dGVzdA')
        assert len(result) == 3
        assert all(isinstance(c, Challenge) for c in result)
        # Exactly one of token / params is set (or both None), never both
        for c in result:
            assert not (c.token is not None and c.params is not None)


# ---------------------------------------------------------------------------
# Property-based tests via Hypothesis
# ---------------------------------------------------------------------------

class TestHypothesis:
    @given(scheme=token_st)
    @settings(max_examples=300)
    def test_any_token_is_parseable_as_bare_scheme(self, scheme):
        result = parse(scheme)
        assert len(result) == 1
        assert result[0].scheme == scheme.lower()
        assert result[0].token is None
        assert result[0].params is None

    @given(scheme=token_st)
    def test_scheme_always_lowercase_in_output(self, scheme):
        result = parse(scheme)
        assert result[0].scheme == result[0].scheme.lower()

    @given(scheme=token_st, token=token68_st)
    @settings(max_examples=300)
    def test_token68_roundtrip(self, scheme, token):
        result = parse(f"{scheme} {token}")
        assert len(result) == 1
        assert result[0].scheme == scheme.lower()
        assert result[0].token == token
        assert result[0].params is None

    @given(scheme=token_st, key=token_st, value=token_st)
    @settings(max_examples=300)
    def test_unquoted_param_roundtrip(self, scheme, key, value):
        result = parse(f"{scheme} {key}={value}")
        assert len(result) == 1
        assert result[0].params is not None
        assert result[0].params[key.lower()] == value

    @given(scheme=token_st, key=token_st, value=quoted_value_st)
    @settings(max_examples=300)
    def test_quoted_param_value_roundtrip(self, scheme, key, value):
        result = parse(f'{scheme} {key}="{value}"')
        assert len(result) == 1
        assert result[0].params[key.lower()] == value

    @given(scheme1=token_st, scheme2=token_st)
    @settings(max_examples=300)
    def test_two_bare_schemes_both_parsed(self, scheme1, scheme2):
        result = parse(f"{scheme1}, {scheme2}")
        assert len(result) == 2
        assert result[0].scheme == scheme1.lower()
        assert result[1].scheme == scheme2.lower()

    @given(scheme=token_st)
    def test_result_is_list_of_challenge_instances(self, scheme):
        result = parse(scheme)
        assert isinstance(result, list)
        assert all(isinstance(c, Challenge) for c in result)

    @given(scheme=token_st, key=token_st, value=token_st)
    def test_all_param_names_are_lowercase(self, scheme, key, value):
        result = parse(f"{scheme} {key}={value}")
        if result[0].params:
            for k in result[0].params:
                assert k == k.lower()

    @given(
        scheme=token_st,
        params=st.dictionaries(
            keys=token_st,
            values=token_st,
            min_size=1,
            max_size=4,
        ),
    )
    @settings(
        max_examples=150,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_multiple_unquoted_params_roundtrip(self, scheme, params):
        # Skip when two keys lowercase to the same string (dict would lose one)
        lowered = [k.lower() for k in params]
        assume(len(set(lowered)) == len(lowered))

        param_str = ", ".join(f"{k}={v}" for k, v in params.items())
        result = parse(f"{scheme} {param_str}")
        assert result[0].scheme == scheme.lower()
        for k, v in params.items():
            assert result[0].params[k.lower()] == v

    @given(scheme=token_st, token=token68_st)
    def test_token68_challenge_has_no_params(self, scheme, token):
        result = parse(f"{scheme} {token}")
        assert result[0].params is None

    @given(scheme=token_st, key=token_st, value=token_st)
    def test_auth_param_challenge_has_no_token(self, scheme, key, value):
        result = parse(f"{scheme} {key}={value}")
        assert result[0].token is None


# ============================================================================
# Private API tests
# ============================================================================

# ---------------------------------------------------------------------------
# _ListPointer
# ---------------------------------------------------------------------------

class TestListPointerConstruction:
    def test_default_position_is_zero(self):
        ptr = _ListPointer([1, 2, 3])
        assert ptr.position == 0

    def test_custom_position(self):
        ptr = _ListPointer([1, 2, 3], 2)
        assert ptr.position == 2

    def test_default_sentinel_is_none(self):
        ptr = _ListPointer([1, 2, 3])
        assert ptr[99] is None

    def test_custom_sentinel(self):
        sentinel = object()
        ptr = _ListPointer([1, 2, 3], sentinel=sentinel)
        assert ptr[99] is sentinel

    def test_custom_sentinel_non_object(self):
        ptr = _ListPointer([1, 2, 3], sentinel=-1)
        assert ptr[99] == -1


class TestListPointerGetitem:
    def test_offset_zero_returns_current(self):
        ptr = _ListPointer([10, 20, 30])
        assert ptr[0] == 10

    def test_positive_offset(self):
        ptr = _ListPointer([10, 20, 30])
        assert ptr[1] == 20
        assert ptr[2] == 30

    def test_negative_offset(self):
        ptr = _ListPointer([10, 20, 30], 2)
        assert ptr[-1] == 20
        assert ptr[-2] == 10

    def test_past_end_returns_sentinel(self):
        ptr = _ListPointer([10, 20, 30])
        assert ptr[3] is None
        assert ptr[100] is None

    def test_before_start_returns_sentinel(self):
        ptr = _ListPointer([10, 20, 30])  # position 0
        assert ptr[-1] is None

    def test_custom_sentinel_on_miss(self):
        ptr = _ListPointer([1, 2], sentinel=-1)
        assert ptr[10] == -1

    def test_getitem_mid_sequence(self):
        ptr = _ListPointer([10, 20, 30, 40], 1)
        assert ptr[-1] == 10
        assert ptr[0] == 20
        assert ptr[1] == 30
        assert ptr[2] == 40
        assert ptr[3] is None

    def test_works_with_non_list_sequence(self):
        ptr = _ListPointer((10, 20, 30))
        assert ptr[0] == 10
        assert ptr[2] == 30


class TestListPointerAdvanceBackup:
    def test_advance_positive(self):
        ptr = _ListPointer([1, 2, 3])
        ptr.advance(1)
        assert ptr.position == 1
        assert ptr[0] == 2

    def test_advance_multiple(self):
        ptr = _ListPointer([1, 2, 3])
        ptr.advance(2)
        assert ptr.position == 2

    def test_advance_negative_moves_backward(self):
        ptr = _ListPointer([1, 2, 3], 2)
        ptr.advance(-1)
        assert ptr.position == 1

    def test_advance_past_end(self):
        ptr = _ListPointer([1, 2, 3])
        ptr.advance(10)
        assert ptr.position == 10
        assert not ptr.valid

    def test_backup_positive(self):
        ptr = _ListPointer([1, 2, 3], 2)
        ptr.backup(1)
        assert ptr.position == 1

    def test_backup_multiple(self):
        ptr = _ListPointer([1, 2, 3], 2)
        ptr.backup(2)
        assert ptr.position == 0

    def test_backup_negative_moves_forward(self):
        ptr = _ListPointer([1, 2, 3])
        ptr.backup(-2)
        assert ptr.position == 2

    def test_backup_before_start(self):
        ptr = _ListPointer([1, 2, 3])
        ptr.backup(5)
        assert ptr.position == -5
        assert not ptr.valid

    def test_advance_zero_no_change(self):
        ptr = _ListPointer([1, 2, 3], 1)
        ptr.advance(0)
        assert ptr.position == 1

    def test_backup_zero_no_change(self):
        ptr = _ListPointer([1, 2, 3], 1)
        ptr.backup(0)
        assert ptr.position == 1


class TestListPointerAugmentedAssignment:
    def test_iadd_advances(self):
        ptr = _ListPointer([1, 2, 3])
        ptr += 2
        assert ptr.position == 2

    def test_iadd_returns_self(self):
        ptr = _ListPointer([1, 2, 3])
        original_id = id(ptr)
        ptr += 1
        assert id(ptr) == original_id

    def test_isub_backs_up(self):
        ptr = _ListPointer([1, 2, 3], 2)
        ptr -= 1
        assert ptr.position == 1

    def test_isub_returns_self(self):
        ptr = _ListPointer([1, 2, 3], 2)
        original_id = id(ptr)
        ptr -= 1
        assert id(ptr) == original_id

    def test_iadd_negative_moves_backward(self):
        ptr = _ListPointer([1, 2, 3], 2)
        ptr += -1
        assert ptr.position == 1

    def test_isub_negative_moves_forward(self):
        ptr = _ListPointer([1, 2, 3])
        ptr -= -2
        assert ptr.position == 2

    def test_add_returns_not_implemented(self):
        ptr = _ListPointer([1, 2, 3])
        assert ptr.__add__(1) is NotImplemented

    def test_sub_returns_not_implemented(self):
        ptr = _ListPointer([1, 2, 3])
        assert ptr.__sub__(1) is NotImplemented

    def test_add_raises_type_error(self):
        ptr = _ListPointer([1, 2, 3])
        with pytest.raises(TypeError):
            _ = ptr + 1

    def test_sub_raises_type_error(self):
        ptr = _ListPointer([1, 2, 3])
        with pytest.raises(TypeError):
            _ = ptr - 1


class TestListPointerProperties:
    def test_position_tracks_changes(self):
        ptr = _ListPointer([1, 2, 3])
        ptr.advance(1)
        assert ptr.position == 1
        ptr.backup(1)
        assert ptr.position == 0

    def test_after_at_start(self):
        ptr = _ListPointer([1, 2, 3])  # position 0, 3 items
        assert ptr.after == 2

    def test_after_at_middle(self):
        ptr = _ListPointer([1, 2, 3], 1)
        assert ptr.after == 1

    def test_after_at_last_item(self):
        ptr = _ListPointer([1, 2, 3], 2)
        assert ptr.after == 0

    def test_after_past_end_is_negative(self):
        ptr = _ListPointer([1, 2, 3], 3)
        assert ptr.after < 0
        assert ptr.after == -1

    def test_after_before_start_gte_len(self):
        ptr = _ListPointer([1, 2, 3], -1)
        assert ptr.after >= 3
        assert ptr.after == 3

    def test_before_at_start(self):
        ptr = _ListPointer([1, 2, 3])
        assert ptr.before == 0

    def test_before_at_middle(self):
        ptr = _ListPointer([1, 2, 3], 1)
        assert ptr.before == 1

    def test_before_at_last_item(self):
        ptr = _ListPointer([1, 2, 3], 2)
        assert ptr.before == 2

    def test_before_past_end_gte_len(self):
        ptr = _ListPointer([1, 2, 3], 3)
        assert ptr.before >= 3
        assert ptr.before == 3

    def test_before_before_start_is_negative(self):
        ptr = _ListPointer([1, 2, 3], -1)
        assert ptr.before < 0
        assert ptr.before == -1

    def test_before_equals_position(self):
        seq = [1, 2, 3, 4, 5]
        for pos in range(-2, 8):
            ptr = _ListPointer(seq, pos)
            assert ptr.before == pos

    def test_before_plus_after_equals_len_minus_one(self):
        seq = [1, 2, 3]
        for pos in range(-2, 6):
            ptr = _ListPointer(seq, pos)
            assert ptr.before + ptr.after == len(seq) - 1

    def test_valid_within_range(self):
        seq = [1, 2, 3]
        for i in range(len(seq)):
            assert _ListPointer(seq, i).valid

    def test_valid_at_end_is_false(self):
        assert not _ListPointer([1, 2, 3], 3).valid

    def test_valid_before_start_is_false(self):
        assert not _ListPointer([1, 2, 3], -1).valid

    def test_valid_empty_sequence(self):
        assert not _ListPointer([], 0).valid


class TestListPointerEnumerate:
    def test_yields_all_items(self):
        seq = [10, 20, 30]
        items = list(_ListPointer.enumerate(seq))
        assert [s.current for s in items] == [10, 20, 30]

    def test_step_is_zero_based(self):
        items = list(_ListPointer.enumerate([10, 20, 30]))
        assert [s.step for s in items] == [0, 1, 2]

    def test_ptr_position_matches_sequence_index(self):
        seq = [10, 20, 30]
        for state in _ListPointer.enumerate(seq):
            assert state.ptr[0] == state.current

    def test_ptr_is_list_pointer_instance(self):
        for state in _ListPointer.enumerate([1, 2, 3]):
            assert isinstance(state.ptr, _ListPointer)

    def test_yields_iter_state_instances(self):
        for state in _ListPointer.enumerate([1]):
            assert isinstance(state, _ListPointer.IterState)

    def test_empty_sequence(self):
        assert list(_ListPointer.enumerate([])) == []

    def test_start_sets_initial_step_counter(self):
        # start= behaves like Python's built-in enumerate: it offsets the step
        # counter but does not skip any sequence items.
        seq = [10, 20, 30]
        items = list(_ListPointer.enumerate(seq, start=5))
        assert [s.step for s in items] == [5, 6, 7]
        assert [s.current for s in items] == [10, 20, 30]

    def test_sentinel_propagated_to_ptr(self):
        sentinel = object()
        for state in _ListPointer.enumerate([1, 2], sentinel=sentinel):
            assert state.ptr[100] is sentinel

    def test_steps_are_sequential(self):
        items = list(_ListPointer.enumerate([1, 2, 3, 4, 5]))
        steps = [s.step for s in items]
        assert steps == list(range(len(steps)))

    def test_iter_state_fields(self):
        state = next(iter(_ListPointer.enumerate(["a", "b"])))
        assert hasattr(state, "step")
        assert hasattr(state, "current")
        assert hasattr(state, "ptr")


# ---------------------------------------------------------------------------
# _ListPointer property-based tests
# ---------------------------------------------------------------------------

class TestListPointerHypothesis:
    @given(
        seq=st.lists(st.integers(), min_size=0, max_size=20),
        position=st.integers(-10, 30),
    )
    def test_before_plus_after_invariant(self, seq, position):
        assume(len(seq) > 0)
        ptr = _ListPointer(seq, position)
        assert ptr.before + ptr.after == len(seq) - 1

    @given(
        seq=st.lists(st.integers(), min_size=1, max_size=20),
        position=st.integers(-10, 30),
    )
    def test_before_equals_position(self, seq, position):
        ptr = _ListPointer(seq, position)
        assert ptr.before == position

    @given(
        seq=st.lists(st.integers(), min_size=0, max_size=20),
        position=st.integers(-5, 25),
    )
    def test_valid_iff_in_range(self, seq, position):
        ptr = _ListPointer(seq, position)
        assert ptr.valid == (0 <= position < len(seq))

    @given(
        seq=st.lists(st.integers(), min_size=0, max_size=20),
        position=st.integers(-5, 25),
        offset=st.integers(-5, 25),
    )
    def test_getitem_in_range_returns_seq_item(self, seq, position, offset):
        sentinel = object()
        ptr = _ListPointer(seq, position, sentinel=sentinel)
        target = position + offset
        if 0 <= target < len(seq):
            assert ptr[offset] == seq[target]
        else:
            assert ptr[offset] is sentinel

    @given(
        seq=st.lists(st.integers(), min_size=1, max_size=20),
        position=st.integers(0, 19),
        steps=st.integers(-10, 10),
    )
    def test_advance_changes_position_by_steps(self, seq, position, steps):
        assume(position < len(seq))
        ptr = _ListPointer(seq, position)
        ptr.advance(steps)
        assert ptr.position == position + steps

    @given(
        seq=st.lists(st.integers(), min_size=1, max_size=20),
        position=st.integers(0, 19),
        steps=st.integers(-10, 10),
    )
    def test_backup_changes_position_by_negative_steps(self, seq, position, steps):
        assume(position < len(seq))
        ptr = _ListPointer(seq, position)
        ptr.backup(steps)
        assert ptr.position == position - steps


# ---------------------------------------------------------------------------
# Token classes
# ---------------------------------------------------------------------------

class TestTokenBase:
    def test_stores_value(self):
        t = _Unprocessed("hello")
        assert t.value == "hello"

    def test_repr_is_string_containing_value(self):
        t = _Unprocessed("hello")
        r = repr(t)
        assert isinstance(r, str)
        assert "hello" in r

    def test_equal_same_type_same_value(self):
        assert _Unprocessed("hello") == _Unprocessed("hello")

    def test_unequal_different_value(self):
        assert _Unprocessed("hello") != _Unprocessed("world")

    def test_unequal_different_type(self):
        assert _Unprocessed("hello") != _QuotedString("hello")

    def test_unequal_to_plain_string(self):
        assert _Unprocessed("hello") != "hello"


class TestSeparatorSingleton:
    def test_comma_is_singleton(self):
        assert _Comma() is _Comma()

    def test_equals_is_singleton(self):
        assert _Equals() is _Equals()

    def test_comma_and_equals_are_distinct_singletons(self):
        assert _Comma() is not _Equals()

    def test_comma_equals_itself(self):
        assert _Comma() == _Comma()

    def test_equals_equals_itself(self):
        assert _Equals() == _Equals()

    def test_comma_not_equal_to_equals(self):
        assert _Comma() != _Equals()

    def test_comma_not_equal_to_non_comma(self):
        assert _Comma() != _Unprocessed(",")

    def test_equals_not_equal_to_non_equals(self):
        assert _Equals() != _Unprocessed("=")


class TestModuleConstants:
    def test_COMMA_is_comma_singleton(self):
        assert _COMMA is _Comma()

    def test_EQUALS_is_equals_singleton(self):
        assert _EQUALS is _Equals()

    def test_WHITESPACE_contains_space(self):
        assert " " in _WHITESPACE

    def test_WHITESPACE_contains_tab(self):
        assert "\t" in _WHITESPACE

    def test_WHITESPACE_does_not_contain_newline(self):
        assert "\n" not in _WHITESPACE

    def test_WHITESPACE_does_not_contain_cr(self):
        assert "\r" not in _WHITESPACE

    def test_WHITESPACE_is_str(self):
        assert isinstance(_WHITESPACE, str)


class TestQuotedString:
    def test_stores_unescaped_value(self):
        qs = _QuotedString("hello world")
        assert qs.value == "hello world"

    def test_equality(self):
        assert _QuotedString("x") == _QuotedString("x")

    def test_inequality_different_value(self):
        assert _QuotedString("a") != _QuotedString("b")

    def test_not_equal_to_unprocessed(self):
        assert _QuotedString("x") != _Unprocessed("x")


class TestUnquotedString:
    def test_stores_value(self):
        us = _UnquotedString("Bearer")
        assert us.value == "Bearer"

    def test_TCHAR_attribute_exists(self):
        assert hasattr(_UnquotedString, "TCHAR")
        assert isinstance(_UnquotedString.TCHAR, (str, frozenset, set))

    def test_equality(self):
        assert _UnquotedString("x") == _UnquotedString("x")

    def test_not_equal_to_quoted_string(self):
        assert _UnquotedString("x") != _QuotedString("x")


class TestToken68HasShape:
    def test_alpha_body(self):
        assert _Token68._has_shape("abc")

    def test_digit_body(self):
        assert _Token68._has_shape("123")

    def test_body_with_single_padding(self):
        assert _Token68._has_shape("abc=")

    def test_body_with_double_padding(self):
        assert _Token68._has_shape("abc==")

    def test_body_with_triple_padding(self):
        assert _Token68._has_shape("abc===")

    def test_all_body_special_chars(self):
        assert _Token68._has_shape("a-b.c_d~e+f/g")

    def test_empty_is_false(self):
        assert not _Token68._has_shape("")

    def test_padding_only_is_false(self):
        assert not _Token68._has_shape("=")
        assert not _Token68._has_shape("==")

    def test_middle_equals_is_false(self):
        assert not _Token68._has_shape("abc=def")

    def test_space_is_false(self):
        assert not _Token68._has_shape("abc def")

    def test_comma_is_false(self):
        assert not _Token68._has_shape("abc,def")

    def test_exclamation_is_false(self):
        # '!' is a valid tchar but NOT a token68 body char
        assert not _Token68._has_shape("abc!")

    def test_at_sign_is_false(self):
        assert not _Token68._has_shape("abc@def")

    @given(
        body=st.text(alphabet=_T68_BODY, min_size=1, max_size=20),
        pad=st.integers(0, 3),
    )
    def test_hypothesis_valid_shapes(self, body, pad):
        assert _Token68._has_shape(body + "=" * pad)

    @given(
        value=st.text(min_size=1, max_size=20).filter(
            lambda v: any(c not in _T68_BODY + "=" for c in v)
        )
    )
    def test_hypothesis_invalid_chars_false(self, value):
        assert not _Token68._has_shape(value)


class TestToken68Parse:
    def test_valid_base64_with_padding(self):
        result = _Token68.parse("dGVzdA==")
        assert result is not None
        assert isinstance(result, _Token68)
        assert result.value == "dGVzdA=="

    def test_valid_no_padding(self):
        result = _Token68.parse("abc")
        assert result is not None
        assert result.value == "abc"

    def test_valid_all_body_chars(self):
        result = _Token68.parse("abc-def.ghi_jkl~mno+pqr/stu===")
        assert result is not None
        assert result.value == "abc-def.ghi_jkl~mno+pqr/stu==="

    def test_middle_equals_returns_none(self):
        assert _Token68.parse("abc=def") is None

    def test_empty_returns_none(self):
        assert _Token68.parse("") is None

    def test_padding_only_returns_none(self):
        assert _Token68.parse("=") is None
        assert _Token68.parse("==") is None

    def test_space_returns_none(self):
        assert _Token68.parse("abc def") is None

    def test_comma_returns_none(self):
        assert _Token68.parse("abc,def") is None

    def test_invalid_char_returns_none(self):
        assert _Token68.parse("abc!") is None

    @given(
        body=st.text(alphabet=_T68_BODY, min_size=1, max_size=20),
        pad=st.integers(0, 3),
    )
    def test_hypothesis_valid_values_parsed(self, body, pad):
        value = body + "=" * pad
        result = _Token68.parse(value)
        assert result is not None
        assert result.value == value


class TestToken68Constructor:
    def test_valid_value_accepted(self):
        t = _Token68("abc==")
        assert t.value == "abc=="

    def test_valid_no_padding(self):
        t = _Token68("abc")
        assert t.value == "abc"

    def test_invalid_value_raises(self):
        with pytest.raises((ValueError, Exception)):
            _Token68("abc=def")


# ---------------------------------------------------------------------------
# Pipeline: _parse_quoted_string
# ---------------------------------------------------------------------------

class TestParseQuotedStringHelper:
    def test_simple_content(self):
        # hdr[0] is the opening '"', start=1 is first content char
        hdr = '"hello"rest'
        tok, end = _parse_quoted_string(hdr, 1)
        assert tok.value == "hello"
        assert end == 7  # position after closing '"' at index 6

    def test_empty_content(self):
        hdr = '""rest'
        tok, end = _parse_quoted_string(hdr, 1)
        assert tok.value == ""
        assert end == 2

    def test_escaped_quote(self):
        hdr = '"a\\"b"rest'  # content: a"b
        tok, end = _parse_quoted_string(hdr, 1)
        assert tok.value == 'a"b'

    def test_escaped_backslash(self):
        hdr = '"a\\\\b"rest'  # content: a\b
        tok, end = _parse_quoted_string(hdr, 1)
        assert tok.value == "a\\b"

    def test_returns_quoted_string_instance(self):
        tok, _ = _parse_quoted_string('"hello"', 1)
        assert isinstance(tok, _QuotedString)

    def test_end_is_position_after_closing_quote(self):
        hdr = '"abc"xyz'
        _, end = _parse_quoted_string(hdr, 1)
        assert hdr[end:] == "xyz"

    def test_offset_into_larger_header(self):
        hdr = 'Basic realm="example"'
        # Opening '"' at index 12, content starts at 13
        tok, end = _parse_quoted_string(hdr, 13)
        assert tok.value == "example"
        assert hdr[end:] == ""  # nothing after closing '"'

    def test_unterminated_raises(self):
        with pytest.raises(ValueError):
            _parse_quoted_string('"hello', 1)

    def test_unterminated_escape_raises(self):
        hdr = '"hello\\'  # ends with backslash (unterminated escape)
        with pytest.raises(ValueError):
            _parse_quoted_string(hdr, 1)

    def test_invalid_control_char_raises(self):
        # Control characters other than HTAB and SP are not valid qdtext
        hdr = '"hel\x01lo"'
        with pytest.raises(ValueError):
            _parse_quoted_string(hdr, 1)


# ---------------------------------------------------------------------------
# Pipeline: _parse_quoted_strings
# ---------------------------------------------------------------------------

class TestParseQuotedStrings:
    def test_no_quotes_gives_unprocessed(self):
        result = _parse_quoted_strings("Bearer")
        assert len(result) == 1
        assert isinstance(result[0], _Unprocessed)
        assert result[0].value == "Bearer"

    def test_only_quoted_string(self):
        result = _parse_quoted_strings('"hello"')
        assert len(result) == 1
        assert isinstance(result[0], _QuotedString)
        assert result[0].value == "hello"

    def test_unprocessed_before_quoted(self):
        result = _parse_quoted_strings('abc "hello"')
        unp = [t for t in result if isinstance(t, _Unprocessed)]
        qts = [t for t in result if isinstance(t, _QuotedString)]
        assert len(qts) == 1
        assert qts[0].value == "hello"
        assert any("abc" in t.value for t in unp)

    def test_quoted_then_unprocessed(self):
        result = _parse_quoted_strings('"hello" abc')
        qts = [t for t in result if isinstance(t, _QuotedString)]
        assert qts[0].value == "hello"

    def test_multiple_quoted_strings(self):
        result = _parse_quoted_strings('"a" x "b"')
        qts = [t for t in result if isinstance(t, _QuotedString)]
        assert len(qts) == 2
        assert qts[0].value == "a"
        assert qts[1].value == "b"

    def test_unescapes_inside_quotes(self):
        result = _parse_quoted_strings(r'"a\"b"')
        qts = [t for t in result if isinstance(t, _QuotedString)]
        assert qts[0].value == 'a"b'

    def test_content_outside_quotes_stays_unprocessed(self):
        result = _parse_quoted_strings('a=b')
        assert all(isinstance(t, _Unprocessed) for t in result)

    def test_unclosed_quote_raises(self):
        with pytest.raises(ValueError):
            _parse_quoted_strings('"unclosed')

    def test_invalid_control_char_in_quoted_raises(self):
        # Control characters other than HTAB and SP are not valid qdtext
        with pytest.raises(ValueError):
            _parse_quoted_strings('"hel\x01lo"')

    def test_empty_string_does_not_raise(self):
        result = _parse_quoted_strings("")
        assert isinstance(result, list)

    def test_result_contains_only_unprocessed_or_quoted(self):
        result = _parse_quoted_strings('Bearer realm="example"')
        for tok in result:
            assert isinstance(tok, (_Unprocessed, _QuotedString))


# ---------------------------------------------------------------------------
# Pipeline: _parse_whitespace
# ---------------------------------------------------------------------------

class TestParseWhitespace:
    def test_splits_at_space(self):
        result = _parse_whitespace([_Unprocessed("a b")])
        unp = [t for t in result if isinstance(t, _Unprocessed)]
        assert [t.value for t in unp] == ["a", "b"]

    def test_splits_at_tab(self):
        result = _parse_whitespace([_Unprocessed("a\tb")])
        unp = [t for t in result if isinstance(t, _Unprocessed)]
        assert [t.value for t in unp] == ["a", "b"]

    def test_consecutive_spaces_collapsed(self):
        result = _parse_whitespace([_Unprocessed("a   b")])
        unp = [t for t in result if isinstance(t, _Unprocessed)]
        assert len(unp) == 2

    def test_leading_whitespace_discarded(self):
        result = _parse_whitespace([_Unprocessed("  abc")])
        assert len(result) == 1
        assert result[0].value == "abc"

    def test_trailing_whitespace_discarded(self):
        result = _parse_whitespace([_Unprocessed("abc  ")])
        assert len(result) == 1
        assert result[0].value == "abc"

    def test_quoted_string_passes_through_unchanged(self):
        qs = _QuotedString("hello world")
        result = _parse_whitespace([qs])
        assert result == [qs]

    def test_quoted_string_not_split_on_space(self):
        qs = _QuotedString("a b c")
        result = _parse_whitespace([qs])
        assert len(result) == 1
        assert result[0] is qs

    def test_mixed_unprocessed_and_quoted(self):
        qs = _QuotedString("q")
        result = _parse_whitespace([_Unprocessed("a b"), qs, _Unprocessed("c d")])
        quoted = [t for t in result if isinstance(t, _QuotedString)]
        unproc = [t for t in result if isinstance(t, _Unprocessed)]
        assert len(quoted) == 1
        assert quoted[0] is qs
        assert len(unproc) == 4  # "a", "b", "c", "d"

    def test_only_whitespace_produces_nothing(self):
        result = _parse_whitespace([_Unprocessed("   ")])
        unp = [t for t in result if isinstance(t, _Unprocessed)]
        assert len(unp) == 0


# ---------------------------------------------------------------------------
# Pipeline: _parse_commas
# ---------------------------------------------------------------------------

class TestParseCommas:
    def test_comma_becomes_singleton(self):
        result = _parse_commas([_Unprocessed("a,b")])
        commas = [t for t in result if t is _COMMA]
        assert len(commas) == 1

    def test_splits_around_comma(self):
        result = _parse_commas([_Unprocessed("a,b")])
        unp = [t for t in result if isinstance(t, _Unprocessed)]
        assert [t.value for t in unp] == ["a", "b"]

    def test_multiple_commas(self):
        result = _parse_commas([_Unprocessed("a,b,c")])
        commas = [t for t in result if t is _COMMA]
        assert len(commas) == 2

    def test_consecutive_commas_combined(self):
        result = _parse_commas([_Unprocessed("a,,b")])
        commas = [t for t in result if t is _COMMA]
        assert len(commas) == 1

    def test_quoted_string_not_split_at_comma(self):
        qs = _QuotedString("a,b")
        result = _parse_commas([qs])
        assert result == [qs]

    def test_quoted_string_comma_not_singleton(self):
        qs = _QuotedString("a,b")
        result = _parse_commas([qs])
        commas = [t for t in result if t is _COMMA]
        assert len(commas) == 0

    def test_leading_comma_removed(self):
        result = _parse_commas([_Unprocessed(",a")])
        # First element should not be _COMMA
        if result:
            assert result[0] is not _COMMA

    def test_result_comma_is_the_singleton(self):
        result = _parse_commas([_Unprocessed("a,b")])
        for tok in result:
            if tok is _COMMA:
                assert tok is _COMMA


# ---------------------------------------------------------------------------
# Pipeline: _parse_equals
# ---------------------------------------------------------------------------

class TestParseEquals:
    def test_trailing_padding_at_end_becomes_token68(self):
        tokens = [_Unprocessed("abc=")]
        result = _parse_equals(tokens)
        assert isinstance(result[0], _Token68)
        assert result[0].value == "abc="

    def test_trailing_padding_before_comma_becomes_token68(self):
        tokens = [_Unprocessed("abc="), _COMMA, _Unprocessed("x")]
        result = _parse_equals(tokens)
        assert isinstance(result[0], _Token68)

    def test_middle_equals_splits(self):
        tokens = [_Unprocessed("key=value")]
        result = _parse_equals(tokens)
        unp = [t for t in result if isinstance(t, _Unprocessed)]
        eq = [t for t in result if t is _EQUALS]
        assert len(eq) == 1
        assert unp[0].value == "key"
        assert unp[1].value == "value"

    def test_no_equals_stays_unprocessed(self):
        tokens = [_Unprocessed("Bearer")]
        result = _parse_equals(tokens)
        assert isinstance(result[0], _Unprocessed)
        assert result[0].value == "Bearer"

    def test_unpadded_value_stays_unprocessed(self):
        # "abc" with no '=' is indistinguishable from a scheme — left for later
        tokens = [_Unprocessed("abc")]
        result = _parse_equals(tokens)
        assert isinstance(result[0], _Unprocessed)

    def test_quoted_string_passes_through(self):
        qs = _QuotedString("key=value")
        tokens = [qs]
        result = _parse_equals(tokens)
        assert result == [qs]

    def test_result_equals_is_the_singleton(self):
        tokens = [_Unprocessed("k=v")]
        result = _parse_equals(tokens)
        eq_tokens = [t for t in result if t is _EQUALS]
        assert len(eq_tokens) == 1
        assert eq_tokens[0] is _EQUALS

    def test_multiple_padding_chars(self):
        tokens = [_Unprocessed("abc==")]
        result = _parse_equals(tokens)
        assert isinstance(result[0], _Token68)
        assert result[0].value == "abc=="


# ---------------------------------------------------------------------------
# Pipeline: _parse_unprocessed
# ---------------------------------------------------------------------------

class TestParseUnprocessed:
    def test_first_token_becomes_unquoted_string(self):
        tokens = [_Unprocessed("Bearer")]
        result = _parse_unprocessed(tokens)
        assert isinstance(result[0], _UnquotedString)
        assert result[0].value == "Bearer"

    def test_unprocessed_after_unprocessed_at_end_becomes_token68(self):
        # scheme "Bearer" then token68 "dGVzdA" at end of list
        tokens = [_Unprocessed("Bearer"), _Unprocessed("dGVzdA")]
        result = _parse_unprocessed(tokens)
        assert isinstance(result[0], _UnquotedString)
        assert isinstance(result[1], _Token68)
        assert result[1].value == "dGVzdA"

    def test_unprocessed_after_unprocessed_before_comma_becomes_token68(self):
        tokens = [_Unprocessed("Bearer"), _Unprocessed("dGVzdA"), _COMMA]
        result = _parse_unprocessed(tokens)
        assert isinstance(result[1], _Token68)

    def test_unprocessed_after_unprocessed_before_equals_stays_unquoted(self):
        # "Basic realm =example": "realm" precedes _EQUALS, not _COMMA/end
        tokens = [
            _Unprocessed("Basic"),
            _Unprocessed("realm"),
            _EQUALS,
            _Unprocessed("example"),
        ]
        result = _parse_unprocessed(tokens)
        assert isinstance(result[1], _UnquotedString)  # param name
        assert isinstance(result[3], _UnquotedString)  # param value

    def test_unprocessed_after_comma_becomes_unquoted(self):
        # After _COMMA, the next _Unprocessed is a new scheme, not token68
        tokens = [_Unprocessed("Bearer"), _COMMA, _Unprocessed("Basic")]
        result = _parse_unprocessed(tokens)
        assert isinstance(result[2], _UnquotedString)
        assert result[2].value == "Basic"

    def test_already_classified_tokens_pass_through(self):
        t68 = _Token68("abc=")
        qs = _QuotedString("hello")
        tokens = [_Unprocessed("x"), t68, qs, _COMMA, _EQUALS]
        result = _parse_unprocessed(tokens)
        assert result[1] is t68
        assert result[2] is qs
        assert result[3] is _COMMA
        assert result[4] is _EQUALS

    def test_no_remaining_unprocessed_in_output(self):
        tokens = [_Unprocessed("Bearer"), _Unprocessed("dGVzdA")]
        result = _parse_unprocessed(tokens)
        assert not any(isinstance(t, _Unprocessed) for t in result)

    def test_invalid_token68_context_raises(self):
        # "!" is not a token68 body char; classified as token68 → ValueError
        tokens = [_Unprocessed("Bearer"), _Unprocessed("invalid!")]
        with pytest.raises(ValueError):
            _parse_unprocessed(tokens)

    def test_invalid_tchar_in_unquoted_context_raises(self):
        # "@" is not a tchar → invalid _UnquotedString
        tokens = [_Unprocessed("inv@lid")]
        with pytest.raises(ValueError):
            _parse_unprocessed(tokens)


# ---------------------------------------------------------------------------
# Pipeline: _parse_params
# ---------------------------------------------------------------------------

class TestParseParams:
    def test_single_quoted_param(self):
        tokens = [_UnquotedString("realm"), _EQUALS, _QuotedString("example")]
        ptr = _ListPointer(tokens)
        result = _parse_params(ptr)
        assert result == {"realm": "example"}

    def test_single_unquoted_param(self):
        tokens = [_UnquotedString("algorithm"), _EQUALS, _UnquotedString("MD5")]
        ptr = _ListPointer(tokens)
        result = _parse_params(ptr)
        assert result == {"algorithm": "MD5"}

    def test_multiple_params(self):
        tokens = [
            _UnquotedString("realm"), _EQUALS, _QuotedString("example"),
            _COMMA,
            _UnquotedString("charset"), _EQUALS, _QuotedString("UTF-8"),
        ]
        ptr = _ListPointer(tokens)
        result = _parse_params(ptr)
        assert result == {"realm": "example", "charset": "UTF-8"}

    def test_param_name_lowercased(self):
        tokens = [_UnquotedString("Realm"), _EQUALS, _QuotedString("example")]
        ptr = _ListPointer(tokens)
        result = _parse_params(ptr)
        assert "realm" in result
        assert result["realm"] == "example"

    def test_param_value_case_preserved(self):
        tokens = [_UnquotedString("realm"), _EQUALS, _QuotedString("MyRealm")]
        ptr = _ListPointer(tokens)
        result = _parse_params(ptr)
        assert result["realm"] == "MyRealm"

    def test_ptr_past_end_after_last_param(self):
        tokens = [_UnquotedString("realm"), _EQUALS, _QuotedString("x")]
        ptr = _ListPointer(tokens)
        _parse_params(ptr)
        assert not ptr.valid

    def test_stops_at_challenge_separator(self):
        # "realm=x, Bearer": the comma before "Bearer" has no '=' two ahead
        tokens = [
            _UnquotedString("realm"), _EQUALS, _QuotedString("x"),
            _COMMA,
            _UnquotedString("Bearer"),
        ]
        ptr = _ListPointer(tokens)
        result = _parse_params(ptr)
        assert result == {"realm": "x"}
        # ptr should point at "Bearer"
        assert ptr.valid
        assert isinstance(ptr[0], _UnquotedString)
        assert ptr[0].value == "Bearer"

    def test_many_params(self):
        tokens = [
            _UnquotedString("realm"), _EQUALS, _QuotedString("r"),
            _COMMA,
            _UnquotedString("nonce"), _EQUALS, _QuotedString("n"),
            _COMMA,
            _UnquotedString("algorithm"), _EQUALS, _UnquotedString("MD5"),
        ]
        ptr = _ListPointer(tokens)
        result = _parse_params(ptr)
        assert result == {"realm": "r", "nonce": "n", "algorithm": "MD5"}

    def test_missing_equals_raises(self):
        # Name present but no _EQUALS follows it
        tokens = [_UnquotedString("realm"), _UnquotedString("example")]
        ptr = _ListPointer(tokens)
        with pytest.raises(ValueError):
            _parse_params(ptr)

    def test_missing_value_after_equals_raises(self):
        # _EQUALS present but no value token follows it
        tokens = [_UnquotedString("realm"), _EQUALS]
        ptr = _ListPointer(tokens)
        with pytest.raises(ValueError):
            _parse_params(ptr)


# ---------------------------------------------------------------------------
# Pipeline: _parse_challenge
# ---------------------------------------------------------------------------

class TestParseChallenge:
    def test_bare_scheme(self):
        tokens = [_UnquotedString("Bearer")]
        ptr = _ListPointer(tokens)
        c = _parse_challenge(ptr)
        assert c == Challenge("bearer")

    def test_bare_scheme_ptr_past_end(self):
        tokens = [_UnquotedString("Bearer")]
        ptr = _ListPointer(tokens)
        _parse_challenge(ptr)
        assert not ptr.valid

    def test_scheme_with_token68(self):
        tokens = [_UnquotedString("Bearer"), _Token68("dGVzdA==")]
        ptr = _ListPointer(tokens)
        c = _parse_challenge(ptr)
        assert c == Challenge("bearer", token="dGVzdA==")

    def test_scheme_with_quoted_param(self):
        tokens = [
            _UnquotedString("Basic"),
            _UnquotedString("realm"), _EQUALS, _QuotedString("example"),
        ]
        ptr = _ListPointer(tokens)
        c = _parse_challenge(ptr)
        assert c == Challenge("basic", params={"realm": "example"})

    def test_scheme_with_unquoted_param(self):
        tokens = [
            _UnquotedString("Bearer"),
            _UnquotedString("max-age"), _EQUALS, _UnquotedString("3600"),
        ]
        ptr = _ListPointer(tokens)
        c = _parse_challenge(ptr)
        assert c == Challenge("bearer", params={"max-age": "3600"})

    def test_scheme_normalized_to_lowercase(self):
        tokens = [_UnquotedString("BEARER")]
        ptr = _ListPointer(tokens)
        c = _parse_challenge(ptr)
        assert c.scheme == "bearer"

    def test_advances_ptr_to_next_scheme(self):
        # [Bearer] [,] [Basic] — after parsing Bearer, ptr at Basic
        tokens = [
            _UnquotedString("Bearer"),
            _COMMA,
            _UnquotedString("Basic"),
        ]
        ptr = _ListPointer(tokens)
        c1 = _parse_challenge(ptr)
        assert c1 == Challenge("bearer")
        assert ptr.valid
        assert ptr[0].value == "Basic"

    def test_two_consecutive_challenges(self):
        tokens = [
            _UnquotedString("Bearer"),
            _COMMA,
            _UnquotedString("Basic"),
        ]
        ptr = _ListPointer(tokens)
        c1 = _parse_challenge(ptr)
        c2 = _parse_challenge(ptr)
        assert c1 == Challenge("bearer")
        assert c2 == Challenge("basic")
        assert not ptr.valid


# ---------------------------------------------------------------------------
# Pipeline: _parse_challenges
# ---------------------------------------------------------------------------

class TestParseChallenges:
    def test_empty_token_list(self):
        result = _parse_challenges([])
        assert result == []

    def test_single_bare_scheme(self):
        tokens = [_UnquotedString("Bearer")]
        assert _parse_challenges(tokens) == [Challenge("bearer")]

    def test_single_scheme_with_token68(self):
        tokens = [_UnquotedString("Negotiate"), _Token68("AAAA==")]
        result = _parse_challenges(tokens)
        assert result == [Challenge("negotiate", token="AAAA==")]

    def test_single_scheme_with_params(self):
        tokens = [
            _UnquotedString("Basic"),
            _UnquotedString("realm"), _EQUALS, _QuotedString("example"),
        ]
        result = _parse_challenges(tokens)
        assert result == [Challenge("basic", params={"realm": "example"})]

    def test_two_bare_schemes(self):
        tokens = [_UnquotedString("Bearer"), _COMMA, _UnquotedString("Basic")]
        result = _parse_challenges(tokens)
        assert result == [Challenge("bearer"), Challenge("basic")]

    def test_three_bare_schemes(self):
        tokens = [
            _UnquotedString("Bearer"), _COMMA,
            _UnquotedString("Basic"), _COMMA,
            _UnquotedString("Negotiate"),
        ]
        result = _parse_challenges(tokens)
        assert len(result) == 3
        assert [c.scheme for c in result] == ["bearer", "basic", "negotiate"]

    def test_mixed_token68_and_params(self):
        tokens = [
            _UnquotedString("Bearer"), _Token68("dGVzdA=="),
            _COMMA,
            _UnquotedString("Basic"),
            _UnquotedString("realm"), _EQUALS, _QuotedString("example"),
        ]
        result = _parse_challenges(tokens)
        assert len(result) == 2
        assert result[0] == Challenge("bearer", token="dGVzdA==")
        assert result[1] == Challenge("basic", params={"realm": "example"})

    def test_result_is_list_of_challenge_instances(self):
        tokens = [_UnquotedString("Bearer"), _COMMA, _UnquotedString("Basic")]
        result = _parse_challenges(tokens)
        assert all(isinstance(c, Challenge) for c in result)

    def test_schemes_lowercased(self):
        tokens = [_UnquotedString("BEARER"), _COMMA, _UnquotedString("BASIC")]
        result = _parse_challenges(tokens)
        assert result[0].scheme == "bearer"
        assert result[1].scheme == "basic"

    def test_token68_followed_by_non_comma_raises(self):
        # token68 data must be followed by a comma or end of token list;
        # anything else is a structural error.
        tokens = [_UnquotedString("Bearer"), _Token68("dGVzdA=="), _UnquotedString("extra")]
        with pytest.raises(ValueError):
            _parse_challenges(tokens)

    def test_listptr_iadd_isub_nonint_raises(self):
        # Kind of silly, but this gets us to 100% coverage
        lp = _ListPointer(())
        with pytest.raises(TypeError):
            lp += None
        with pytest.raises(TypeError):
            lp -= None


def _pipeline(hdr: str) -> list:
    """Run the full tokenizing pipeline through _parse_unprocessed."""
    tokens = _parse_quoted_strings(hdr)
    tokens = _parse_whitespace(tokens)
    tokens = _parse_commas(tokens)
    tokens = _parse_equals(tokens)
    tokens = _parse_unprocessed(tokens)
    return tokens


def _challenges(hdr: str) -> list:
    """Run the full pipeline, through structural analysis into challenges."""
    return _parse_challenges(_pipeline(hdr))


@pytest.mark.parametrize(
    "hdr, expected",
    [
        # Degenerate inputs
        ("", []),
        ("nogap", [_Unprocessed("nogap")]),
        ('""', [_QuotedString("")]),
        # Single quoted string, various positions
        ('realm="foo"', [_Unprocessed("realm="), _QuotedString("foo")]),
        ('"lead"tail', [_QuotedString("lead"), _Unprocessed("tail")]),
        ('a="b"c', [_Unprocessed("a="), _QuotedString("b"), _Unprocessed("c")]),
        # A trailing quoted string leaves no trailing _Unprocessed token.
        ('a="b"', [_Unprocessed("a="), _QuotedString("b")]),
        # Adjacent quoted strings emit no empty _Unprocessed between them
        ('"a""b"', [_QuotedString("a"), _QuotedString("b")]),
        # Multiple params
        (
            'realm="foo", service="bar"',
            [
                _Unprocessed("realm="),
                _QuotedString("foo"),
                _Unprocessed(", service="),
                _QuotedString("bar"),
            ],
        ),
        # Quoted-pairs are unescaped (quotes stripped, '\X' -> 'X')
        # An escaped quote does not end the string; it decodes to '"'.
        (r'x="a\"b"', [_Unprocessed("x="), _QuotedString('a"b')]),
        # An escaped backslash decodes to a single backslash.
        (r'"a\\b"', [_QuotedString("a\\b")]),
        # A backslash before an ordinary char decodes to just that char.
        (r'"a\nb"', [_QuotedString("anb")]),
        # A well-formed trailing backslash (escaped) ends the content with one.
        (r'"foo\\"', [_QuotedString("foo\\")]),
        # A comma inside quotes is content, not a separator
        (
            'scope="a:b:pull,push"',
            [_Unprocessed("scope="), _QuotedString("a:b:pull,push")],
        ),
        # Realistic Docker Hub challenge
        (
            'Bearer realm="https://auth.docker.io/token",'
            'service="registry.docker.io",'
            'scope="repository:library/ubuntu:pull"',
            [
                _Unprocessed("Bearer realm="),
                _QuotedString("https://auth.docker.io/token"),
                _Unprocessed(",service="),
                _QuotedString("registry.docker.io"),
                _Unprocessed(",scope="),
                _QuotedString("repository:library/ubuntu:pull"),
            ],
        ),
    ],
)
def test_parse_quoted_strings(hdr: str, expected: list) -> None:
    assert _parse_quoted_strings(hdr) == expected


@pytest.mark.parametrize(
    "hdr",
    [
        'realm="foo',       # opening quote, never closed
        '"unterminated',    # bare unterminated quote
        'a="b"c="d',        # second quoted string never closes
        '"foo\\',           # single trailing backslash escapes nothing
        'x="a\\"',          # trailing \" is an escaped quote, so no real close
    ],
)
def test_parse_quoted_strings_unterminated(hdr: str) -> None:
    with pytest.raises(ValueError):
        _parse_quoted_strings(hdr)


@pytest.mark.parametrize(
    "hdr",
    [
        '"a\nb"',       # a raw control char (LF) inside the quotes
        '"a\\\nb"',     # an escaped control char: \<LF> decodes to LF
        '"x\x7f"',      # a raw DEL
        '"x\\\x7f"',    # an escaped DEL: \<DEL> decodes to DEL
    ],
)
def test_parse_quoted_strings_invalid_char(hdr: str) -> None:
    with pytest.raises(ValueError):
        _parse_quoted_strings(hdr)


@pytest.mark.parametrize(
    "tokens, expected",
    [
        # Empty input
        ([], []),
        # No whitespace -> unchanged
        ([_Unprocessed("realm=")], [_Unprocessed("realm=")]),
        # A whitespace-only run vanishes entirely
        ([_Unprocessed(" \t ")], []),
        # Leading, internal, and trailing whitespace are all discarded
        ([_Unprocessed("  a  b  ")], [_Unprocessed("a"), _Unprocessed("b")]),
        # Tab counts as whitespace
        ([_Unprocessed("a\tb")], [_Unprocessed("a"), _Unprocessed("b")]),
        # Newline is NOT whitespace; it stays in the _Unprocessed run
        ([_Unprocessed("a\nb")], [_Unprocessed("a\nb")]),
        # Already-classified tokens pass through unchanged
        (
            [_QuotedString("a b"), _Unprocessed("x y")],
            [_QuotedString("a b"), _Unprocessed("x"), _Unprocessed("y")],
        ),
    ],
)
def test_parse_whitespace(tokens: list, expected: list) -> None:
    assert _parse_whitespace(tokens) == expected


@pytest.mark.parametrize(
    "hdr, expected",
    [
        ("", []),
        # The scheme is separated from the first parameter by adjacency alone
        (
            'Bearer realm="x"',
            [_Unprocessed("Bearer"), _Unprocessed("realm="), _QuotedString("x")],
        ),
        # Whitespace inside a quoted value is preserved, not removed
        ('a="x y"', [_Unprocessed("a="), _QuotedString("x y")]),
        # A space following a comma separator is discarded
        (
            'a="1", b="2"',
            [
                _Unprocessed("a="),
                _QuotedString("1"),
                _Unprocessed(","),
                _Unprocessed("b="),
                _QuotedString("2"),
            ],
        ),
    ],
)
def test_quoted_then_whitespace(hdr: str, expected: list) -> None:
    assert _parse_whitespace(_parse_quoted_strings(hdr)) == expected


@pytest.mark.parametrize(
    "tokens, expected",
    [
        # Empty input
        ([], []),
        # No comma -> unchanged
        ([_Unprocessed("realm")], [_Unprocessed("realm")]),
        # A lone comma
        ([_Unprocessed(",")], []),
        # _Comma between text
        ([_Unprocessed("a,b")], [_Unprocessed("a"), _Comma(), _Unprocessed("b")]),
        # Consecutive commas are combined
        ([_Unprocessed("a,,b")], [_Unprocessed("a"), _Comma(), _Unprocessed("b")]),
        # Leading comma is removed; trailing comma remains
        ([_Unprocessed(",x")], [_Unprocessed("x")]),
        ([_Unprocessed("x,")], [_Unprocessed("x"), _Comma()]),
        # '=' is left untouched (resolved with token68 in a later step)
        ([_Unprocessed("realm=")], [_Unprocessed("realm=")]),
        # token68 '==' padding is not split
        ([_Unprocessed("abc123==")], [_Unprocessed("abc123==")]),
        # Already-classified tokens pass through; a comma inside a _QuotedString
        # stays part of it
        (
            [_QuotedString("a,b"), _Unprocessed("x,y")],
            [
                _QuotedString("a,b"),
                _Unprocessed("x"),
                _Comma(),
                _Unprocessed("y"),
            ],
        ),
    ],
)
def test_parse_commas(tokens: list, expected: list) -> None:
    assert _parse_commas(tokens) == expected


@pytest.mark.parametrize(
    "tokens, expected",
    [
        # Empty input
        ([], []),
        # No '=' -> unchanged
        ([_Unprocessed("Bearer")], [_Unprocessed("Bearer")]),
        # '=' inside a _QuotedString is untouched
        ([_QuotedString("a=b")], [_QuotedString("a=b")]),
        # Separator with a following quoted value
        (
            [_Unprocessed("realm="), _QuotedString("x")],
            [_Unprocessed("realm"), _Equals(), _QuotedString("x")],
        ),
        # Separator with an unquoted value in the same run
        ([_Unprocessed("a=b")], [_Unprocessed("a"), _Equals(), _Unprocessed("b")]),
        # Multiple '=' in a run each become a separator
        (
            [_Unprocessed("a=b=c")],
            [
                _Unprocessed("a"),
                _Equals(),
                _Unprocessed("b"),
                _Equals(),
                _Unprocessed("c"),
            ],
        ),
        # token68 at end of input, and followed by a comma
        ([_Unprocessed("abc==")], [_Token68("abc==")]),
        ([_Unprocessed("abc=="), _Comma()], [_Token68("abc=="), _Comma()]),
        # A trailing '=' with a comma after (no value) is treated as token68
        ([_Unprocessed("realm="), _Comma()], [_Token68("realm="), _Comma()]),
        # A lone '=' run (as left by BWS around '=') becomes _Equals; value
        # follows in the next token
        (
            [_Unprocessed("realm"), _Unprocessed("="), _QuotedString("x")],
            [_Unprocessed("realm"), _Equals(), _QuotedString("x")],
        ),
        # Multi-challenge: _Token68 and _Equals resolved in the same list
        (
            [
                _Unprocessed("Negotiate"),
                _Unprocessed("abc=="),
                _Comma(),
                _Unprocessed("Bearer"),
                _Unprocessed("realm="),
                _QuotedString("x"),
            ],
            [
                _Unprocessed("Negotiate"),
                _Token68("abc=="),
                _Comma(),
                _Unprocessed("Bearer"),
                _Unprocessed("realm"),
                _Equals(),
                _QuotedString("x"),
            ],
        ),
    ],
)
def test_parse_equals(tokens: list, expected: list) -> None:
    assert _parse_equals(tokens) == expected


@pytest.mark.parametrize(
    "tokens, expected",
    [
        # Empty input
        ([], []),
        # A lone token (bare scheme) is never a token68
        ([_Unprocessed("Basic")], [_UnquotedString("Basic")]),
        # scheme + padding-less token68 at the end of the list
        (
            [_Unprocessed("Negotiate"), _Unprocessed("abc")],
            [_UnquotedString("Negotiate"), _Token68("abc")],
        ),
        # padding-less token68 followed by a comma
        (
            [_Unprocessed("Negotiate"), _Unprocessed("abc"), _Comma()],
            [_UnquotedString("Negotiate"), _Token68("abc"), _Comma()],
        ),
        # A name (followed by _Equals) is not a token68
        (
            [_Unprocessed("Bearer"), _Unprocessed("realm"), _Equals()],
            [_UnquotedString("Bearer"), _UnquotedString("realm"), _Equals()],
        ),
        # An unquoted value (preceded by _Equals) is not a token68, even at end
        (
            [_Unprocessed("k"), _Equals(), _Unprocessed("v")],
            [_UnquotedString("k"), _Equals(), _UnquotedString("v")],
        ),
        # A bare scheme after a comma is not a token68 (preceded by _Comma)
        (
            [_Unprocessed("x"), _Comma(), _Unprocessed("Basic")],
            [_UnquotedString("x"), _Comma(), _UnquotedString("Basic")],
        ),
        # Already-classified tokens are left untouched
        (
            [_QuotedString("v"), _Token68("abc==")],
            [_QuotedString("v"), _Token68("abc==")],
        ),
    ],
)
def test_parse_unprocessed(tokens: list, expected: list) -> None:
    assert _parse_unprocessed(tokens) == expected


@pytest.mark.parametrize(
    "tokens",
    [
        # A positional token68 whose value isn't valid token68 characters
        [_Unprocessed("Negotiate"), _Unprocessed("foo:bar")],
        # A bare scheme (or name) with a non-tchar character
        [_Unprocessed("foo:bar")],
        # A param name with an invalid character
        [_Unprocessed("Bearer"), _Unprocessed("re:lm"), _Equals()],
    ],
)
def test_parse_unprocessed_invalid(tokens: list) -> None:
    with pytest.raises(ValueError):
        _parse_unprocessed(tokens)


@pytest.mark.parametrize(
    "hdr, expected",
    [
        ("", []),
        # Realistic Docker Hub Bearer challenge
        (
            'Bearer realm="https://auth.docker.io/token",'
            'service="registry.docker.io",'
            'scope="repository:library/ubuntu:pull"',
            [
                _UnquotedString("Bearer"),
                _UnquotedString("realm"),
                _Equals(),
                _QuotedString("https://auth.docker.io/token"),
                _Comma(),
                _UnquotedString("service"),
                _Equals(),
                _QuotedString("registry.docker.io"),
                _Comma(),
                _UnquotedString("scope"),
                _Equals(),
                _QuotedString("repository:library/ubuntu:pull"),
            ],
        ),
        # token68 challenge: scheme -> _UnquotedString, credential -> _Token68
        (
            "Negotiate abc123==",
            [_UnquotedString("Negotiate"), _Token68("abc123==")],
        ),
        # Multi-challenge: a token68 challenge alongside a Bearer challenge
        (
            'Negotiate abc123==, Bearer realm="x"',
            [
                _UnquotedString("Negotiate"),
                _Token68("abc123=="),
                _Comma(),
                _UnquotedString("Bearer"),
                _UnquotedString("realm"),
                _Equals(),
                _QuotedString("x"),
            ],
        ),
        # A comma inside a quoted value is preserved; the separator outside is
        # split out; '=' becomes _Equals
        (
            'a="x,y", b="z"',
            [
                _UnquotedString("a"),
                _Equals(),
                _QuotedString("x,y"),
                _Comma(),
                _UnquotedString("b"),
                _Equals(),
                _QuotedString("z"),
            ],
        ),
    ],
)
def test_full_pipeline(hdr: str, expected: list) -> None:
    assert _pipeline(hdr) == expected


@pytest.mark.parametrize(
    "hdr",
    [
        "Negotiate foo:bar",    # invalid token68 credential
        "Bearer re:lm=x",       # invalid param name (':' is not a tchar)
    ],
)
def test_full_pipeline_raises(hdr: str) -> None:
    with pytest.raises(ValueError):
        _pipeline(hdr)


def test_token_equality() -> None:
    assert _QuotedString("a") == _QuotedString("a")
    assert _QuotedString("a") != _QuotedString("b")
    assert _QuotedString("a") != _Unprocessed("a")   # same value, different type
    assert _Unprocessed("a") != "a"                  # not equal to a bare str


@pytest.mark.parametrize(
    "value",
    ["abc", "abc==", "dGVzdA==", "realm=", "a-b_c.d~e+f/g", "A1=="],
)
def test_token68_valid(value: str) -> None:
    assert _Token68(value).value == value


@pytest.mark.parametrize(
    "value",
    [
        "foo:bar",  # ':' is not a token68 character
        "a!b",      # '!' is a tchar but not a token68 character
        "a=b",      # '=' is only allowed as trailing padding
        "===",      # no characters before the padding
        "",         # empty
    ],
)
def test_token68_invalid(value: str) -> None:
    with pytest.raises(ValueError):
        _Token68(value)


@pytest.mark.parametrize(
    "value",
    ["Bearer", "realm", "MD5", "a.b-c_d", "!#$%&'*+-.^_`|~"],
)
def test_unquoted_string_valid(value: str) -> None:
    assert _UnquotedString(value).value == value


@pytest.mark.parametrize(
    "value",
    [
        "foo:bar",  # ':' is not a tchar
        "a/b",      # '/' is a token68 character but not a tchar
        "a b",      # space is not a tchar
        "a=b",      # '=' is not a tchar
        "",         # empty
    ],
)
def test_unquoted_string_invalid(value: str) -> None:
    with pytest.raises(ValueError):
        _UnquotedString(value)


@pytest.mark.parametrize(
    "value",
    [
        "",                 # an empty quoted string is valid
        "hello world",      # SP is allowed
        "a\tb",             # HTAB is allowed
        'a"b\\c',           # '"' and '\' appear in a decoded value
        "colon:slash/comma,",  # any VCHAR is allowed inside quotes
        "\x80\xa0\xff",     # obs-text (0x80-0xFF) is allowed
    ],
)
def test_quoted_string_valid(value: str) -> None:
    assert _QuotedString(value).value == value


@pytest.mark.parametrize(
    "value",
    [
        "a\nb",     # LF (a C0 control)
        "a\rb",     # CR (a C0 control)
        "a\x00b",   # NUL
        "a\x1fb",   # 0x1F, the last C0 control
        "a\x7fb",   # DEL
    ],
)
def test_quoted_string_invalid(value: str) -> None:
    with pytest.raises(ValueError):
        _QuotedString(value)


@pytest.mark.parametrize(
    "tokens, expected",
    [
        # Empty input
        ([], []),
        # A bare scheme (normalized to lowercase)
        ([_UnquotedString("Basic")], [Challenge("basic")]),
        # A token68 credential (case-sensitive value left as-is)
        (
            [_UnquotedString("Negotiate"), _Token68("abc123==")],
            [Challenge("negotiate", token="abc123==")],
        ),
        # A single auth-param; scheme and name lowercased, value preserved
        (
            [_UnquotedString("Bearer"), _UnquotedString("Realm"),
             _Equals(), _QuotedString("x")],
            [Challenge("bearer", params={"realm": "x"})],
        ),
        # Multiple auth-params
        (
            [_UnquotedString("Bearer"),
             _UnquotedString("realm"), _Equals(), _QuotedString("x"),
             _Comma(),
             _UnquotedString("service"), _Equals(), _QuotedString("y")],
            [Challenge("bearer", params={"realm": "x", "service": "y"})],
        ),
        # An unquoted param value
        (
            [_UnquotedString("Digest"), _UnquotedString("a"),
             _Equals(), _UnquotedString("b")],
            [Challenge("digest", params={"a": "b"})],
        ),
        # Two bare schemes
        (
            [_UnquotedString("Basic"), _Comma(), _UnquotedString("Negotiate")],
            [Challenge("basic"), Challenge("negotiate")],
        ),
        # A token68 challenge alongside a param challenge
        (
            [_UnquotedString("Negotiate"), _Token68("abc=="),
             _Comma(),
             _UnquotedString("Bearer"), _UnquotedString("realm"),
             _Equals(), _QuotedString("x")],
            [
                Challenge("negotiate", token="abc=="),
                Challenge("bearer", params={"realm": "x"}),
            ],
        ),
    ],
)
def test_parse_challenges(tokens: list, expected: list) -> None:
    assert _parse_challenges(tokens) == expected


@pytest.mark.parametrize(
    "tokens",
    [
        # Does not begin with a scheme
        [_Equals()],
        [_QuotedString("x")],
        # A token68 with no preceding scheme
        [_Token68("abc==")],
        # A parameter name not followed by '='
        [_UnquotedString("Bearer"), _UnquotedString("realm")],
        # '=' with no value
        [_UnquotedString("Bearer"), _UnquotedString("realm"), _Equals()],
        # A value that is neither a token nor a quoted string
        [_UnquotedString("Bearer"), _UnquotedString("realm"),
         _Equals(), _Token68("x==")],
        # Two params with no comma between them
        [_UnquotedString("Bearer"),
         _UnquotedString("realm"), _Equals(), _QuotedString("x"),
         _UnquotedString("service"), _Equals(), _QuotedString("y")],
        # A duplicate parameter name (matched case-insensitively)
        [_UnquotedString("Bearer"),
         _UnquotedString("realm"), _Equals(), _QuotedString("x"),
         _Comma(),
         _UnquotedString("Realm"), _Equals(), _QuotedString("y")],
        # Trailing junk after a token68
        [_UnquotedString("Negotiate"), _Token68("abc=="), _Token68("def==")],
    ],
)
def test_parse_challenges_invalid(tokens: list) -> None:
    with pytest.raises(ValueError):
        _parse_challenges(tokens)


@pytest.mark.parametrize(
    "hdr, expected",
    [
        ("", []),
        # Realistic Docker Hub Bearer challenge
        (
            'Bearer realm="https://auth.docker.io/token",'
            'service="registry.docker.io",'
            'scope="repository:library/ubuntu:pull"',
            [
                Challenge("bearer", params={
                    "realm": "https://auth.docker.io/token",
                    "service": "registry.docker.io",
                    "scope": "repository:library/ubuntu:pull",
                }),
            ],
        ),
        # token68 challenge
        ("Negotiate abc123==", [Challenge("negotiate", token="abc123==")]),
        # Multi-challenge: token68 alongside Bearer
        (
            'Negotiate abc123==, Bearer realm="x"',
            [
                Challenge("negotiate", token="abc123=="),
                Challenge("bearer", params={"realm": "x"}),
            ],
        ),
        # Unquoted values
        ("Digest a=b, c=d", [Challenge("digest", params={"a": "b", "c": "d"})]),
        # Scheme and names normalized to lowercase; values are not
        ('BEARER REALM="X"', [Challenge("bearer", params={"realm": "X"})]),
        # Empty list elements around a challenge are ignored
        (',Bearer realm="x",', [Challenge("bearer", params={"realm": "x"})]),
    ],
)
def test_parse_challenges_pipeline(hdr: str, expected: list) -> None:
    assert _challenges(hdr) == expected


@pytest.mark.parametrize(
    "hdr",
    [
        'Bearer realm="x" service="y"',  # missing comma between params
        'Bearer realm="x", realm="y"',   # duplicate parameter name
        "Bearer =x",                     # parameter with no name
    ],
)
def test_parse_challenges_pipeline_raises(hdr: str) -> None:
    with pytest.raises(ValueError):
        _challenges(hdr)
