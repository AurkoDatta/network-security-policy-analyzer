import pytest

from src.parsers.exceptions import ParserError, parse_json_or_yaml, validate_size


def test_validate_size_passes_under_limit():
    validate_size(b"x" * 100, max_bytes=1000)


def test_validate_size_raises_over_limit():
    with pytest.raises(ParserError, match="exceeds maximum size"):
        validate_size(b"x" * 1001, max_bytes=1000)


def test_parse_json_or_yaml_parses_json():
    result = parse_json_or_yaml(b'{"a": 1}')
    assert result == {"a": 1}


def test_parse_json_or_yaml_parses_yaml():
    result = parse_json_or_yaml(b"a: 1\nb: 2\n")
    assert result == {"a": 1, "b": 2}


def test_parse_json_or_yaml_raises_on_garbage():
    with pytest.raises(ParserError, match="could not be parsed"):
        parse_json_or_yaml(b"{not: valid: json: or: yaml: [[[")
