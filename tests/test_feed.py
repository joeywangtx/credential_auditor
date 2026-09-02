import json
from unittest.mock import patch

from credaudit.feed import load_cached_feed, update_cache


def _fake_feed_payload():
    return {
        "meta": {"total": 2},
        "extensions": [
            {
                "ext_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "name": "Fake Malicious Extension",
                "threat_types": ["spyware", "data-theft"],
            },
            {
                "ext_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "name": "Another One",
                "threat_types": [],
            },
        ],
    }


def test_update_cache_writes_feed_and_returns_count(tmp_path):
    cache_path = tmp_path / "feed.json"
    with patch("credaudit.feed.fetch_feed", return_value=_fake_feed_payload()):
        path, count = update_cache(cache_path)

    assert path == cache_path
    assert count == 2
    assert json.loads(cache_path.read_text())["meta"]["total"] == 2


def test_load_cached_feed_builds_id_to_reason_map(tmp_path):
    cache_path = tmp_path / "feed.json"
    cache_path.write_text(json.dumps(_fake_feed_payload()))

    result = load_cached_feed(cache_path)

    assert set(result) == {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
    assert "spyware" in result["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]


def test_load_cached_feed_missing_file_returns_empty(tmp_path):
    assert load_cached_feed(tmp_path / "does-not-exist.json") == {}


def test_load_cached_feed_corrupt_file_returns_empty(tmp_path):
    cache_path = tmp_path / "feed.json"
    cache_path.write_text("not valid json{{{")

    assert load_cached_feed(cache_path) == {}
