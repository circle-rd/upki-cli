"""Unit tests for client.collection.Collection (local node registry)."""

from __future__ import annotations

import json
import os

import pytest

from client.collection import Collection


@pytest.fixture()
def collection_dir(tmp_path):
    return str(tmp_path)


class TestCollectionInit:
    def test_creates_empty_registry_file_when_absent(self, collection_dir):
        coll = Collection(collection_dir)

        conf_path = os.path.join(collection_dir, "cli.nodes.json")
        assert os.path.isfile(conf_path)
        with open(conf_path) as fh:
            assert json.load(fh) == []
        assert coll.nodes == []

    def test_reuses_existing_registry_file(self, collection_dir):
        conf_path = os.path.join(collection_dir, "cli.nodes.json")
        with open(conf_path, "wt") as fh:
            json.dump([{"name": "existing", "profile": "server"}], fh)

        coll = Collection(collection_dir)

        assert os.path.isfile(conf_path)
        with open(conf_path) as fh:
            assert json.load(fh) == [{"name": "existing", "profile": "server"}]


class TestCollectionRegister:
    def test_register_persists_node_to_disk(self, collection_dir):
        coll = Collection(collection_dir)

        coll.register(
            "https://ra.example.com", "host1", "server", ["host1.example.com"]
        )

        nodes = coll.list_nodes()
        assert len(nodes) == 1
        assert nodes[0]["name"] == "host1"
        assert nodes[0]["profile"] == "server"
        assert nodes[0]["state"] == "init"
        assert nodes[0]["sans"] == ["host1.example.com"]

    def test_register_duplicate_name_and_profile_raises(self, collection_dir):
        coll = Collection(collection_dir)
        coll.register("https://ra.example.com", "host1", "server", [])

        with pytest.raises(Exception, match="already exists"):
            coll.register("https://ra.example.com", "host1", "server", [])

    def test_register_same_name_different_profile_is_allowed(self, collection_dir):
        coll = Collection(collection_dir)
        coll.register("https://ra.example.com", "host1", "server", [])
        coll.register("https://ra.example.com", "host1", "client", [])

        assert len(coll.nodes) == 2


class TestCollectionGetNode:
    def test_get_node_returns_matching_record(self, collection_dir):
        coll = Collection(collection_dir)
        coll.register("https://ra.example.com", "host1", "server", [])

        node = coll.get_node("host1", "server")

        assert node is not None
        assert node["name"] == "host1"

    def test_get_node_returns_none_when_not_found(self, collection_dir):
        coll = Collection(collection_dir)

        assert coll.get_node("missing", "server") is None


class TestCollectionSign:
    def test_sign_updates_state_and_persists(self, collection_dir):
        coll = Collection(collection_dir)
        coll.register("https://ra.example.com", "host1", "server", [])

        coll.sign("host1", "server")

        assert coll.nodes[0]["state"] == "signed"
        reloaded = Collection(collection_dir)
        reloaded.list_nodes()
        assert reloaded.nodes[0]["state"] == "signed"

    def test_sign_unknown_node_is_a_noop(self, collection_dir):
        coll = Collection(collection_dir)
        coll.register("https://ra.example.com", "host1", "server", [])

        coll.sign("does-not-exist", "server")

        assert coll.nodes[0]["state"] == "init"


class TestCollectionRemove:
    def test_remove_deletes_node_and_persists(self, collection_dir):
        coll = Collection(collection_dir)
        coll.register("https://ra.example.com", "host1", "server", [])

        coll.remove("host1", "server")

        assert coll.nodes == []
        reloaded = Collection(collection_dir)
        assert reloaded.list_nodes() == []


class TestCollectionCheckCompliance:
    def test_backfills_missing_fields(self, collection_dir):
        coll = Collection(collection_dir)
        coll.nodes = [{"name": "host1", "profile": "server"}]

        coll.check_compliance("https://ra.example.com", firefox=True, chrome=False)

        assert coll.nodes[0]["url"] == "https://ra.example.com"
        assert coll.nodes[0]["firefox"] is True
        assert coll.nodes[0]["chrome"] is False

    def test_does_not_override_existing_fields(self, collection_dir):
        coll = Collection(collection_dir)
        coll.nodes = [
            {"name": "host1", "profile": "server", "url": "https://old.example.com"}
        ]

        coll.check_compliance("https://new.example.com")

        assert coll.nodes[0]["url"] == "https://old.example.com"

    def test_raises_when_url_missing(self, collection_dir):
        coll = Collection(collection_dir)

        with pytest.raises(Exception, match="Missing mandatory url"):
            coll.check_compliance("")
