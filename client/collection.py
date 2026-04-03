# -*- coding:utf-8 -*-
from __future__ import annotations

import json
import os
from typing import TypedDict


class NodeRecord(TypedDict, total=False):
    """A certificate node entry stored in cli.nodes.json."""

    state: str
    url: str
    name: str
    profile: str
    sans: list[str]
    p12: bool
    passwd: str | None
    firefox: bool
    chrome: bool


class Collection:
    """Manages the local certificate node registry (cli.nodes.json)."""

    def __init__(self, path: str) -> None:
        self.nodes: list[NodeRecord] = []
        self.path = path
        self.conf = os.path.join(self.path, "cli.nodes.json")

        if not os.path.isfile(self.conf):
            try:
                self.__update()
            except Exception as err:
                raise Exception(f"Unable to initialize collection: {err}") from err

    def __update(self, data: list[NodeRecord] | None = None) -> None:
        with open(self.conf, "wt") as raw:
            raw.write(json.dumps(data if data is not None else [], indent=4))

    def check_compliance(
        self,
        url: str,
        firefox: bool = False,
        chrome: bool = False,
    ) -> bool:
        """Ensure every node has the required fields, back-filling defaults.

        Args:
            url: RA URL to set on nodes that are missing it.
            firefox: Default value for the 'firefox' flag.
            chrome: Default value for the 'chrome' flag.

        Returns:
            True on success.
        """
        if not url:
            raise Exception("Missing mandatory url")

        for node in self.nodes:
            node.setdefault("url", url)
            node.setdefault("firefox", firefox)
            node.setdefault("chrome", chrome)

        self.__update(self.nodes)
        return True

    def list_nodes(self) -> list[NodeRecord]:
        """Load nodes from disk and return them.

        Returns:
            List of NodeRecord dicts.
        """
        with open(self.conf, "rt") as raw:
            self.nodes = json.loads(raw.read())
        return self.nodes

    def get_node(self, name: str, profile: str) -> NodeRecord | None:
        """Find a node by name and profile.

        Args:
            name: Common Name.
            profile: Certificate profile.

        Returns:
            Matching NodeRecord or None.
        """
        for n in self.nodes:
            if n.get("name") == name and n.get("profile") == profile:
                return n
        return None

    def register(
        self,
        url: str,
        name: str,
        profile: str,
        sans: list[str],
        p12: bool = False,
        passwd: str | None = None,
        chrome: bool = False,
        firefox: bool = False,
    ) -> None:
        """Register a new node in the collection.

        Args:
            url: RA URL.
            name: Common Name.
            profile: Certificate profile.
            sans: Subject Alternative Names.
            p12: Whether to generate a P12 bundle.
            passwd: P12 password.
            chrome: Register in Chrome NSS database.
            firefox: Register in Firefox NSS database.

        Raises:
            Exception: If a node with the same name and profile already exists.
        """
        node: NodeRecord = {
            "state": "init",
            "url": url,
            "name": name,
            "profile": profile,
            "sans": sans,
            "p12": p12,
            "passwd": passwd,
            "firefox": firefox,
            "chrome": chrome,
        }

        for n in self.nodes:
            if n.get("name") == node["name"] and n.get("profile") == node["profile"]:
                raise Exception("This node already exists")

        self.nodes.append(node)
        try:
            self.__update(self.nodes)
        except Exception as err:
            raise Exception(f"Unable to register node: {err}") from err

    def sign(self, name: str, profile: str) -> None:
        """Mark a node as signed.

        Args:
            name: Common Name.
            profile: Certificate profile.
        """
        for i, n in enumerate(self.nodes):
            if n.get("name") == name and n.get("profile") == profile:
                self.nodes[i]["state"] = "signed"
                break

        try:
            self.__update(self.nodes)
        except Exception as err:
            raise Exception(f"Unable to update node state: {err}") from err

    def remove(self, name: str, profile: str) -> None:
        """Remove a node from the collection.

        Args:
            name: Common Name.
            profile: Certificate profile.
        """
        for i, n in enumerate(self.nodes):
            if n.get("name") == name and n.get("profile") == profile:
                del self.nodes[i]
                break

        try:
            self.__update(self.nodes)
        except Exception as err:
            raise Exception(f"Unable to remove node: {err}") from err
