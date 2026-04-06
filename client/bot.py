# -*- coding:utf-8 -*-
from __future__ import annotations

import configparser
import hashlib
import os
import platform
import subprocess
import sys

from cryptography import x509

import client
from client.acme_client import AcmeClient


class Bot:
    def __init__(self, logger, ra_url: str, path: str, verbose: bool = True) -> None:
        self._logger = logger
        self._verbose = verbose
        self._path = path

        # Normalize URL
        ra_url = ra_url.rstrip("/")
        if ra_url.startswith("http://"):
            self._output(
                'Using unsecured protocol "http://" is NOT recommended...',
                level="warning",
            )
            while True:
                rep = input("Do you want to continue ? [y/N]")
                if rep.lower() == "y":
                    break
                raise Exception("Unsecure protocol refused by user.")
        elif not ra_url.startswith("https://"):
            ra_url = "https://" + ra_url
        self._ra_url = ra_url

        self.ca_cert = os.path.join(self._path, "ca.crt")
        self.crl_crt = os.path.join(self._path, "crl.pem")

        try:
            self.collection = client.Collection(self._path)
        except Exception as err:
            raise Exception(f"Unable to initialize collection: {err}") from err

        try:
            self.collection.list_nodes()
            self.collection.check_compliance(self._ra_url)
        except Exception as err:
            raise Exception(f"Unable to list certificates: {err}") from err

        # AcmeClient: disable cert verification until we have the CA cert
        ca_cert_path = self.ca_cert if os.path.isfile(self.ca_cert) else None
        self._acme = AcmeClient(self._ra_url, self._path, ca_cert_path=ca_cert_path)

        try:
            self.get_ca_checksum()
        except Exception as err:
            raise Exception(f"Unable to validate CA certificate: {err}") from err

        # After CA cert is on disk, re-instantiate with TLS verification
        self._acme = AcmeClient(self._ra_url, self._path, ca_cert_path=self.ca_cert)

        # Extract CA common name from the certificate
        self.ca_name = "uPKI-CA"
        if os.path.isfile(self.ca_cert):
            try:
                with open(self.ca_cert, "rb") as fh:
                    cert = x509.load_pem_x509_certificate(fh.read())
                attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                if attrs:
                    self.ca_name = attrs[0].value
            except Exception:
                pass  # keep default

    def _output(self, message: str, level: str | None = None) -> None:
        try:
            self._logger.write(message, level=level)
        except Exception as err:
            sys.stdout.write(f"Unable to log: {err}\n")

    def _run_cmd(self, cmd: str) -> None:
        """Run a shell command, ignoring non-zero exit codes (browser tools)."""
        self._output(f"> {cmd}", level="debug")
        subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            executable="/bin/bash",
        )

    def _get_mozilla_profile(self) -> str:
        if platform.system() == "Linux":
            f_path = os.path.expanduser("~/.mozilla/firefox")
            alt_path = os.path.expanduser("~/snap/firefox/common/.mozilla/firefox")
            if os.path.isdir(f_path):
                mozilla_profile = f_path
            elif os.path.isdir(alt_path):
                mozilla_profile = alt_path
            else:
                raise NotImplementedError(
                    "Firefox has not been detected on this system"
                )
        elif platform.system() == "Darwin":
            fp = os.path.expanduser("~/Library/Application Support/Firefox/Profiles")
            if os.path.isdir(fp):
                mozilla_profile = fp
            else:
                raise NotImplementedError(
                    "Firefox has not been detected on this system"
                )
        elif platform.system() == "Windows":
            wp = os.path.join(os.getenv("APPDATA", ""), r"Mozilla\Firefox")
            if os.path.isdir(wp):
                mozilla_profile = wp
            else:
                raise NotImplementedError(
                    "Firefox has not been detected on this system"
                )
        else:
            raise NotImplementedError(f"Unsupported platform: {platform.system()}")

        ini_path = os.path.join(mozilla_profile, "profiles.ini")
        profile = configparser.ConfigParser()
        profile.read(ini_path)
        data_path = os.path.normpath(
            os.path.join(mozilla_profile, profile.get("Profile0", "Path"))
        )
        return data_path

    def _add_to_firefox(self, p12_file: str, passwd: str | None) -> bool:
        self._output("Get Mozilla profile", level="debug")
        data_path = self._get_mozilla_profile()
        self._output(f"Found Firefox profile DB: {data_path}", level="debug")

        try:
            self._output(f"Add {self.ca_name} in Firefox")
            self._run_cmd(
                f"certutil -A -n '{self.ca_name}' -t 'TC,,' -i {self.ca_cert} -d sql:{data_path}"
            )
        except Exception:
            self._output("Unable to add Root CA in Firefox", level="error")

        try:
            self._output("Add user certificate in Firefox")
            self._run_cmd(
                f"pk12util -i {p12_file} -d sql:{data_path} -W '{passwd or ''}'"
            )
        except Exception:
            self._output("Unable to add user certificate in Firefox", level="error")

        return True

    def _add_to_chrome(self, p12_file: str, pem_file: str, passwd: str | None) -> bool:
        if platform.system() == "Linux":
            db_path = os.path.expanduser("~/.pki/nssdb")
            if not os.path.isdir(db_path):
                raise FileNotFoundError("Chrome has not been detected on this system")

            try:
                self._output(f"Add {self.ca_name} in Chrome")
                self._run_cmd(
                    f"certutil -A -n '{self.ca_name}' -t 'TC,,' -i {self.ca_cert} -d sql:{db_path}"
                )
            except Exception:
                self._output("Unable to add Root CA in Chrome", level="error")

            try:
                self._output("Add user certificate in Chrome")
                self._run_cmd(
                    f"pk12util -i {p12_file} -d sql:{db_path} -W '{passwd or ''}'"
                )
            except Exception:
                self._output("Unable to add user certificate in Chrome", level="error")

        elif platform.system() == "Darwin":
            sys_kc = "/Library/Keychains/System.keychain"
            if os.path.isfile(sys_kc):
                try:
                    self._output(
                        "[+] Run following command to import uPKI Root CA in System KeyChain"
                    )
                    self._run_cmd(
                        f"sudo security add-trusted-cert -d -r trustRoot -k {sys_kc} {self.ca_cert}"
                    )
                except Exception:
                    self._output(
                        "Unable to add Root CA in System KeyChain", level="error"
                    )

            login_kc = os.path.expanduser("~/Library/Keychains/login.keychain")
            if not os.path.isfile(login_kc):
                raise FileNotFoundError("No KeyChain detected on this system")

            try:
                self._output(
                    "[+] Run following command to import uPKI Root CA in Login KeyChain"
                )
                self._run_cmd(
                    f"sudo security add-trusted-cert -d -r trustRoot -k {login_kc} {self.ca_cert}"
                )
            except Exception:
                self._output("Unable to add Root CA in Login KeyChain", level="error")

            try:
                self._output("Add user certificate in KeyChain")
                self._run_cmd(f"certtool i {pem_file}")
            except Exception:
                self._output(
                    "Unable to add user certificate in Login KeyChain", level="error"
                )
        else:
            raise NotImplementedError("Sorry this OS is not supported yet.")

        return True

    def get_ca_checksum(self) -> bool:
        self._output("Check CA certificate", level="debug")
        ca_pem = self._acme.get_ca_certificate()
        received = hashlib.sha256(ca_pem.encode("utf-8")).hexdigest()
        self._output(f"CA certificate hash received: {received}", level="debug")

        if os.path.isfile(self.ca_cert):
            with open(self.ca_cert, "rt") as fh:
                raw = fh.read()
            found = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            if found != received:
                self._output(f"OLD CA certificate hash was: {found}", level="debug")
                self._output("NEW CA certificate received!", level="warning")
                while True:
                    rep = input("Would you like to update it ? [y/N]")
                    if rep.lower() == "y":
                        break
                    raise Exception("CA certificate change refused by user.")
                try:
                    os.chmod(self.ca_cert, 0o600)
                except Exception as err:
                    raise Exception(
                        "Unable to remove CA certificate protection"
                    ) from err
            else:
                self._output("CA certificate unchanged", level="debug")
                return True
        else:
            self._output("CA certificate first installation", level="warning")

        with open(self.ca_cert, "wt") as fh:
            fh.write(ca_pem)

        try:
            os.chmod(self.ca_cert, 0o444)
        except Exception as err:
            raise Exception("Unable to protect CA certificate") from err

        return True

    def add_node(
        self,
        name: str | None,
        profile: str | None,
        sans: list[str] | None = None,
        p12: bool = False,
        passwd: str | None = None,
        chrome: bool = False,
        firefox: bool = False,
    ) -> bool:
        if name is None:
            name = input("Enter your node name (CN): ")
        if profile is None:
            profile = input("Enter your profile: ")

        # Force p12 output if browser certificate is needed
        p12 = True if (chrome or firefox) else p12

        try:
            self._output("Register node in local collection", level="debug")
            self.collection.register(
                self._ra_url,
                name,
                profile,
                sans or [],
                p12=p12,
                passwd=passwd,
                chrome=chrome,
                firefox=firefox,
            )
        except Exception as err:
            if "node already exists" in str(err).lower():
                raise RuntimeError(err)
            raise Exception(f"Unable to add node: {err}") from err

        try:
            self._output("Enroll certificate via ACME", level="debug")
            result = self._acme.enroll(name, profile, sans, p12, passwd)
        except Exception as err:
            raise Exception(f"Unable to enroll certificate: {err}") from err

        try:
            self.collection.sign(name, profile)
        except Exception as err:
            raise Exception(f"Unable to update certificate status: {err}") from err

        if p12:
            if firefox:
                self._add_to_firefox(result["p12"], passwd)
            if chrome:
                self._add_to_chrome(result["p12"], result["pem"], passwd)

        return True

    def renew(self) -> bool:
        try:
            self.collection.list_nodes()
        except Exception as err:
            raise Exception(f"Unable to list nodes: {err}") from err

        if not self.collection.nodes:
            raise Exception("No node to renew.")

        for node in self.collection.nodes:
            name = node["name"]
            profile = node["profile"]
            self._output(f"Renew certificate {name} ({profile})")

            try:
                result = self._acme.renew(
                    name,
                    profile,
                    node.get("sans"),
                    node.get("p12", False),
                    node.get("passwd"),
                )
            except Exception as err:
                self._output(f"Unable to renew certificate: {err}", level="warning")
                continue

            try:
                self.collection.sign(name, profile)
            except Exception as err:
                raise Exception(f"Unable to update node status: {err}") from err

            if node.get("p12"):
                p12_file = result.get("p12", "")
                pem_file = result.get("pem", "")
                if node.get("firefox") and p12_file:
                    self._add_to_firefox(p12_file, node.get("passwd"))
                if node.get("chrome") and p12_file:
                    self._add_to_chrome(p12_file, pem_file, node.get("passwd"))

        return True

    def crl(self) -> bool:
        self._output("Retrieve CRL", level="debug")
        crl_pem = self._acme.get_crl()
        with open(self.crl_crt, "wt") as fh:
            fh.write(crl_pem)
        return True

    def list(self) -> bool:
        try:
            nodes = self.collection.list_nodes()
        except Exception as err:
            raise Exception(f"Unable to retrieve nodes: {err}") from err

        if not nodes:
            self._output("No node found in config.")
            return False

        self._output("\t\t..:: Nodes found in config ::..")
        for i, node in enumerate(nodes):
            self._output(f"\t- [{i}] {node['name']}\t({node['profile']})")

        return True

    def delete(self, name: str | None, profile: str | None) -> bool:
        if name is None:
            name = input("Enter node name to delete (CN): ")
        if profile is None:
            profile = input("Enter node profile to delete: ")

        try:
            node = self.collection.get_node(name, profile)
        except Exception as err:
            raise Exception(f"Unable to load node: {err}") from err

        if node is None:
            raise Exception("Node does not exist.")

        name = node["name"]
        profile = node["profile"]
        p12 = node.get("p12", False)

        try:
            self.collection.remove(name, profile)
        except Exception as err:
            raise Exception(f"Unable to remove node from collection: {err}") from err

        for ext in ("key", "csr", "crt", "pem"):
            path = os.path.join(self._path, f"{profile}.{name}.{ext}")
            if os.path.isfile(path):
                try:
                    os.chmod(path, 0o600)
                    os.unlink(path)
                except Exception as err:
                    raise Exception(f"Unable to delete {ext} file: {err}") from err

        if p12:
            p12_path = os.path.join(self._path, f"{profile}.{name}.p12")
            if os.path.isfile(p12_path):
                try:
                    os.chmod(p12_path, 0o600)
                    os.unlink(p12_path)
                except Exception as err:
                    raise Exception(f"Unable to delete p12 file: {err}") from err

        self._output(f"Node {name} ({profile}) deleted.")
        return True
