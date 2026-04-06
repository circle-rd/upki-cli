# µPKI-CLI

**NOT READY FOR PRODUCTION USE**

This project has only been tested on Python 3.11 to 3.13.
Due to Python usage it _SHOULD_ work on many other configurations, but it has NOT been tested.

## 1. About

µPKI [maɪkroʊ ˈpiː-ˈkeɪ-ˈaɪ] is a small PKI in Python that should let you make basic tasks without effort.
It works in combination with:

- [µPKI-CA](https://github.com/circle-rd/upki) - Certification Authority
- [µPKI-RA](https://github.com/circle-rd/upki-ra) - Registration Authority

µPKI-CLI is the client app that interacts with the [µPKI-RA](https://github.com/circle-rd/upki-ra) Registration Authority.

### 1.1 Dependencies

The following modules are required:

- Requests

Some systems libs & tools are also required, make sure you have them pre-installed:

```bash
sudo apt update
sudo apt -y install build-essential python3-dev python3-pip git
```

## 2. Install

The Installation process requires three different phases:

1. Clone the current repository:

```bash
git clone https://github.com/circle-rd/upki-cli
cd ./upki-cli
```

2. Install the dependencies and upki-client service timer in order to re-generate local certificates if needed. Registration Authority URL is required at this step:

```bash
./install.sh --url https://certificates.domain.com
```

3. Setup certificates required (cf. Usage below)

## 3. Usage

µPKI-CLI is the µPKI client and should be installed on server/customer host that will receive the final certificate. µPKI-CLI is responsible for private key and certificate request generation.

### 3.1 Add a certificate

_Note: On basic configuration you can add a certificate locally only if it has been registered on RA by an admin. To setup your Registration Authority (RA) please check [µPKI-RA](https://github.com/circle-rd/upki-ra)._

Call the client script with 'add' action:

```bash
./client.py --url https://certificates.domain.com add
```

For browser integration call the client script with 'add' action and browser flags:

```bash
./client.py --url https://certificates.domain.com add --firefox --chrome
```

### 3.2 List all certificates

You can list all certificates registered locally (this does not reflect what is configured on the RA server):

```bash
./client.py --url https://certificates.domain.com list
```

### 3.3 Delete a certificate

You can un-register a locally defined certificate (note: this will not affect RA configuration):

```bash
./client.py --url https://certificates.domain.com delete
```

### 3.4 Renew all certificates

You can force a certificate renewal for all certificates, which is basically what the upki-client services timer is doing:

```bash
./client.py --url https://certificates.domain.com renew
```

### 3.5 Renew Certificates Revocation List

Re-download CRL, useful when client is a server and web server needs to have an updated list.
An example systemd timer for Nginx is given in _upki-cli-crl.service_ and _upki-cli-crl.timer_:

```bash
./client.py --url https://certificates.domain.com crl
```

### 3.6 Help

For more advanced usage please check the app help global:

```bash
./client.py --help
```

You can also have specific help for each action:

```bash
./client.py --url https://certificates.domain.com add --help
```

## Project Structure

```
upki-cli/
├── README.md
├── LICENSE
├── __metadata.py
├── requirements.txt
├── setup.py
├── install.sh
├── upki-cli.sh
├── client.py
├── upki-cli-crl.service
├── upki-cli-crl.timer
└── client/
    ├── __init__.py
    ├── collection.py
    ├── node.py
    ├── bot.py
    └── upkiLogger.py
```

## License

MIT License - See LICENSE file for details.

## Links

- Website: https://circle-cyber.com
- GitHub: https://github.com/circle-rd
- Documentation: https://circle-rd.github.io/upki-cli
