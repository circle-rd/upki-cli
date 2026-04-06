# upki-cli - Plan de Migration

## Vue d'ensemble du projet

- **Projet**: upki-cli (Client CLI pour uPKI)
- **Langage**: Python 3
- **Technologies actuelles**: Click (CLI), ZMQ (communication avec CA/RA), requests (API REST optionnelle)
- **Objectif**: Améliorer l'expérience utilisateur, ajouter TypeScript SDK

---

## 1. Refactoring CLI

### 1.1 Architecture actuelle

L CLI actuel utilise Click pour gérer les commandes. La refactorisation vise à améliorer la structure.

### 1.2 Structure cible

```
upki-cli/
├── upkicli/
│   ├── __init__.py
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── main.py           # Entry point Click
│   │   ├── commands/
│   │   │   ├── __init__.py
│   │   │   ├── cert.py       # Commandes certificats
│   │   │   ├── profile.py   # Commandes profils
│   │   │   └── admin.py     # Commandes admin
│   │   └── options.py       # Options partagées
│   ├── client/
│   │   ├── __init__.py
│   │   ├── base.py          # Client de base
│   │   ├── zmq_client.py    # Client ZMQ
│   │   └── rest_client.py   # Client REST (optionnel)
│   ├── validators/
│   │   └── input.py         # Validation des entrées
│   └── formatters/
│       ├── __init__.py
│       └── output.py        # Formatage JSON/table
├── requirements.txt
└── setup.py
```

---

## 2. Expérience utilisateur

### 2.1 Assistant interactif

**Objectif**: Faciliter l'utilisation pour les néophytes.

```python
# Exemple: Commande interactive pour créer un certificat
import click
from upkicli.commands import interactive

@cert.command()
@interactive
def create_interactive():
    """Créer un certificat avec assistant interactif."""
    fqdn = click.prompt("FQDN du service", type=str)
    profile = click.prompt(
        "Profil à utiliser",
        type=click.Choice(['docker-internal', 'web-server', 'internal-service']),
        default='docker-internal'
    )
    # Suite du processus...
```

### 2.2 Profils suggérés

| Commande                  | Description                              |
| ------------------------- | ---------------------------------------- |
| `upki cert suggest fqdn`  | Suggère le profil optimal                |
| `upki cert create --auto` | Création automatique avec profil suggéré |

### 2.3 Sortie améliorée

| Format  | Utilisation                      |
| ------- | -------------------------------- |
| `json`  | Sortie structurée pour scripting |
| `table` | Sortie lisible pour humains      |
| `yaml`  | Configuration Docker/Traefik     |

```bash
# Exemples d'utilisation
upki cert list --format table
upki cert get mycert --format json
upki cert export traefik --format yaml
```

---

## 3. Communication

### 3.1 Support double protocole

Le CLI doit supporter ZMQ et REST (pour les futures intégrations).

```python
from abc import ABC, abstractmethod
from typing import Optional

class ClientBase(ABC):
    @abstractmethod
    def request_certificate(self, fqdn: str, profile: str) -> dict:
        pass

    @abstractmethod
    def get_certificate(self, cert_id: str) -> dict:
        pass

class ZMQClient(ClientBase):
    """Client ZMQ pour communication directe avec CA."""
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def request_certificate(self, fqdn: str, profile: str) -> dict:
        # Implémentation ZMQ
        pass

class RESTClient(ClientBase):
    """Client REST pour communication avec RA via API."""
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url
        self.api_key = api_key

    def request_certificate(self, fqdn: str, profile: str) -> dict:
        # Implémentation REST
        pass
```

### 3.2 Configuration centralisée

```yaml
# ~/.upki/config.yml
ca:
  host: 127.0.0.1
  port: 5000
  protocol: zmq # zmq | rest

ra:
  url: http://127.0.0.1:8000
  api_key: null

defaults:
  profile: docker-internal
  format: table
```

---

## 4. TypeScript SDK - Future

### 4.1 Objectif

Créer un SDK TypeScript pour intégration native dans:

- Applications Node.js
- Scripts de déploiement
- Agents IA

### 4.2 Structure TypeScript

```
upki-sdk/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts           # Export principal
│   ├── client.ts          # Client HTTP
│   ├── types.ts           # Types partagés
│   └── errors.ts          # Erreurs personnalisées
├── dist/                  # Compilé
└── README.md
```

### 4.3 API TypeScript

```typescript
import { UPKIClient, CertificateRequest } from "@circle/upki-sdk";

const client = new UPKIClient({
  baseUrl: "http://ra.upki.local:8000",
  apiKey: process.env.upki_api_key,
});

async function requestCert() {
  const request: CertificateRequest = {
    fqdn: "nginx.docker.internal",
    profile: "docker-internal",
  };

  const cert = await client.certificates.create(request);
  console.log(cert);
}
```

---

## 5. Roadmap

### 5.1 Court terme (v2.1.x)

- [ ] Refactoring structure CLI
- [ ] Assistant interactif
- [ ] Sortie multi-format (JSON, table, YAML)

### 5.2 Moyen terme (v2.2.x)

- [ ] Support REST en plus de ZMQ
- [ ] Configuration centralisée YAML
- [ ] Validation des entrées avancée

### 5.3 Long terme (v3.0)

- [ ] SDK TypeScript
- [ ] Intégration MCP pour agents IA
- [ ] Plugins système (completion, hooks)

---

## 6. Notes de migration

### Compatibilité

- **Commandes**: Conserver les mêmes noms de commandes pour compatibilité
- **Arguments**: backward compatible avec les arguments existants
- **API**: Support simultané ZMQ et REST

### Dépendances à ajouter (Python)

- `pyyaml` pour configuration
- `tabulate` pour sortie table
- `requests` pour REST (optionnel)

### Dépendances TypeScript (future)

- `typescript` >= 5.0
- `@types/node` >= 18
- `axios` pour HTTP
