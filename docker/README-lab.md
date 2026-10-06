# HexStrike ⇄ Hermes — intégration labo (Docker)

Architecture mise en place pour que **Hermes** pilote les outils **HexStrike**
via MCP, à l'intérieur du réseau Docker du laboratoire, sans exposition sur
l'hôte et avec un contrôle explicite des outils accessibles.

```
hermes-audit ──(hermes-agent_default)──▶ hexstrike-gateway ──(hexstrike-link)──▶ hexstrike ──(shaapi_monshaapi)──▶ monshaapi_api:8000
  agent Hermes                            passerelle MCP                           serveur HexStrike               cible de labo
                                          allowlist deny-by-default                API Flask :8888
```

Chaîne : `Hermes → passerelle MCP → HexStrike → outil → cible de labo → résultat → Hermes`.

## Composants

| Rôle | Service / conteneur | Image | Réseaux | Exposé sur l'hôte |
|------|---------------------|-------|---------|-------------------|
| Agent | `hermes` / `hermes-audit` | `hermes-agent-local:audit` | `default`, `shasec` | `127.0.0.1:9119` (dashboard) |
| Passerelle MCP | `hexstrike-gateway` | `hexstrike-gateway:lab` | `default`, `hexstrike-link` | aucun |
| Serveur HexStrike | `hexstrike` | `hexstrike-ai:lab` | `hexstrike-link`, `shasec` | aucun |
| API d'audit SHASEC | `monshaapi_api` | `monshaapi:latest` | `shaapi_monshaapi` | `:8000` (routes `/api/v1/...`) |

> **Deux backends d'audit, un orchestrateur.** Hermes pilote (a) **SHASEC**
> (`monshaapi_api`, API REST d'audit déjà utilisée par Hermes, ex. analyse DNS)
> en direct sur le réseau `shasec`, et (b) **HexStrike** via la passerelle MCP.
> Les deux sont complémentaires ; HexStrike complète SHASEC.
>
> **Cibles.** Elles peuvent être internes (`monshaapi_api`, utilisé aussi comme
> hôte de test de plomberie) **ou externes** : HexStrike dispose d'une sortie
> internet (NAT du bridge Docker), vérifiée sur `kaanari.com`.

- **Réseau "default"** : `hermes-agent_default` — Hermes y joint la passerelle.
- **Réseau "hexstrike-link"** : `hermes-agent_hexstrike-link` — lien privé
  passerelle ⇄ HexStrike. **Hermes n'y est pas** : sur ce réseau, seul le
  gateway voit HexStrike.
- **Réseau "shasec"** : `shaapi_monshaapi` (externe) — HexStrike y atteint les
  cibles du labo par leur nom (`monshaapi_api`).

### Nom DNS utilisé par Hermes

Hermes joint la passerelle par **`http://hexstrike-gateway:8888/mcp`**
(résolution DNS Docker par nom de service, jamais `localhost`).
La passerelle joint HexStrike par **`http://hexstrike:8888`**.

### Capacités réseau (scans)

Le conteneur `hexstrike` tourne en non-root. Pour que nmap puisse faire des
scans SYN/OS (sockets raw), l'image applique `setcap cap_net_raw,cap_net_admin`
sur le binaire nmap, et le service reçoit `cap_add: [NET_RAW, NET_ADMIN]` dans
le compose. Sans ce `cap_add`, le setcap est inerte et nmap retombe sur les
scans connect (`-sT`), qui fonctionnent sans privilège.

## Passerelle MCP : contrôle des outils (deny-by-default)

La passerelle (`docker/gateway/hexstrike_gateway.py`) est un petit serveur MCP
streamable-HTTP qui :

- n'expose **que** les outils d'une **allowlist explicite** ;
- mappe chaque outil autorisé vers `/api/tools/<outil>` de HexStrike ;
- **ne mappe jamais** les surfaces d'exécution arbitraire de HexStrike
  (`/api/command`, `/api/python/execute`, `/api/files/*`,
  `/api/payloads/generate`, msfvenom/metasploit, …). Ces endpoints restent sur
  le conteneur HexStrike, non routable depuis Hermes.

Allowlist par défaut (configurable sans rebuild) :

```
nmap, httpx, nuclei, ffuf, gobuster, nikto
```

Plus deux outils méta en lecture seule : `hexstrike_health`, `list_allowed_tools`.

Variables d'environnement de la passerelle (dans `docker-compose.audit.yml`) :

| Variable | Défaut | Rôle |
|----------|--------|------|
| `HEXSTRIKE_ALLOWED_TOOLS` | `nmap,httpx,nuclei,ffuf,gobuster,nikto` | allowlist CSV |
| `HEXSTRIKE_ALLOW_GENERIC` | `false` | passthrough générique (toujours borné à l'allowlist et à `/api/tools/*`) |
| `HEXSTRIKE_URL` | `http://hexstrike:8888` | API HexStrike amont |
| `HEXSTRIKE_TIMEOUT` | `300` | timeout par appel (s) |

> **Note sur le point 9 du cahier des charges.** Il demandait à la fois une
> « allowlist explicite » et d'« exposer arbitrairement tous les outils » — ce
> qui est contradictoire. L'intention retenue (et implémentée) est l'allowlist
> **deny-by-default** : rien n'est exposé hors de la liste.

## Démarrage

Depuis `hermes/hermes-agent/` (la stack SHASEC `shaapi` doit déjà tourner) :

```bash
# build + up des deux nouveaux services (le service hermes existant n'est pas recréé)
HERMES_DASH_PASS=change-me docker compose -f docker-compose.audit.yml up -d --build hexstrike hexstrike-gateway

# pour restreindre/élargir l'allowlist sans toucher au compose :
HEXSTRIKE_ALLOWED_TOOLS="nmap,nuclei" HERMES_DASH_PASS=change-me \
  docker compose -f docker-compose.audit.yml up -d hexstrike-gateway
```

Rechargez la config MCP de Hermes (nouvel `mcp_servers.hexstrike` dans
`~/.hermes-audit/config.yaml`) :

```bash
docker restart hermes-audit
```

## Procédure de test de bout en bout

```bash
# 1. Santé des conteneurs
docker compose -f docker-compose.audit.yml ps

# 2. La passerelle voit HexStrike (depuis le conteneur passerelle)
docker exec hexstrike-gateway \
  python3 -c "import requests;print(requests.get('http://hexstrike:8888/health',timeout=10).json())"

# 3. HexStrike atteint la cible de labo (même réseau shasec)
docker exec hexstrike curl -fsS -o /dev/null -w 'target http=%{http_code}\n' http://monshaapi_api:8000/

# 4. Hermes joint la passerelle MCP par son nom DNS (handshake MCP)
docker exec hermes-audit python3 - <<'PY'
import urllib.request, json
req = urllib.request.Request(
    "http://hexstrike-gateway:8888/mcp",
    data=json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{"protocolVersion":"2025-06-18","capabilities":{},
                "clientInfo":{"name":"hermes","version":"0"}}}).encode(),
    headers={"Content-Type":"application/json",
             "Accept":"application/json, text/event-stream"})
r = urllib.request.urlopen(req, timeout=10)
print("MCP initialize:", r.status, "session:", r.headers.get("mcp-session-id"))
PY

# 5. Appel outil complet de bout en bout : nmap de la cible via la passerelle
#    (le gateway forwarde vers /api/tools/nmap de HexStrike)
docker exec hexstrike-gateway python3 - <<'PY'
import requests
r = requests.post("http://hexstrike:8888/api/tools/nmap",
                  json={"target":"monshaapi_api","ports":"8000","scan_type":"-sV",
                        "additional_args":"-Pn -T4"}, timeout=300)
print(r.status_code, r.json().get("success"))
PY
```

Côté Hermes, une fois `hermes-audit` redémarré, le serveur MCP `hexstrike`
apparaît avec exactement les outils de l'allowlist ; demandez à Hermes un
`nmap`/`nuclei` sur `monshaapi_api` pour valider la chaîne complète.

## Durcissement optionnel (isolation L3 stricte)

Par défaut, HexStrike et Hermes partagent `shasec` (tous deux ont besoin
d'atteindre la cible), donc Hermes *pourrait* techniquement joindre
`hexstrike:8888` en direct ; le chemin **sanctionné** reste la passerelle (c'est
la seule chose que la config MCP de Hermes connaît).

Pour empêcher aussi au niveau réseau tout accès direct Hermes → HexStrike,
retirez `shasec` du service `hexstrike` et rattachez plutôt **la cible** au lien
privé :

```bash
docker network connect hermes-agent_hexstrike-link monshaapi_api
# puis, dans docker-compose.audit.yml, enlever "shasec" des networks de hexstrike
```

HexStrike n'est alors joignable que par la passerelle, et atteint la cible via
`hexstrike-link`.
