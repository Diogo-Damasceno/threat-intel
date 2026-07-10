# Threat Intelligence Platform (TIP) 🌐

Plataforma para armazenar, consultar e compartilhar **Indicadores de Comprometimento (IOCs)** — IPs, domínios, URLs, hashes (MD5/SHA1/SHA256) e e-mails maliciosos — com **detecção automática de tipo**, busca filtrada, importação em massa e **API REST** (stdlib pura, sem dependências).

> ⚠️ Ferramenta educacional/defensiva para gestão de threat intel.

## Recursos

- **Detecção automática** do tipo de IOC
- Deduplicação inteligente (atualiza `last_seen`/confiança em vez de duplicar)
- Campos: `threat`, `source`, `confidence` (0–100), `tags`, `first_seen`, `last_seen`
- **Busca** por tipo, ameaça e confiança mínima
- **Importação em massa** de arquivos (um IOC por linha, ignora `#` comentários)
- **API REST**: `/health`, `/stats`, `/lookup`, `/search`, `POST /ioc`
- Persistência em **SQLite**

## Instalação

```bash
git clone https://github.com/Diogo-Damasceno/threat-intel.git
cd threat-intel
pip install -e .
```

## Uso (CLI)

```bash
tip add 185.220.101.5 --threat C2 --source honeypot --confidence 90
tip add evil-phish.tk --threat phishing
tip lookup 185.220.101.5
tip search --type ip --min-confidence 80
tip import iocs.txt --threat ransomware --source feed-x
tip stats
```

## API REST

```bash
tip serve --port 8088
```

```bash
# adicionar IOC
curl -X POST http://127.0.0.1:8088/ioc \
  -H 'Content-Type: application/json' \
  -d '{"value":"9.9.9.9","threat":"C2","confidence":95}'

# consultar
curl 'http://127.0.0.1:8088/lookup?value=9.9.9.9'
curl 'http://127.0.0.1:8088/search?type=ip&min_confidence=80'
curl http://127.0.0.1:8088/stats
```

## Integração com o portfólio

Este TIP é o *hub* central: o **Honeypot** alimenta IOCs, o **Malware Analyzer** exporta hashes/URLs, e o **Phishing Detector** consulta domínios. Juntos formam a base do **SentinelAI**.

## Testes

```bash
pip install -e '.[dev]'
pytest -q
```

## Licença

MIT
