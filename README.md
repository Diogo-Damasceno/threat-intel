# threat-intel

Plataforma para armazenar, consultar e compartilhar **Indicadores de
Comprometimento (IOCs)** — IPs, domínios, URLs, hashes (MD5/SHA1/SHA256) e
e-mails maliciosos — com **detecção automática de tipo**, busca filtrada,
importação em massa e **API REST** (stdlib pura, sem dependências).

> ⚠️ Ferramenta educacional/defensiva para gestão de IOCs próprios.

## Instalação

Pré-requisitos: **Python 3.10+**.

```bash
git clone https://github.com/Diogo-Damasceno/threat-intel.git
cd threat-intel
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Após instalar, o comando do projeto fica disponível dentro do venv.
Para usar fora dele, crie um atalho:

```bash
mkdir -p ~/.local/bin
ln -sf "$(pwd)/.venv/bin/tip" ~/.local/bin/tip
```

> Dica: se `~/.local/bin` não estiver no teu `PATH`, rode
> `export PATH="$HOME/.local/bin:$PATH"` (e adicione ao `~/.bashrc`/`~/.zshrc`).


## Uso

```bash
# adiciona um IOC
tip add 185.220.101.1 --threat botnet --tags c2

# busca por valor / tipo
tip lookup 185.220.101.1
tip search --type ip --min-confidence 70

# importa IOCs em massa de arquivo
tip import iocs.txt

# sobe a API REST
tip serve --port 8080

# estatisticas
tip stats
```

## Licença

MIT — veja `LICENSE`.
