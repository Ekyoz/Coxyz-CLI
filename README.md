# coxyz

CLI to manage Docker services under `/srv/docker` following coxyz rules
(ownership, permissions, ACL principals).

Replaces `check_fix_permission.zsh` + `services.zsh` with a single typed Python
tool driven by a YAML configuration.

## Install

```bash
# Recommended (isolated env)
sudo apt install pipx
sudo pipx install /path/to/coxyz --global

# Or via pip directly
sudo pip install /path/to/coxyz
```

This installs the `coxyz` binary into your `PATH`.

Optional: drop your custom config at `/etc/coxyz/config.yaml`
(otherwise the bundled defaults are used). Generate a starting point:

```bash
coxyz show-config       # inspect resolved defaults
```

You can also export the bundled default and edit it:

```bash
sudo install -d /etc/coxyz
sudo cp $(python3 -c "import coxyz, pathlib; print(pathlib.Path(coxyz.__file__).parent / 'default_config.yaml')") /etc/coxyz/config.yaml
```

## Commands

```bash
coxyz list                      # list services with image, ports, status
coxyz list -C apps              # filter by category

coxyz check                     # audit all services (exit 1 on drift)
coxyz check bitwarden           # audit one service
coxyz check apps/bitwarden -v   # verbose (show OK findings too)

coxyz apply                     # preview planned fixes, ask confirmation, then apply
coxyz apply bitwarden -y

coxyz create                    # interactive prompts
coxyz create -C apps -n myapp -i nginx:1.27 -p 80 --apply

coxyz show-config               # print resolved config
coxyz edit                      # edit /etc/coxyz/config.yaml
```

Most operations require root (chown/setfacl), so prefix with `sudo`.

Example excludes in `config.yaml`:

```yaml
exclude:
  - "*.bak"
  - "*/do_not_touch/"
```

## How it works

- **Config** (`/etc/coxyz/config.yaml` or bundled default) defines:
  - root dir, ACL principals, authorized categories
  - `exclude` glob patterns to ignore paths during audit/apply
  - per-path rules: mode, ACL perms, optional owner override, audit-only flag
- **`check`**: read-only audit. Reports drift and warn-only (data/, .env).
- **`apply`**: shows planned changes, asks for confirmation, then applies fixes.
  - Touches: category/service dirs, compose.yaml, config/ tree.
  - Never touches: `data/` content, `.env` files (audit-only).
  - Creates required missing directories before applying path fixes.
- **`create`**: scaffolds `<category>/<service>/{compose.yaml,config/,data/}`
  with correct owners + perms + ACL.
- **`list`**: parses each `compose.yaml` for image/ports and runs an audit
  to show a compliance status.

## File layout (enforced)

```
/srv/docker/<category>/<service>/
├── compose.yaml      660  svc_<cat>:svc_<cat>  acl:rw
├── config/           750  svc_<cat>:svc_<cat>  acl:rx
│   └── ...           (subdirs 750 rwx, files 660 rw)
└── data/             750  svc_<cat>:svc_<cat>  no ACL (audit only)
```
