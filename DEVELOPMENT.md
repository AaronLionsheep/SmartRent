# Development

This guide covers how the SmartRent Indigo plugin is structured and how to set up a local environment. If you'd like to contribute changes, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Project layout

The plugin source lives in `SmartRent.indigoPlugin/Contents/Server Plugin/`:

| File | Purpose |
|---|---|
| `plugin.py` | Plugin logic: SmartRent login, device sync, and Indigo action handlers. |
| `Devices.xml` | Door Lock and Thermostat device definitions. |
| `PluginConfig.xml` | Plugin configuration dialog. |
| `requirements.txt` | Pinned Python dependencies. |

See the [Indigo Plugin Developer's Guide](https://www.indigodomo.com/docs/plugin_guide) for how these files fit together.

SmartRent communication uses [smartrent-py](https://github.com/ZacheryThomas/smartrent.py), which is built on `asyncio`. Indigo plugins run synchronously, so the plugin runs its own event loop on a background thread and submits work to it with [`asyncio.run_coroutine_threadsafe`](https://docs.python.org/3/library/asyncio-task.html#asyncio.run_coroutine_threadsafe).

## Local environment

A [conda](https://docs.conda.io/) environment with Python 3.13, [Ruff](https://docs.astral.sh/ruff/) and [pytest](https://docs.pytest.org/) is defined in `environment.yaml`:

```sh
conda env create -f environment.yaml
conda activate indigo-smartrent-dev
```

The `indigo` module is only available inside Indigo, so the plugin itself must be run and tested there.

## Linting and formatting

The project uses [Ruff](https://docs.astral.sh/ruff/) for linting, import sorting, and formatting. Its settings are in [`ruff.toml`](ruff.toml): a 120-character line length, Python 3.11 as the target version, and the Pyflakes (`F`), pycodestyle error (`E4`, `E7`, `E9`), and isort (`I`) rules.

Before opening a pull request, run these from the repository root:

```sh
ruff check --fix .   # lint, and fix what can be fixed automatically (including import order)
ruff format .        # format the code
```

The [Lint workflow](.github/workflows/lint.yml) runs the same checks on every pull request, using the Ruff version pinned in that file. [Renovate](https://docs.renovatebot.com/) keeps that version up to date. `environment.yaml` installs the latest Ruff, so if your local results differ from CI, install the pinned version (for example, `pip install ruff==0.17.3`).

### VS Code

The repository's [VS Code settings](.vscode/settings.json) format files and organize imports with Ruff on save. Install the [Ruff extension](https://marketplace.visualstudio.com/items?itemName=charliermarsh.ruff) to use them. The extension reads `ruff.toml`, so it uses the same rules as CI. It bundles its own Ruff version, though, so if it ever disagrees with CI, set the extension's [`ruff.path`](https://docs.astral.sh/ruff/editors/settings/#path) to a Ruff installed at the pinned version.
