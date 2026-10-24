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
