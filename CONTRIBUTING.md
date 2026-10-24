# Contributing

Thanks for your interest in improving the SmartRent Indigo plugin! For help setting up a local environment and understanding how the plugin is built, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Reporting issues

Bugs and feature requests are tracked in [GitHub Issues](https://github.com/AaronLionsheep/SmartRent/issues). When reporting a bug, set the plugin's log level to **Debug**, reproduce the problem, and include the relevant Indigo Event Log lines along with your Indigo and plugin versions.

## Pull requests

Pull request titles must follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) (for example, `feat: add leak sensor support` or `fix: handle offline locks`). This is checked automatically, and the PR title is used to build the changelog.

## Releases

Releases are managed with [release-please](https://github.com/googleapis/release-please): merging to `main` updates a release PR that bumps the version in `Info.plist` and updates [CHANGELOG.md](CHANGELOG.md). Publishing a release attaches a zipped `SmartRent.indigoPlugin` automatically. Dependencies are kept up to date by [Renovate](https://docs.renovatebot.com/).
