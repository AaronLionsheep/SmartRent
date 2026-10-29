# SmartRent for Indigo

An [Indigo](https://www.indigodomo.com) plugin that brings your [SmartRent](https://smartrent.com) apartment devices into your Indigo home automation setup. Once connected, your SmartRent door locks and thermostats show up as native Indigo devices, so you can control them from Indigo, Control Pages, triggers, schedules and Action Groups, and they stay in sync with live updates from SmartRent.

## Features

- **Door locks**: lock and unlock, live locked/unlocked status with the matching lock icon, battery level, and online status.
- **Thermostats**: set HVAC mode (Heat, Cool, Auto, Off), fan mode (Auto or Always On), heat and cool setpoints (including increase/decrease), with live temperature, humidity, heating/cooling state, and online status.
- **Live updates**: device state is pushed from SmartRent as it changes, so Indigo reflects changes made in the SmartRent app or at the device itself.
- **Two-factor authentication**: the plugin generates SmartRent 2FA codes automatically from your authenticator secret, so it can log in unattended.

## Requirements

- Indigo 2023.2 or later (the plugin targets Indigo Server API 3.4 and Python 3.11+).
- A SmartRent resident account with **two-factor authentication enabled through an authenticator app**. The plugin needs the authenticator *secret*, not a one-time code (see [Configuration](#configuration)).

Python dependencies ([smartrent-py](https://github.com/ZacheryThomas/smartrent.py), [pyotp](https://pyauth.github.io/pyotp/) and [more-itertools](https://more-itertools.readthedocs.io/)) are listed in the plugin's `requirements.txt` and are installed by Indigo automatically when the plugin is enabled.

## Installation

1. Download `SmartRent.indigoPlugin.zip` from the latest [release](https://github.com/AaronLionsheep/SmartRent/releases).
2. Unzip it and double-click `SmartRent.indigoPlugin`. Indigo will install and enable the plugin.
3. Configure the plugin as described below.

## Configuration

Open **Plugins → SmartRent → Configure…** and fill in:

| Field | Description |
|---|---|
| Email | The email address you use to sign in to SmartRent. |
| Password | Your SmartRent password. |
| 2FA Secret | The secret key from your SmartRent authenticator-app setup (see below). This is **not** the 6-digit code. |
| Log level | Debug, Info (default), or Warning. |

### Finding your 2FA secret

When you set up an authenticator app for SmartRent, you're shown a QR code. Most setup screens also offer a text version of the key (often labeled something like "can't scan the code?"). That text, usually a long string of letters and numbers, is the secret the plugin needs.

If 2FA is already set up and you no longer have the secret, you'll typically need to turn 2FA off and back on in SmartRent to get a new one. Add the new secret to your authenticator app *and* to the plugin.

Use the **Check 2FA code** button to confirm the secret is correct: the code it shows should match the one in your authenticator app.

Some setup screens show the secret in groups separated by spaces (for example, `ABCD EFGH IJKL MNOP`). Remove the spaces when you enter it in the plugin, or it will be rejected as invalid.

> **Note:** The plugin logs in to SmartRent when it starts. If you change your email, password, or 2FA secret, reload the plugin (**Plugins → SmartRent → Reload**) for the change to take effect.

## Adding devices

1. In Indigo, create a new device and choose **SmartRent** as the type.
2. Pick the model: **Door Lock** or **Thermostat**.
3. Select the matching device from the **SmartRent Device** menu, which lists the devices on your SmartRent account of that kind.
4. Save. The device will populate with its current state and then update live.

> **Note:** The plugin loads your SmartRent device list when it starts. If you add a device to your SmartRent account later, reload the plugin (**Plugins → SmartRent → Reload**) before it will appear in the **SmartRent Device** menu.

### Door Lock

Door locks are Indigo relay devices with the lock subtype. **Turn On** locks the door and **Turn Off** unlocks it, so the standard Indigo lock/unlock controls and actions work as expected.

| State | Description |
|---|---|
| `lockStatus` | `locked` or `unlocked` (shown in the device list). |
| `onOffState` | `true` when locked. |
| `batteryLevel` | Battery percentage reported by the lock. |
| `online` | Whether SmartRent reports the lock as online. |

### Thermostat

Thermostats are native Indigo thermostat devices and support the built-in thermostat actions.

| Indigo | SmartRent |
|---|---|
| HVAC mode Heat / Cool / Heat-Cool (Auto) / Off | `heat` / `cool` / `auto` / `off` |
| Fan mode Auto / Always On | `auto` / `on` |
| Heat and cool setpoints | Heating and cooling setpoints |

The device also reports current temperature, humidity, whether heating or cooling is running, and an `online` state.

## Using SmartRent devices in Indigo

Because these are standard Indigo devices, you can use them anywhere you'd use a built-in lock or thermostat. A few ideas:

- Trigger an Action Group when the front door is unlocked.
- Lock the door on a schedule each night.
- Switch the thermostat to a setback temperature when everyone leaves.
- Get a notification when a device's `online` state becomes false, or when a lock's battery runs low.

From a Python script in Indigo, the standard device commands work too:

```python
lock = indigo.devices["Front Door"]
indigo.device.turnOn(lock)  # lock the door

thermostat = indigo.devices["Living Room Thermostat"]
indigo.thermostat.setHeatSetpoint(thermostat, value=68)
```

See the Indigo [scripting tutorial](https://www.indigodomo.com/docs/plugin_scripting_tutorial) for more.

## Troubleshooting

- **"The email, password, and 2FA secrets are not configured!"**: open the plugin configuration and fill in all three fields, then reload the plugin.
- **"SmartRent rejected the login. Check your email, password, and 2FA secret."**: SmartRent didn't accept your credentials. Check your email and password, use **Check 2FA code** to confirm the code matches your authenticator app, then reload the plugin.
- **"Couldn't reach SmartRent: …"**: the plugin couldn't connect to SmartRent, or SmartRent returned an unexpected response. Check your network connection, wait a few minutes in case SmartRent is having problems, then reload the plugin.
- **"Timed out connecting to SmartRent."**: SmartRent didn't respond in time. This is usually temporary; reload the plugin to try again.
- **"Invalid 2FA secret: …"**: shown when you click **Check 2FA code** or save the plugin configuration with a secret that isn't valid. Check that the secret was copied completely, without spaces, and that you used the secret rather than a 6-digit code. See [Finding your 2FA secret](#finding-your-2fa-secret).
- **The SmartRent Device menu says "No connection to SmartRent API"**: the plugin couldn't log in. Look in the Event Log for one of the login errors above, fix the cause, then reload the plugin.
- **"No SmartRent device linked to …"**: edit the Indigo device and choose a device from the **SmartRent Device** menu.
- **A device is missing from the SmartRent Device menu**: the device list is loaded when the plugin starts, so devices added to your SmartRent account afterward won't appear until you reload the plugin. Also check that you picked the right model: the menu only lists SmartRent devices of the selected kind (Door Lock or Thermostat).
- **Something else**: set the log level to **Debug**, reproduce the problem, and include the relevant Indigo Event Log lines when asking for help.

For help, post in the plugin's [Indigo forum](https://forums.indigodomo.com/viewforum.php?f=330) or open an [issue](https://github.com/AaronLionsheep/SmartRent/issues).

## Development and contributing

See [DEVELOPMENT.md](DEVELOPMENT.md) for how the plugin is structured and how to set up a local environment, and [CONTRIBUTING.md](CONTRIBUTING.md) for how to report issues and submit pull requests.
