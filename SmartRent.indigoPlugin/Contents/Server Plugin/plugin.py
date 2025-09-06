import indigo
import logging
import aiohttp
import asyncio
import threading

from functools import partial
from more_itertools import first
from json import JSONEncoder, dumps

from typing import Any, TypeVar
from collections.abc import Coroutine
from concurrent.futures import Future

from pyotp import TOTP
from smartrent import (
    async_login,
    Thermostat as SmartRentThermostat,
    DoorLock as SmartRentDoorLock,
    LeakSensor as SmartRentLeakSensor
)
from smartrent.device import Device as SmartRentDevice

SMARTRENT_INDIGO_HVAC_FAN_MODES = {
    "on": indigo.kFanMode.AlwaysOn,
    "auto": indigo.kFanMode.Auto,
}
"""Mapping of SmartRent fan modes to Indigo fan modes"""

INDIGO_SMARTRENT_HVAC_FAN_MODES = {
    indigo.kFanMode.AlwaysOn: "on",
    indigo.kFanMode.Auto: "auto",
}
"""Mapping of Indigo fan modes to SmartRent fan modes"""

SMARTRENT_INDIGO_HVAC_MODES = {
    "cool": indigo.kHvacMode.Cool,
    "heat": indigo.kHvacMode.Heat,
    "auto": indigo.kHvacMode.HeatCool,
    "off": indigo.kHvacMode.Off,
}
"""Mapping of SmartRent Hvac modes to Indigo Hvac modes"""

INDIGO_SMARTRENT_HVAC_MODES = {
    indigo.kHvacMode.Cool: "cool",
    indigo.kHvacMode.Heat: "heat",
    indigo.kHvacMode.HeatCool: "auto",
    indigo.kHvacMode.Off: "off",
}
"""Mapping of Indigo Hvac modes to SmartRent Hvac modes"""

_T = TypeVar("_T")

class OTP():
    """A wrapper class to generate one-time-passcodes"""
    
    def __init__(self, secret: str):
        self._totp = TOTP(secret)

    def __str__(self):
        return self._totp.now()

    def __repr__(self):
        return str(self)
    
class OTPEncoder(JSONEncoder):
    """A custom JSON Encoder class that generates OTP codes at encode-time."""

    def default(self, o):
        if isinstance(o, OTP):
            return o.__str__()
            
        return super().default(o)

class Plugin(indigo.PluginBase):

    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)

        self.setLogLevel(pluginPrefs.get('log-level', "info"))

        self.loop = None
        self._async_thread = None
        
        self.initialize_asyncio()

    ##########################################################################
    # MARK: Plugin Lifecycle
    ##########################################################################

    def startup(self):
        """
        Called by Indigo to start the plugin.
        """
        self.logger.debug("Starting SmartRent...")

        self.email = self.pluginPrefs.get("email")
        self.password = self.pluginPrefs.get("password")
        self.tfa_secret = self.pluginPrefs.get("tfa-secret")

        # Alert when the plugin is not fully configured
        if not self.email or not self.password or not self.tfa_secret:
            self.logger.error("The email, password, and 2FA secrets are not configured!")
        else:
            self.tfa_token = OTP(self.tfa_secret)
            
            self.logger.info("Connecting to SmartRent API...")
            # We need a custom session that will use our loop and custom JSON serializer to generate 2FA codes when needed
            smartrent_session = aiohttp.ClientSession(
                loop=self.loop,
                json_serialize=partial(dumps, cls=OTPEncoder)
            )
            api_login = self.run(async_login(
                email=self.email,
                password=self.password,
                aiohttp_session=smartrent_session,
                tfa_token=self.tfa_token
            ))
            self.api = api_login.result()
            self.logger.info("Successfully connected to SmartRent API!")

    def shutdown(self):
        """
        Called by Indigo to shut down the plugin
        """
        self.logger.debug(u"Stopping SmartRent...")

    ##########################################################################
    # MARK: asyncio
    ##########################################################################

    def initialize_asyncio(self):
        """
        Initializes the components to support an external asyncio loop
        """
        self.loop = asyncio.new_event_loop()

        def run():
            self.loop.run_until_complete(async_run())

        async def async_run():
            # Run forever to pick up coroutines submitted from the main thread
            while True:
                # Periodically check for the stopThread signal when the plugin is shutting down
                await asyncio.sleep(1.0)
                if self.stopThread:
                    break

        self._async_thread = threading.Thread(target=run)
        self._async_thread.start()

    def run(self, coro: Coroutine[Any, Any, _T]) -> Future[_T]:
        """
        Runs a coroutine in the event loop from the main Indio thread on the asyncio thread.

        Parameters
        ----------
        coro: Couroutine
            The coroutine to run.

        Returns
        -------
        future: Future
            The future reference to the running coroutine.
        """
        return asyncio.run_coroutine_threadsafe(coro, loop=self.loop)

    ##########################################################################
    # MARK: Device Lifecycle
    ##########################################################################

    def deviceStartComm(self, device):
        """
        Handles processes for starting a device. This will check dependencies, validate configurations,
        subscribe to topics, and add message handlers.

        Parameters
        ----------
        device: Device
            The device that is starting

        Returns
        -------
        started: bool
            True or false to indicate if the device was started.
        """
        self.logger.debug(f"Starting {device.name}...")

        try:
            smartrent_device = self.get_smartrent_device_for_device(device)
        except ValueError:
            self.logger.error(f"No SmartRent device linked to '{device.name}'!")
            return False
        
        # Update the indigo device with the current SmartRent state
        self.update_device_from_smartrent(device=device, smartrent_device=smartrent_device)

        # Update the Indigo device on each SmartRent update
        update_handler = partial(
            self.update_device_from_smartrent,
            device=device,
            smartrent_device=smartrent_device
        )
        smartrent_device.set_update_callback(update_handler)
        
        # A hack to run the updated initialization synchronously inside the asyncio thread
        async def _start_updater():
            smartrent_device.start_updater()

        # Configure the SmartRent device to receive live updates
        self.run(_start_updater())

    def deviceStopComm(self, device):
        """
        Handles processes for a device that has been told to stop communication.
        Cleanup happens here. This includes removing subscriptions,
        removing listeners, and not tracking this device.

        Parameters
        ----------
        device: Device
            The device that is stopping.

        Returns
        -------
        stopped:
            True or false to indicate if the device was stopped.
        """
        self.logger.debug(f"Stopping {device.name}...")

    def didDeviceCommPropertyChange(self, original_device, updated_device):
        """
        This method gets called by the default implementation of deviceUpdated() to determine if
        any of the properties needed for device communication (or any other change requires a
        device to be stopped and restarted). The default implementation checks for any changes to
        properties. You can implement your own to provide more granular results. For instance, if
        your device requires 4 parameters, but only 2 of those parameters requires that you restart
        the device, then you can check to see if either of those changed. If they didn't then you
        can just return False and your device won't be restarted (via deviceStopComm()/deviceStartComm() calls).

        Parameters
        ----------
        original_device: Device
            The device before updates.
        
        updated_device: Device
            The device after updates.
        
        Returns
        -------
        changed: bool
            True or false whether the device had the communication properties changed.
        """
        return original_device.pluginProps.get("smartrent-device") != updated_device.pluginProps.get("smartrent-device")
    
    ##########################################################################
    # MARK: Device Actions
    ##########################################################################

    def actionControlDevice(self, action, device):
        """
        Handles an action being performed on the device.

        :param action: The action that occurred.
        :param device: The device that was acted on.
        :return: None
        """
        smartrent_device = self.get_smartrent_device_for_device(device)
        if device.deviceTypeId == "lock":
            # lock devices can only be represented by the SmartRent DoorLock class
            if not isinstance(smartrent_device, SmartRentDoorLock):
                self.logger.error(f"The SmartRent device associated with '{device.name}' was not found to be a Thermostat!")
                return

            if action.deviceAction == indigo.kDeviceAction.TurnOn:
                self.run(smartrent_device.async_set_locked(True))
            
            elif action.deviceAction == indigo.kDeviceAction.TurnOff:
                self.run(smartrent_device.async_set_locked(False))

    def actionControlUniversal(self, action, device):
        """
        Handles an action being performed on the device.

        :param action: The action that occurred.
        :param device: The device that was acted on.
        :return: None
        """
        smartrent_device = self.get_smartrent_device_for_device(device)

        if action.deviceAction == indigo.kUniversalAction.RequestStatus:
            self.run(smartrent_device._async_fetch_state())

    def actionControlThermostat(self, action, device):
        """
        Handles a thermostat-related action being performed on a device.

        :param action: The action being performed.
        :param device: The device the action was performed on.
        :return: None
        """
        smartrent_device = self.get_smartrent_device_for_device(device)
        if not isinstance(smartrent_device, SmartRentThermostat):
            self.logger.error(f"The SmartRent device associated with '{device.name}' was not found to be a Thermostat!")
            return

        if action.thermostatAction == indigo.kThermostatAction.SetHvacMode:
            if mode := INDIGO_SMARTRENT_HVAC_MODES.get(action.actionMode):
                self.run(smartrent_device.async_set_mode(mode))
            else:
                self.logger.warning(f"Unsupported Hvac mode: {action.actionMode}")

        elif action.thermostatAction == indigo.kThermostatAction.SetFanMode:
            if mode := INDIGO_SMARTRENT_HVAC_FAN_MODES.get(action.actionMode):
                self.run(smartrent_device.async_set_fan_mode(mode))
            else:
                self.logger.warning(f"Unsupported fan mode: {action.actionMode}")

        elif action.thermostatAction == indigo.kThermostatAction.SetCoolSetpoint:
            self.run(smartrent_device.async_set_cooling_setpoint(action.actionValue))

        elif action.thermostatAction == indigo.kThermostatAction.SetHeatSetpoint:
            self.run(smartrent_device.async_set_heating_setpoint(action.actionValue))

        elif action.thermostatAction == indigo.kThermostatAction.DecreaseCoolSetpoint:
            self.run(smartrent_device.async_set_cooling_setpoint(device.coolSetpoint - action.actionValue))

        elif action.thermostatAction == indigo.kThermostatAction.IncreaseCoolSetpoint:
            self.run(smartrent_device.async_set_cooling_setpoint(device.coolSetpoint + action.actionValue))

        elif action.thermostatAction == indigo.kThermostatAction.DecreaseHeatSetpoint:
            self.run(smartrent_device.async_set_heating_setpoint(device.heatSetpoint - action.actionValue))

        elif action.thermostatAction == indigo.kThermostatAction.IncreaseHeatSetpoint:
            self.run(smartrent_device.async_set_heating_setpoint(device.heatSetpoint + action.actionValue))

    ##########################################################################
    # MARK: SmartRent
    ##########################################################################

    def get_smartrent_device_for_device(self, device) -> SmartRentDevice:
        """
        Gets the associated SmartRent Device instance for the Indigo device.

        Parameters
        ----------
        device: indigo.Device
            The indigo device to lookup.

        Returns
        -------
        device: SmartRentDevice
            The associated SmartRent device.

        Raises
        ------
        ValueError: When there is no associated SmartRent device.
        """
        smartrent_device_id = int(device.pluginProps.get("smartrent-device", 0))
        smartrent_devices = self.api.get_device_list()
        return first(filter(lambda d: d._device_id == smartrent_device_id, smartrent_devices))
    
    def update_device_from_smartrent(self, device, smartrent_device: SmartRentDevice | None = None):
        """
        Update the indigo device from the SmartRent API.
        """
        smartrent_device = smartrent_device or self.get_smartrent_device_for_device(device)
        _updated_data = {key: value for key, value in vars(smartrent_device).items() if key not in ["_client", "_update_callback_funcs"]}
        self.logger.debug(f"Received device update: {_updated_data}")

        state_updates = { "online": smartrent_device.get_online() }

        if device.deviceTypeId == "thermostat":
            if not isinstance(smartrent_device, SmartRentThermostat):
                raise TypeError(f"Thermostat '{device.name}' not linked with a SmartRent thermostat!")
            
            state_updates.update({
                "humidityInput1": smartrent_device.get_current_humidity(),
                "hvacCoolerIsOn": smartrent_device.get_operating_state() == "cooling",
                "hvacFanMode": SMARTRENT_INDIGO_HVAC_FAN_MODES[smartrent_device.get_fan_mode()],
                "hvacHeaterIsOn": smartrent_device.get_operating_state() == "heating",
                "hvacOperationMode": SMARTRENT_INDIGO_HVAC_MODES[smartrent_device.get_mode()],
                "setpointCool": smartrent_device.get_cooling_setpoint(),
                "setpointHeat": smartrent_device.get_heating_setpoint(),
                "temperatureInput1": smartrent_device.get_current_temp()
            })
        elif device.deviceTypeId == "lock":
            if not isinstance(smartrent_device, SmartRentDoorLock):
                raise TypeError(f"Thermostat '{device.name}' not linked with a SmartRent lock!")

            state_updates.update({
                "batteryLevel": smartrent_device.get_battery_level(),
                "onOffState": smartrent_device.get_locked()
            })

            if smartrent_device.get_locked():
                device.updateStateImageOnServer(indigo.kStateImageSel.Locked)
                device.updateStateOnServer("lockStatus", "locked", uiValue="Locked")
            else:
                device.updateStateImageOnServer(indigo.kStateImageSel.Unlocked)
                device.updateStateOnServer("lockStatus", "unlocked", uiValue="Unlocked")

        device.updateStatesOnServer([{"key": key, "value": value} for key, value in state_updates.items()])

    ##########################################################################
    # MARK: UI Validation
    ##########################################################################

    def validatePrefsConfigUi(self, valuesDict):
        """
        Validates the plugin preferences Config UI.

        :param valuesDict:
        :return: Tuple of the form (valid, valuesDict, errors)
        """
        errors = indigo.Dict()

        # Ensure an email, password, and 2fa secret were provided
        required_fields = ["email", "password", "tfa-secret"]
        for field in required_fields:
            if len(valuesDict.get(field, "")) == 0:
                errors[field] = "A value is required!"

        if len(errors) == 0:
            return True
        else:
            return False, valuesDict, errors

    def validateDeviceConfigUi(self, valuesDict, typeId, devId):
        """
        Validates a device config.

        :param valuesDict: The values in the Config UI.
        :param typeId: the device type as specified in the type attribute.
        :param devId: The id of the device (0 if a new device).
        :return: True if the config is valid.
        """
        return True, valuesDict

    def validateActionConfigUi(self, valuesDict, typeId, deviceId):
        """
        Validates an action config UI.

        :param valuesDict: The values in the UI.
        :param typeId:
        :param deviceId:
        :return: True or false based on the validity of the data.
        """
        errors = indigo.Dict()

        if len(errors) == 0:
            return True
        else:
            return False, valuesDict, errors

    def validateEventConfigUi(self, valuesDict, typeId, eventId):
        """
        Validates an event config UI.

        :param valuesDict: the dictionary of values currently specified in the dialog
        :param typeId: event type specified in the type attribute
        :param eventId: the unique event ID for the event being edited (or 0 of it's a new event)
        :return: True or false based on the validity of the data
        """
        errors = indigo.Dict()

        if len(errors) == 0:
            return True
        else:
            return False, valuesDict, errors

    ##########################################################################
    # MARK: UI Close
    ##########################################################################

    def closedDeviceConfigUi(self, valuesDict, userCancelled, typeId, devId):
        return True

    def closedPrefsConfigUi(self, valuesDict, userCancelled):
        """
        Handler for the closing of a configuration UI.

        :param valuesDict: The values in the config.
        :param userCancelled: True or false to indicate if the config was cancelled.
        :return:
        """
        if userCancelled:
            return
            
        self.setLogLevel(valuesDict.get('log-level', "info"))

        self.logger.info("Restart the plugin if credentials have changed.")

    ##########################################################################
    # MARK: Utilities
    ##########################################################################

    def setLogLevel(self, level):
        """
        Helper method to set the logging level.

        :param level: Expected to be a string with a valid log level.
        :return: None
        """
        valid_log_levels = ["debug", "info", "warning"]
        if level not in valid_log_levels:
            self.logger.error(u"Attempted to set the log level to an unhandled value: {}".format(level))

        if level == "debug":
            self.indigo_log_handler.setLevel(logging.DEBUG)
            self.logger.debug(u"Log level set to debug")
        elif level == "info":
            self.indigo_log_handler.setLevel(logging.INFO)
            self.logger.info(u"Log level set to info")
        elif level == "warning":
            self.indigo_log_handler.setLevel(logging.WARNING)
            self.logger.warning(u"Log level set to warning")

    ##########################################################################
    # MARK: Callbacks
    ##########################################################################

    def menuChanged(self, valuesDict):
        """
        Dummy function used to update a ConfigUI dynamic menu

        :return: the values currently in the ConfigUI
        """
        return valuesDict
    
    def generate_2fa_code(self, valuesDict):
        """
        Callback to check if the 2FA secret generates the expected code.
        """
        totp = TOTP(valuesDict.get("tfa-secret"))
        valuesDict["tfa-code"] = totp.now()

        return valuesDict

    ##########################################################################
    # MARK: List Generators
    ##########################################################################

    def get_smartrent_devices(self, filter="", valuesDict=None, typeId="", targetId=0):
        """
        Gets SmartRent devices.
        """
        if self.api is None:
            return [(-1, "%%disabled:No connection to SmartRent API%%")]

        filter = list(map(lambda item: item.strip(), filter.split(",")))
        devices = []

        if len(filter) == 0:
            devices.extend(self.api.get_device_list())
        else:
            if "lock" in filter:
                devices.extend(self.api.get_locks())
            if "thermostat" in filter:
                devices.extend(self.api.get_thermostats())
            if "binary_switch" in filter:
                devices.extend(self.api.get_binary_switches())
            if "multilevel_switch" in filter:
                devices.extend(self.api.get_multilevel_switches())
            if "leak_sensor" in filter:
                devices.extend(self.api.get_leak_sensors())
            if "motion_sensor" in filter:
                devices.extend(self.api.get_motion_sensors())

        if len(devices) == 0:
            return [(-1, "%%disabled:No SmartRent devices found!%%")]

        return list(map(lambda device: (device._device_id, device.get_name()), devices))

        