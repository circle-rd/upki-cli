# -*- coding: utf-8 -*-

"""
UPKI Logger Module.

This module provides logging functionality for the UPKI CLI client.
Supports file logging with rotation and optional syslog output.
"""

import os
import errno
import sys
import logging
import logging.handlers
from typing import Optional, Union


class UPKILogger:
    """
    Logging class for UPKI CLI client.

    Allows logging to file and optional syslog server.
    Supports colored console output in verbose mode.
    """

    def __init__(
        self,
        filename: str,
        level: Union[int, str] = logging.WARNING,
        proc_name: Optional[str] = None,
        verbose: bool = False,
        backup: int = 3,
        when: str = "midnight",
        syshost: Optional[str] = None,
        sysport: int = 514,
    ) -> None:
        """
        Initialize the logger.

        Args:
            filename: Path to the log file.
            level: Logging level (int or string).
            proc_name: Process name for the logger.
            verbose: Enable colored console output.
            backup: Number of backup log files to keep.
            when: When to rotate the log file.
            syshost: Syslog server host (not currently used).
            sysport: Syslog server port.
        """
        if proc_name is None:
            proc_name = __name__

        try:
            self.level = int(level)
        except ValueError:
            self.level = logging.INFO

        self.logger = logging.getLogger(proc_name)

        try:
            os.makedirs(os.path.dirname(filename))
        except OSError as err:
            if (err.errno != errno.EEXIST) or not os.path.isdir(
                os.path.dirname(filename)
            ):
                raise Exception(err) from err

        try:
            handler = logging.handlers.TimedRotatingFileHandler(
                filename, when=when, backupCount=backup
            )
        except IOError:
            sys.stderr.write(f"[!] Unable to write to log file: {filename}\n")
            sys.exit(1)

        formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(self.level)

        self.verbose = verbose

    def debug(
        self, msg: str, color: Optional[str] = None, light: Optional[bool] = None
    ) -> None:
        """Shortcut to debug message."""
        self.write(msg, level=logging.DEBUG, color=color, light=light)

    def info(
        self, msg: str, color: Optional[str] = None, light: Optional[bool] = None
    ) -> None:
        """Shortcut to info message."""
        self.write(msg, level=logging.INFO, color=color, light=light)

    def warning(
        self, msg: str, color: Optional[str] = None, light: Optional[bool] = None
    ) -> None:
        """Shortcut to warning message."""
        self.write(msg, level=logging.WARNING, color=color, light=light)

    def error(
        self, msg: str, color: Optional[str] = None, light: Optional[bool] = None
    ) -> None:
        """Shortcut to error message."""
        self.write(msg, level=logging.ERROR, color=color, light=light)

    def critical(
        self, msg: str, color: Optional[str] = None, light: Optional[bool] = None
    ) -> None:
        """Shortcut to critical message."""
        self.write(msg, level=logging.CRITICAL, color=color, light=light)

    def write(
        self,
        message: str,
        level: Optional[Union[int, str]] = None,
        color: Optional[str] = None,
        light: Optional[bool] = None,
    ) -> bool:
        """
        Accept log message with level set with string or logging int.

        Args:
            message: The message to log.
            level: Logging level (int or string).
            color: Color for console output.
            light: Use light color variant.

        Returns:
            True if message was logged, False if empty message.
        """
        message = str(message).rstrip()

        if message == "":
            return True

        if level is None:
            level = self.level

        if isinstance(level, str):
            level = level.upper()
            if level == "DEBUG":
                level = logging.DEBUG
            elif level in ["INFO", "INFOS"]:
                level = logging.INFO
            elif level == "WARNING":
                level = logging.WARNING
            elif level == "ERROR":
                level = logging.ERROR
            elif level == "CRITICAL":
                level = logging.CRITICAL
            else:
                level = self.level

        if level == logging.DEBUG:
            def_color = "BLUE"
            def_light = True
            prefix = "*"
            self.logger.debug(message)
        elif level == logging.INFO:
            def_color = "GREEN"
            def_light = False
            prefix = "+"
            self.logger.info(message)
        elif level == logging.WARNING:
            def_color = "YELLOW"
            def_light = False
            prefix = "-"
            self.logger.warning(message)
        elif level == logging.ERROR:
            def_color = "RED"
            def_light = False
            prefix = "!"
            self.logger.error(message)
        elif level == logging.CRITICAL:
            def_color = "RED"
            def_light = True
            prefix = "!"
            self.logger.critical(message)
        else:
            raise Exception("Invalid log level")

        if color is None:
            color = def_color
        if light is None:
            light = def_light

        if self.verbose:
            color = color.upper()
            c = "\033[1" if light else "\033[0"
            if color == "BLACK":
                c += ";30m"
            elif color == "BLUE":
                c += ";34m"
            elif color == "GREEN":
                c += ";32m"
            elif color == "CYAN":
                c += ";36m"
            elif color == "RED":
                c += ";31m"
            elif color == "PURPLE":
                c += ";35m"
            elif color == "YELLOW":
                c += ";33m"
            elif color == "WHITE":
                c += ";37m"
            else:
                c += "m"

            if level >= self.level:
                sys.stdout.write(f"{c}[{prefix}] {message}\033[0m\n")

        return True
