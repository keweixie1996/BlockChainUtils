#! -*- coding: utf8 -*-
import os
import json
import math
import logging
import hashlib
import asyncio
import functools
import contextvars
import urllib.parse
import logging.handlers


DEFAULT_FMT = "%(asctime)s [%(levelname)s] (%(process)d:%(threadName)s) [%(module)s:%(lineno)d] %(message)s"

def init_logging(filename=None, level=logging.INFO, days=7, fmt=DEFAULT_FMT, *args, **kwargs):
    if filename:
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        handlers = [logging.handlers.TimedRotatingFileHandler(
            filename, when="MIDNIGHT", backupCount=days, interval=1
        )]
    else:
        handlers = None
    logging.basicConfig(level=level, format=fmt, handlers=handlers)


async def async_shell(cmd):
    process = await asyncio.subprocess.create_subprocess_shell(
        cmd, stderr=asyncio.subprocess.STDOUT, stdout=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        return False, stdout
    return True, stdout


