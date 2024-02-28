import json
import time
import random
import logging
import asyncio
import functools


logging_logger = logging.getLogger(__name__)


def retry_call(run, *args, **kwargs):
    tries = kwargs.pop("tries", -1)
    delay = kwargs.pop("delay", 0)
    jitter = kwargs.pop("jitter", 0)
    backoff = kwargs.pop("backoff", 1)
    max_delay = kwargs.pop("max_delay", None)
    exceptions = kwargs.pop("exceptions", BaseException)
    logger = kwargs.pop("logger", logging_logger)

    while tries:
        try:
            return run(*args, **kwargs)
        except exceptions as e:
            tries -= 1
            if not tries:
                raise
            name = f"[{run.__name__}](args:{json.dumps(args, default=str)}, kwargs:{json.dumps(kwargs, default=str)})"
            logger.warning("[%s]%s, retrying[%s] in %s seconds...", type(e).__name__, name, tries, delay)
            time.sleep(delay)
            delay = delay * backoff + (random.uniform(*jitter) if isinstance(jitter, tuple) else jitter)
            delay = min(delay, max_delay or delay)


async def async_retry_call(run, *args, **kwargs):
    tries = kwargs.pop("tries", -1)
    delay = kwargs.pop("delay", 0)
    jitter = kwargs.pop("jitter", 0)
    backoff = kwargs.pop("backoff", 1)
    max_delay = kwargs.pop("max_delay", None)
    exceptions = kwargs.pop("exceptions", BaseException)
    logger = kwargs.pop("logger", logging_logger)

    i = 1
    while tries > 0:
        try:
            return await run(*args, **kwargs)
        except exceptions as e:
            tries -= 1
            if not tries:
                raise
            name = f"[{run.__name__}](args:{json.dumps(args, default=str)}, kwargs:{json.dumps(kwargs, default=str)})"
            logger.warning("[%s]%s, retrying[%s] in %s seconds...", type(e).__name__, name, i, delay)
            await asyncio.sleep(delay)
            delay = delay * backoff + (random.uniform(*jitter) if isinstance(jitter, tuple) else jitter)
            delay = min(delay, max_delay or delay)
            logger.warning(f"{name}, Start {i} retry...")
            i += 1


def retry(exceptions=BaseException, tries=-1, delay=0, max_delay=None, backoff=1, jitter=0, logger=logging_logger):
    retry_kwargs = {
        "exceptions": exceptions, "tries": tries, "delay": delay, "max_delay": max_delay,
        "backoff": backoff, "jitter": jitter, "logger": logger,
    }

    def retry_decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            return retry_call(f, *args, **kwargs, **retry_kwargs)

        @functools.wraps(f)
        async def async_wrapper(*args, **kwargs):
            return await async_retry_call(f,  *args, **kwargs, **retry_kwargs)
        return async_wrapper if asyncio.iscoroutinefunction(f) else wrapper

    return retry_decorator


