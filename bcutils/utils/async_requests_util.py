# -*- coding: utf-8 -*-


import aiohttp
import asyncio
import logging
import itertools
import json
import sys
import requests
import time
from aiohttp import BasicAuth
from collections import Counter
from typing import Union, Optional

from .retry import retry




class AsyncRequestClient(object):


    def __init__(self):
        pass

    @retry(tries=3, delay=1)
    async def make_request(
        self, endpoint: str, method: str, api: str,
        payload: Union[None, dict] = None,
        headers: dict = {},
        proxy: Union[None, str] = None,
        timeout: int = 180,
        auth: Optional[BasicAuth] = None,
        data: Union[None, str] = None,
    ) -> Union[dict, str]:

        endpoint, api = endpoint.rstrip("/"), api.lstrip("/")
        headers = headers or {}
        api_url = f"{endpoint}/{api}"
        kwargs = {
            "timeout": timeout,
            "proxy": proxy,
        }
        if method.upper() == "GET":
            kwargs["params"] = payload
        else:
            if data:
                kwargs["data"] = data
            else:
                kwargs["json"] = payload

        async with aiohttp.ClientSession(headers=headers, auth=auth) as session:
            async with session.request(method, api_url, **kwargs) as response:
                response.raise_for_status()
                if response.content_type == "application/json":
                    body = await response.json()
                else:
                    body = await response.text()
        return body





