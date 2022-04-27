from typing import Union
from typing_extensions import Self
import httpx
from .api_settings import api_settings

import json
import webbrowser
import sys
import re

"""
Veeam Easy Connect
This module does all the set up to allow you to connect to Veeam APIs
"""


class VeeamEasyConnect:

    SUPPORTED_API_TYPES = (
        "aws",
        "azure",
        "entman",
        "gcp",
        "o365",
        "spc",
        "vbr",
    )

    verify: bool = True
    api_type: str = None
    access_token: str = None
    refresh_token: str = None
    oauth_headers: dict = None
    res_json_oauth: dict = None
    res_json_basic: dict = None

    def __init__(
        self,
        username: str = None,
        password: str = None,
        access_token: str = None,
        verify=True,
    ) -> None:
        if not access_token and (not password or not username):
            raise RuntimeError("Must provide username and password or access token")

        self.username = username
        self.password = password
        self.access_token = access_token
        self.verify = verify
        self.oauth_headers = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
        }
        self.__get_settings()
        self.api_type = None

    def _prepare_entman_login(self):
        self.basic_url = f"https://{self.address}:{self.url_port}{self.url_end}"
        self.b_auth = httpx.BasicAuth(self.username, self.password)
        self.basic_headers = {
            "accept": "application/json",
        }

    def __entman_login(self) -> None:
        self._prepare_entman_login()
        self.response = httpx.post(
            self.basic_url,
            headers=self.basic_headers,
            auth=self.b_auth,
            verify=self.verify,
        )
        self._process_entman_login_response()

    async def __async_entman_login(self) -> None:
        self._prepare_entman_login()
        params = {
            "headers": self.oauth_headers,
            "verify": self.verify,
            "timeout": httpx.Timeout(timeout=5.0),
        }
        async with httpx.AsyncClient(**params) as client:
            self.response: httpx.Response = await client.post(
                self.oauth_url,
                data=self.oauth_data,
            )
            self.response.raise_for_status()
        self._process_entman_login_response()

    def _process_entman_login_response(self) -> None:
        self.basic_id = self.response.headers["X-RestSvcSessionId"]
        self.res_json_basic = self.response.json()
        self.request_header = self.get_request_header()

    def _prepare_login_request_with_refresh_token(
        self, address: str = None, refresh_token: str = None
    ) -> None:
        if self.api_type == "ent_man":
            raise RuntimeError(
                "Veeam Backup Enterprise Manager does not support refresh tokens"
            )

        # Address is optional here because we're potentially refreshing an existing session token
        if address:
            self.address = address

        # Again, we could be mid-flight, so pull from the current state if we weren't given a refresh token
        if not refresh_token:
            refresh_token = self.get_refresh_token()

        self.oauth_url = f"https://{self.address}"
        if self.url_port:
            self.oauth_url += f":{self.url_port}"
        self.oauth_url += f"{self.url_end}"
        self.oauth_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

    async def async_login_with_refresh_token(
        self, address: str = None, refresh_token: str = None
    ) -> None:
        self._prepare_login_request_with_refresh_token(
            address=address, refresh_token=refresh_token
        )
        params = {
            "headers": self.oauth_headers,
            "verify": self.verify,
            "timeout": httpx.Timeout(timeout=5),
        }
        async with httpx.AsyncClient(**params) as client:
            self.response = await client.post(
                self.oauth_url,
                data=self.oauth_data,
            )
        self._process_authorisation_response()

    def login_with_refresh_token(
        self, address: str = None, refresh_token: str = None
    ) -> None:
        self._prepare_login_request_with_refresh_token(
            address=address, refresh_token=refresh_token
        )
        self.response = httpx.post(
            self.oauth_url,
            data=self.oauth_data,
            headers=self.oauth_headers,
            verify=self.verify,
        )
        self._process_authorisation_response()

    def _prepare_login_request(self, address: str) -> None:
        # set up each login url endpoint and api version
        self.address = address
        self.oauth_url = f"https://{self.address}"
        if self.url_port:
            self.oauth_url += f":{self.url_port}"
        self.oauth_url += f"{self.url_end}"
        self.oauth_data = {
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
        }

    async def async_login(self, address: str) -> None:
        if self.api_type == "ent_man":
            self.address = address
            await self.__async_entman_login()
            return

        self._prepare_login_request(address)
        params = {
            "headers": self.oauth_headers,
            "verify": self.verify,
            "timeout": httpx.Timeout(timeout=5),
        }
        async with httpx.AsyncClient(**params) as client:
            self.response = await client.post(
                self.oauth_url,
                data=self.oauth_data,
            )
            self._process_authorisation_response()

    def login(self, address: str) -> None:
        if self.api_type == "ent_man":
            self.address = address
            self.__entman_login()
            return

        self._prepare_login_request(address)
        self.response = httpx.post(
            self.oauth_url,
            data=self.oauth_data,
            headers=self.oauth_headers,
            verify=self.verify,
        )
        self._process_authorisation_response()

    def _process_authorisation_response(self) -> None:

        self.response.raise_for_status()
        self.res_json_oauth = self.response.json()

        if "access_token" in self.res_json_oauth:
            self.set_access_token(self.res_json_oauth["access_token"])

        if "refresh_token" in self.res_json_oauth:
            self.set_refresh_token(self.res_json_oauth["refresh_token"])

        if "mfa_token" not in self.res_json_oauth or not self.res_json_oauth["mfa_token"]:
            self.request_header = self.get_request_header()
            return

        print(
            f"MFA Token in response - use 'mfa_token_login' to with access code to continue"
        )

    def mfa_token_login(self, code: str) -> None:
        self.token = self.res_json_oauth["mfa_token"]
        self.mfa_url = f"https://{self.address}"
        if self.url_port:
            self.mfa_url += f":{self.url_port}"
        self.mfa_url += self.url_end
        self.mfa_data = {"grant_type": "Mfa", "mfa_token": self.token, "mfa_code": code}
        # I don't think I need to change the content-type on this request- not clear

        self.response = httpx.post(
            self.mfa_url,
            data=self.mfa_data,
            headers=self.oauth_headers,
            verify=self.verify,
        )
        self.response.raise_for_status()
        self.res_json_oauth = self.response.json()
        self.request_header = self.get_request_header()

    def save_token(self, file_name: str) -> None:
        # Added a check in case extension was included
        file_name = file_name.split(".")[0] if "." in file_name else file_name

        if self.api_type == "ent_man":
            data = self.response.headers
        else:
            data = self.res_json_oauth
        with open(f"{file_name}.json", "w") as token_file:
            json.dump(dict(data), token_file)

    def get_body_data(self) -> dict:
        if self.api_type == "ent_man":
            return self.res_json_basic

        return self.res_json_oauth

    def get_header_data(self) -> dict:
        return self.response.headers

    def set_access_token(self, token: str) -> None:
        self.access_token = token

    def get_access_token(self) -> Union[str, None]:
        if self.api_type == "ent_man":
            return self.basic_id

        if self.access_token:
            return self.access_token

        if "access_token" in self.res_json_oauth:
            return self.res_json_oauth["access_token"]

    def set_refresh_token(self, token: str) -> None:
        self.refresh_token = token

    def get_refresh_token(self) -> Union[str, None]:
        if self.api_type == "ent_man":
            return None

        if self.refresh_token:
            return self.refresh_token

        if self.res_json_oauth and "refresh_token" in self.res_json_oauth:
            return self.res_json_oauth["refresh_token"]

    def get_request_header(self) -> dict:
        if self.api_type == "ent_man":
            return {
                "accept": "application/json",
                "X-RestSvcSessionId": self.basic_id,
            }

        if not self.api_type:
            raise RuntimeError("No api type selected")

        headers = self.api_settings[self.api_type]["headers"]
        if "application/x-www-form-urlencoded" in headers.values():
            del headers["content-type"]
        bearer_string = self.get_access_token_with_bearer()
        headers["authorization"] = bearer_string
        return headers

    def save_request_header(self, file_name: str) -> None:
        file_name = (
            file_name.split(".")[0] + ".json"
            if "." in file_name
            else file_name + ".json"
        )
        headers = self.get_request_header()
        with open(file_name, "w") as headers_file:
            json.dump(headers, headers_file)

    def get_access_token_with_bearer(self) -> str:
        if self.api_type == "ent_man":
            return self.basic_id

        token = self.get_access_token()
        return f"Bearer " + token

    def get_mfa_token(self) -> str:
        return self.res_json_oauth["mfa_token"]

    # load in data from the settings file - makes this easier to update
    def __get_settings(self) -> None:
        self.api_settings = api_settings
        # with open("api_settings.json", "r") as settings_file:
        #     self.api_settings = json.load(settings_file)

    ##
    # Api switchers shape request headers and url structure to suit the target api
    def aws(self, address: str = None) -> Self:
        self.switch_api("aws", address)
        return self

    def gcp(self, address: str = None) -> Self:
        self.switch_api("gcp", address)
        return self

    def azure(self, address: str = None) -> Self:
        self.switch_api("azure", address)
        return self

    def vbr(self, address: str = None) -> Self:
        self.switch_api("vbr", address)
        return self

    def o365(self, address: str = None) -> Self:
        self.switch_api("o365", address)
        return self

    def spc(self, address: str = None) -> Self:
        self.switch_api("spc", address)
        return self

    def ent_man(self, address: str = None) -> Self:
        self.switch_api("ent_man", address)
        return self

    ##
    # Create your own API endpoint
    def custom(self, settings: dict) -> Self:
        if "address" in settings:
            self.address = settings["address"]
        if "port" in settings:
            self.url_port = settings["port"]
        self.url_end = settings["url"]
        self.oauth_headers = settings["header"]
        self.api_version = settings["api_version"]
        return self

    def switch_api(self, api_type: str, address: str = None) -> None:

        if api_type not in self.SUPPORTED_API_TYPES:
            print("API type not found")
            return

        if address:
            self.address = address

        self.api_type = api_type

        if api_type == "o365":
            self.url_port = self.api_settings["o365"]["port"]
            self.url_end = self.api_settings["o365"]["url"]
            self.api_version = self.api_settings["o365"]["api_version"]
            return

        if api_type == "aws":
            self.url_port = self.api_settings["aws"]["port"]
            self.url_end = self.api_settings["aws"]["url"]
            self.oauth_headers = self.api_settings["aws"]["headers"]
            self.api_version = self.api_settings["aws"]["api_version"]
            return

        if api_type == "vbr":
            self.url_port = self.api_settings["vbr"]["port"]
            self.url_end = self.api_settings["vbr"]["url"]
            self.oauth_headers = self.api_settings["vbr"]["headers"]
            self.api_version = self.api_settings["vbr"]["api_version"]
            return

        if api_type == "azure":
            self.url_port = self.api_settings["azure"]["port"]
            self.url_end = self.api_settings["azure"]["url"]
            self.oauth_headers = self.api_settings["azure"]["headers"]
            self.api_version = self.api_settings["azure"]["api_version"]
            return

        if api_type == "gcp":
            self.url_port = self.api_settings["gcp"]["port"]
            self.url_end = self.api_settings["gcp"]["url"]
            self.oauth_headers = self.api_settings["gcp"]["headers"]
            self.api_version = self.api_settings["gcp"]["api_version"]
            return

        if api_type == "ent_man":
            self.url_port = self.api_settings["ent_man"]["port"]
            self.url_end = self.api_settings["ent_man"]["url"]
            self.api_version = "None"
            return

        if api_type == "spc":
            self.url_port = self.api_settings["spc"]["port"]
            self.url_end = self.api_settings["spc"]["url"]
            self.oauth_headers = self.api_settings["spc"]["headers"]
            self.api_version = self.api_settings["spc"]["api_version"]
            return

        if api_type == "vone":
            self.url_port = self.api_settings["vone"]["port"]
            self.url_end = self.api_settings["vone"]["url"]
            self.oauth_headers = self.api_settings["vone"]["headers"]
            self.api_version = self.api_settings["vone"]["api_version"]
            return

    def _create_url(self, request: str, full: bool) -> str:
        # if it's truly a "complete" url, it'll have a proto prefix
        if full and request[:4] == "http":
            return request

        if request.startswith("/"):
            request = request[1:]

        if self.api_type == "ent_man":
            # ":9398/api/sessionMngr/?v=latest"
            url_middle = "/".join(self.url_end.split("/")[:-2]) + "/"
            # the beginning / has been removed from the request variable
            # No api_version needs to be added in this case
            rtn = f"https://{self.address}"
            if self.url_port:
                rtn += f":{self.url_port}"
            rtn += f"{url_middle}{request}"

            return rtn

        # ":11005/api/v1/token"
        # check if oauth is in the url_end as that means we need to go back
        # two splits unlike the others that need 1
        # split_qty = -2 if "oauth" in self.url_end else -1
        url_middle = re.split("oauth|v[0-9]", self.url_end)[0]
        # url_middle = "/".join(self.url_end.split("/")[:split_qty]) + "/"
        # the beginning / has been removed from the request variable
        # But the api_version doesn't have the trailing / so needs to be added
        rtn = f"https://{self.address}"
        if self.url_port:
            rtn += f":{self.url_port}"
        rtn += f"{url_middle}{self.api_version}/{request}"
        return rtn

    def get(self, url: str, full=True) -> dict:
        url = self._create_url(url, full)
        return self._http_exec("get", url)

    async def async_get(self, url: str, full=True, timeout: int = 5) -> dict:
        url = self._create_url(url, full)
        return await self._async_http_exec("get", url, timeout=timeout)

    def post(self, url: str, data: dict, full=True) -> dict:
        url = self._create_url(url, full)
        return self._http_exec("post", url, data)

    async def async_post(
        self, url: str, data: dict, full=True, timeout: int = 5
    ) -> dict:
        url = self._create_url(url, full)
        return await self._async_http_exec("post", url, data, timeout=timeout)

    def put(self, url: str, data: dict, full=True) -> dict:
        url = self._create_url(url, full)
        return self._http_exec("put", url, data)

    async def async_put(
        self, url: str, data: dict, full=True, timeout: int = 5
    ) -> dict:
        url = self._create_url(url, full)
        return await self._async_http_exec("put", url, data, timeout=timeout)

    def patch(self, url: str, data: dict, full=True) -> dict:
        url = self._create_url(url, full)
        return self._http_exec("patch", url, data)

    async def async_patch(
        self, url: str, data: dict, full=True, timeout: int = 5
    ) -> dict:
        url = self._create_url(url, full)
        return await self._async_http_exec("patch", url, data, timeout=timeout)

    def delete(self, url: str, full=True) -> dict:
        url = self._create_url(url, full)
        return self._http_exec("delete", url)

    async def async_delete(self, url: str, full=True, timeout: int = 5) -> dict:
        url = self._create_url(url, full)
        return await self._async_http_exec("delete", url, timeout=timeout)

    def _http_exec(self, method: str, url: str, data: dict = None) -> dict:
        params = {
            "url": url,
            "headers": self.get_request_header(),
            "verify": self.verify,
            "timeout": httpx.Timeout(timeout=30.0),
        }
        if data:
            if params["headers"]["content-type"] == "application/json":
                params["json"] = data
            else:
                params["data"] = data

        resp: httpx.Response = getattr(httpx, method)(**params)
        resp.raise_for_status()
        if len(resp.text) > 1:
            return resp.json()

        return True

    async def _async_http_exec(
        self, method: str, url: str, data: dict = None, timeout: int = 5
    ) -> dict:
        params = {
            "headers": self.get_request_header(),
            "verify": self.verify,
            "timeout": httpx.Timeout(timeout=timeout),
        }

        async with httpx.AsyncClient(**params) as client:

            req_params = {}
            if data:
                if params["headers"]["content-type"] == "application/json":
                    req_params["json"] = data
                else:
                    req_params["data"] = data

            method = getattr(client, method)
            resp: httpx.Response = await method(url, **req_params)
            resp.raise_for_status()
            if len(resp.text) > 1:
                return resp.json()

            return True

    def update_api_version(self, api_version: str) -> None:
        if self.api_type == "ent_man":
            return

        self.oauth_headers["x-api-version"] = api_version
        self.api_version = api_version

    def get_api_version(self) -> None:
        if self.api_type == "ent_man":
            return "latest"

        if len(self.url_end) > 0:
            return self.api_version
        else:
            raise Exception("The API type needs to be set")

    # being worked on
    def __sso_login(self, address: str, sso_username: str, sso_address: str):
        # set up for first request

        # remove the /token from the url_end brought in from config file
        sso_url = (
            "/".join(self.url_end.split("/")[0:3])
            + "/identityProvider/signOnUrl?userName="
        )

        # create the full url
        url = f"https://{address}:{sso_url}{sso_username}"
        api_version = self.oauth_headers.get("x-api-version")
        headers = {"x-api-version": api_version}

        # send first request
        data = httpx.get(url, headers=headers, verify=self.verify)
        data.raise_for_status()
        data_json = data.json()

        # confirm SSO
        sso_url = data_json.get("redirectToUrl")
        print("opening webpage")
        webbrowser.open(sso_url)
        confirm = input("continue? y/n")
        if confirm == "n":
            sys.exit()

        # second request set up
        data = {"username": self.username, "password": self.password}
        headers["content-type"] = "x-www-form-urlencoded"

        # get the code from the response to add to the new url
        saml_code = sso_url.split("=")[1]
        saml_url = f"https://{sso_address}//adfs/ls/?SAMLRequest={saml_code}"

        # send third request

        saml_res = httpx.post(saml_url, data=data, headers=headers, verify=self.verify)
        saml_res.raise_for_status()

        # third request set up
        token = saml_res.json().get("value")

        login_url = f"https://{sso_address}:11005/api/v1/identityProvider/token"

        headers.pop("content-type")
        token_data = {"SamlResponse": token}

        # send third request
        self.respose = httpx.post(
            login_url, headers=headers, data=token_data, verify=self.verify
        )
        self.response.raise_for_status()

        # if all has gone well, set the data as normal
        self.res_json_oauth = self.response.json()
        self.request_header = self.get_request_header()
