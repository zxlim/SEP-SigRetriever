#!/usr/bin/env python3

# Proof of concept code for querying a specified online resource for information
# regarding Symantec's signature detections.
#
# MIT License
#
# Copyright (c) 2020 LIM ZHAO XIANG.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# ----------[ IMPORTS ]---------- #
import requests
import sys

from argparse import ArgumentParser, Namespace
from queue import Empty, Queue
from rich import print as rprint
from rich.panel import Panel
from rich.progress import BarColumn, Progress
from rich.traceback import install
from typing import Union
from urllib.parse import urljoin


# --------------------[ CONSTANTS ]-------------------- #
HTTP_OK = 200
LIMIT = 4
MAX_LIMIT = 32
TIMEOUT = 10


# --------------------[ CLASSES ]-------------------- #
class SignatureException(Exception):
    def __init__(
        self,
        message: str
    ) -> None:
        super().__init__(message)


class Symantec(object):
    _LOCALE = "avg_en"
    _PROVIDER = "Broadcom"
    _BASE_URL = "https://www.broadcom.com"
    _API_URL = urljoin(_BASE_URL, "/api/getjsonbyurl")
    _SIGNATURE_URL_FORMAT = urljoin(_BASE_URL, "/support/security-center/attacksignatures/detail?asid={0}")


class SymantecAttackSignature(Symantec):
    def __init__(
        self,
        asid: int
    ) -> None:
        """
        SymantecAttackSignature initialisation.

        :param	(int) asid:				Broadcom Attack Signature ID.
        """
        super().__init__()
        self._loaded = False
        self._url = self._SIGNATURE_URL_FORMAT.format(asid)
        self.asid = asid
        self.name = "None"
        self.description = ("No description", "")
        self.affected_systems = []
        self.severity = "Undetermined"
        self.severity_description = ""
        self.references = []

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return "<SymantecAttackSignature: asid={asid}, loaded={loaded}>".format(**self.__dict__)

    @property
    def asid(
        self
    ) -> int:
        """
        Attack Signature ID.
        """
        return self._asid

    @asid.setter
    def asid(
        self,
        asid: int
    ) -> None:
        """
        Setter for asid attribute.
        """
        if asid < 1:
            raise ValueError("asid must be more than 0")
        self._asid = asid

    @property
    def url(
        self
    ) -> str:
        """
        URL to original provider page for this signature detection.
        """
        return self._url

    @url.setter
    def url(
        self,
        url: str
    ) -> None:
        """
        Setter for url attribute.
        """
        raise AttributeError("url is automatically set based on the asid.")

    @property
    def name(
        self
    ) -> str:
        """
        Attack signature name or title.
        """
        return self._name

    @name.setter
    def name(
        self,
        name: str
    ) -> None:
        """
        Setter for name attribute.
        """
        if len(name.strip()) != 0:
            self._name = name.strip()

    @property
    def description(
        self
    ) -> str:
        """
        Attack signature description.
        """
        return self._description

    @description.setter
    def description(
        self,
        value: Union[list, tuple]
    ) -> None:
        """
        Setter for description attribute.

        Format of value: [DESCRIPTION, ADDITIONAL_INFO]
        """
        if len(value) != 2:
            raise IndexError("value should have a length of 2")
        description, additional_info = value

        if description.strip() != additional_info.strip():
            if description.endswith("."):
                description += " "
            elif len(description) != 0:
                description += ". "

            if len(additional_info.strip()) != 0:
                description += additional_info.strip()
        self._description = description.replace("<BR/>", "\n").strip()

    @property
    def affected_systems(
        self
    ) -> str:
        """
        Systems affected by this signature detection.
        """
        return self._affected_systems

    @affected_systems.setter
    def affected_systems(
        self,
        affected_systems: Union[list, tuple]
    ) -> None:
        """
        Setter for affected_systems attribute.
        """
        if len(affected_systems) == 0:
            self._affected_systems = "Not specified"
        else:
            self._affected_systems = ", ".join(affected_systems).strip()

    @property
    def severity(
        self
    ) -> str:
        """
        Attack signature severity rating.
        """
        return self._severity

    @severity.setter
    def severity(
        self,
        severity: str
    ) -> None:
        """
        Setter for severity attribute.
        """
        if len(severity.strip()) != 0:
            self._severity = severity.strip()

    @property
    def severity_description(
        self
    ) -> str:
        """
        Attack signature severity rating description.
        """
        return self._severity_description

    @severity_description.setter
    def severity_description(
        self,
        severity_description: str
    ) -> None:
        """
        Setter for severity_description attribute.
        """
        if len(severity_description.strip()) != 0:
            self._severity_description = severity_description.strip()

    @property
    def references(
        self
    ) -> str:
        """
        Attack signature references.
        """
        return self._references

    @references.setter
    def references(
        self,
        references: Union[list, tuple]
    ) -> None:
        """
        Setter for references attribute.
        """
        if len(references) == 0:
            self._references = "None"
        else:
            references_list = []
            for reference in references:
                references_list.append("{0}: {1}".format(reference["title"], reference["_url_"]))
            self._references = ", ".join(references_list).strip()

    def info(
        self
    ) -> None:
        """
        Pretty printing of signature information.
        """
        if not self._loaded:
            raise SignatureException("Signature not loaded yet")

        heading = "underline bold"
        severity_style = "green bold"
        if self.severity.lower() == "medium":
            severity_style = "yellow bold"
        elif self.severity.lower() == "high":
            severity_style = "red bold"
        severity = "[{0}]{1}[/{0}]".format(severity_style, self.severity)

        rprint(Panel(
            "[{0}]URL[/{0}]\n{1}\n\n".format(heading, self.url) +
            "[{0}]Detection Name[/{0}]\n{1}\n\n".format(heading, self.name) +
            "[{0}]Description[/{0}]\n{1}\n\n".format(heading, self.description) +
            "[{0}]Severity[/{0}]\n{1}\n{2}\n\n".format(heading, severity, self.severity_description) +
            "[{0}]Affected System(s)[/{0}]\n{1}\n\n".format(heading, self.affected_systems) +
            "[{0}]Reference(s)[/{0}]\n{1}\n".format(heading, self.references)
        ))

    def fetch_from_provider(
        self
    ) -> None:
        """
        Retrieve signature information from the online provider.
        """
        params = {
            "vanityurl": "support/security-center/attacksignatures/detail",
            "locale": self._LOCALE,
            "asid": self.asid
        }

        response = requests.get(self._API_URL, params=params, timeout=TIMEOUT)
        if response.status_code != HTTP_OK:
            raise SignatureException("Failed retrieve signature data from {0}: HTTP {1}".format(self._PROVIDER, response.status_code))

        details = response.json()
        if not details.get("title", None):
            raise SignatureException("Null signature retrieved for asid: {0}".format(self.asid))

        self.name = details.get("signature_name", "")
        self.affected_systems = details.get("affected_systems", [])
        self.severity = details.get("severity", "")
        self.severity_description = details.get("severity_description", "")
        self.references = details.get("additional_references", [])
        self.description = (
            details.get("description", "No description"),
            details.get("additional_info", "")
        )
        self._loaded = True


class SymantecSearcher(Symantec):
    def __init__(
        self,
        keyword: str,
        limit: int
    ) -> None:
        """
        SymantecSearcher initialisation.

        :param	(str) keyword:			Signature detection keywords to search.
        :param	(int) limit:			Amount of signatures to fetch per cycle.
        """
        super().__init__()
        self.keywords = keyword
        self.limit = limit
        self.search_results = Queue()

    def __repr__(
        self
    ) -> str:
        return self.__str__()

    def __str__(
        self
    ) -> str:
        return "<SymantecSearcher: keywords={keywords}, limit={limit}>".format(**self.__dict__)

    @property
    def keywords(
        self
    ) -> list:
        """
        Keywords to search online provider to retrieve attack signatures.
        """
        return self._keywords

    @keywords.setter
    def keywords(
        self,
        keywords: str
    ) -> None:
        """
        Setter for keywords attribute.
        """
        self._keywords = keywords.lower().replace(".", " ").split(" ")

    @property
    def limit(
        self
    ) -> int:
        """
        Search limit per cycle.
        """
        return self._limit

    @limit.setter
    def limit(
        self,
        limit: int
    ) -> None:
        """
        Setter for limit attribute.
        """
        if limit < 1:
            raise ValueError("limit must be more than 0")
        elif limit > MAX_LIMIT:
            # Let's not hit the online provider too hard shall we...
            raise ValueError("limit must be less than {0}".format(MAX_LIMIT))
        self._limit = limit

    def search(
        self
    ) -> int:
        """
        Searches for relevant signature information using the keywords
        provided.

        :return	(int) count:			Total count of the result of the search.
        """
        params = {
            "vanityurl": "support/security-center/attacksignatures",
            "locale": self._LOCALE
        }

        response = requests.get(self._API_URL, params=params, timeout=TIMEOUT)

        if response.status_code != HTTP_OK:
            raise SignatureException("Failed to retrieve signature list from {0}: HTTP {1}".format(self._PROVIDER, response.status_code))

        all_signatures = response.json()["attack_signature_listings"]
        for signature in all_signatures:
            if all(kw in signature["title"].lower() for kw in self.keywords):
                asid = int(signature["_url_"].split("?")[1].lstrip("asid="))
                self.search_results.put(SymantecAttackSignature(asid))
        return self.search_results.qsize()

    def fetch_signatures(
        self
    ) -> list:
        """
        Fetch signature information from the online provider with respect to
        the limit provided.

        :return	(list) result:			Signature information.
        """
        fetched_signatures = []
        to_fetch = self.limit

        if self.search_results.qsize() < self.limit:
            to_fetch = self.search_results.qsize()

        progress = Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
        )

        with progress:
            loader = progress.add_task(
                "[bold]Fetching {0} signature(s)...[/bold]".format(to_fetch),
                total=to_fetch
            )

            while not self.search_results.empty() and len(fetched_signatures) < to_fetch:
                try:
                    signature = self.search_results.get_nowait()
                except Empty:
                    break

                try:
                    signature.fetch_from_provider()
                    fetched_signatures.append(signature)
                    progress.update(loader, advance=1)
                except requests.exceptions.Timeout:
                    _error("Failed to connect to provider endpoint: {0}".format(self._PROVIDER), True)
                except SignatureException as error_msg:
                    _error("{0}".format(error_msg), True)
                except KeyboardInterrupt:
                    _warn("Keyboard interrupt detected\n", True)
        return fetched_signatures


# --------------------[ FUNCTIONS ]-------------------- #
def _warn(
    message: str,
    trailing_newline: bool = False
) -> None:
    """
    Prints a warning message to console.

    :param	(str) message:			    Message to display.
    :param  (bool) trailing_newline:    Whether to add a new line at the start.
    """
    if trailing_newline:
        rprint("\n[yellow bold]Warn[/yellow bold]: {0}".format(message))
    else:
        rprint("[yellow bold]Warn[/yellow bold]: {0}".format(message))


def _error(
    message: str,
    trailing_newline: bool = False
) -> None:
    """
    Prints an error message to console.

    :param	(str) message:			    Message to display.
    :param  (bool) trailing_newline:    Whether to add a new line at the start.
    """
    if trailing_newline:
        rprint("\n[red bold]Error[/red bold]: {0}".format(message))
    else:
        rprint("[red bold]Error[/red bold]: {0}".format(message))


def _search_symantec(
    keyword: str,
    limit: int
) -> int:
    """
    Symantec Alert Detection Definition searcher.

    :param	(str) keyword:			    Keywords used to search for signatures.
    :param	(int) limit:			    Amount of signatures to fetch per cycle.
    :return	(int):					    Exit code.
    """
    if limit < 1 or limit > MAX_LIMIT:
        _error("Limit must be more than 0 and less than {0}".format(MAX_LIMIT))
        return 1

    symantec = SymantecSearcher(keyword, limit)
    rprint("Searching for signatures with keyword [bold underline]{0}[/bold underline]".format(keyword))
    result_count = symantec.search()
    rprint("Found [bold underline]{0}[/bold underline] matching signature(s).".format(result_count))

    for idx in range(0, result_count, limit):
        for signature in symantec.fetch_signatures():
            signature.info()

        if not symantec.search_results.empty():
            rprint("[bold underline]{0}[/bold underline] signatures left.".format(symantec.search_results.qsize()))
            if input("Press <ENTER> to continue, <Q + ENTER> to quit: ").lower() == "q":
                break
    return 0


def _parse_cmd_args() -> Namespace:
    """
    Parse command-line arguments.
    """
    parser = ArgumentParser(
        description="Simplify your life when handling Symantec detection alerts."
    )
    parser.add_argument(
        "keyword", type=str, help="Specific keywords of the detection."
    )
    parser.add_argument(
        "--limit", type=int, default=LIMIT,
        help="Maximum signatures to fetch per cycle. Defaults to {0}.".format(LIMIT)
    )
    return parser.parse_args()


# --------------------[ MAIN ]-------------------- #
def main() -> int:
    """
    Main function. Executed if script is called standalone.
    """
    args = _parse_cmd_args()
    try:
        return _search_symantec(args.keyword, args.limit)
    except KeyboardInterrupt:
        _warn("Keyboard interrupt detected\n", True)
        return 1


if __name__ == "__main__":
    # Initialise the Rich Traceback handler.
    install()
    sys.exit(
        main()
    )
