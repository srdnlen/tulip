from typing import Iterable

import requests
from .flagid import FlagId
from .flagid_protocol import FlagIdProtocol


class CCITFlagIdProtocol(FlagIdProtocol):
    def __init__(self, endpoint: str) -> None:
        super().__init__(endpoint)
        self._full_flagstores_data_cache: list[dict[str, str]] | None = None
        self._services_cache: set[str] | None = None
        self._flagstores_cache: set[str] | None = None
        self._service_flagstores_mappings_cache: dict[str, list[str]] | None = None
        self.destroy_cache()

    def _get_full_flagstores_data(self) -> list[dict[str, str]]:
        if self._full_flagstores_data_cache is None:
            self._full_flagstores_data_cache = requests.get(self.endpoint).json()[
                "services"
            ]
        return self._full_flagstores_data_cache

    def get_services(self) -> set[str]:
        if self._services_cache is None:
            self._services_cache = set(self.get_service_flagstores_mappings().keys())
        return self._services_cache.copy()

    def get_flagstores(self) -> set[str]:
        if self._flagstores_cache is None:
            self._flagstores_cache = {
                o["id"] for o in self._get_full_flagstores_data()
            }
        return self._flagstores_cache.copy()

    def destroy_cache(self) -> None:
        self._full_flagstores_data_cache = None
        self._services_cache = None
        self._flagstores_cache = None
        self._service_flagstores_mappings_cache = None

    def get_flagids(self, team_id: str) -> Iterable[FlagId]:
        data = requests.get(f"{self.endpoint}/flagIds").json()
        mappings = self.get_service_flagstores_mappings()
        for service in mappings:
            flagstores = mappings[service]
            # Traverse all the flagstores
            for flagstore in flagstores:
                # Traverse ticks of flagstore

                if not flagstore in data:
                    continue
                if not team_id in data[flagstore]:
                    continue

                flagIdsForTeam = data[flagstore][team_id]
                for tick in flagIdsForTeam:
                    # Get all flagids
                    elem = flagIdsForTeam[tick]

                    if type(elem) is dict:
                        for key in elem:
                            yield FlagId(tick=int(tick), content=str(elem[key]), flagstore=flagstore, service=service)
                    elif type(elem) in (list, tuple):
                        for flagid in elem:
                            yield FlagId(tick=int(tick), content=str(flagid), flagstore=flagstore, service=service)
                    else:
                        yield FlagId(tick=int(tick), content=str(elem), flagstore=flagstore, service=service)

    def get_service_flagstores_mappings(self) -> dict[str, list[str]]:
        if self._service_flagstores_mappings_cache is None:
            flagstores = self._get_full_flagstores_data()
            mappings: dict[str, list[str]] = {}
            for fs in flagstores:
                parts = fs["id"].split("-")
                # If only 1 flagstore is present for some service, the flagstore name is
                # the service name and vice versa.
                if len(parts) == 1:
                    svc_name = fs['id']
                    # service does not contain a dash, svc_name = flagstore name
                    mappings[svc_name] = [svc_name]
                else:
                    svc_name = "-".join(parts[:-1])
                    mappings[svc_name] = mappings.get(svc_name, []) + [fs["id"]]
            self._service_flagstores_mappings_cache = mappings
        return {
            service: flagstores.copy()
            for service, flagstores in self._service_flagstores_mappings_cache.items()
        }