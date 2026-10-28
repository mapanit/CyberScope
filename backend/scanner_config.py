from dataclasses import dataclass


@dataclass(frozen=True)
class AmassProfile:
    name: str
    mode: str
    timeout: int


@dataclass(frozen=True)
class WebScannerProfile:
    name: str
    depth: int
    concurrency: int

    def get_katana_arguments(self, target_url: str) -> list[str]:
        return [
            "katana",
            "-u",
            target_url,
            "-d",
            str(self.depth),
            "-c",
            str(self.concurrency),
        ]


@dataclass(frozen=True)
class RetireProfile:
    name: str
    severity_filter: str | None
    include_js: bool


@dataclass(frozen=True)
class NmapProfile:
    name: str
    arguments: str

    def get_full_arguments(self) -> str:
        return self.arguments


AMASS_PROFILES = {
    "quick_passive": AmassProfile("Quick passive", "passive", 120),
    "standard_passive": AmassProfile("Standard passive", "passive", 300),
    "active_scan": AmassProfile("Active scan", "active", 600),
    "aggressive": AmassProfile("Aggressive", "active", 900),
}

WEB_SCANNER_PROFILES = {
    "low": WebScannerProfile("Low", 2, 10),
    "medium": WebScannerProfile("Medium", 3, 50),
    "high": WebScannerProfile("High", 5, 100),
}

RETIRE_PROFILES = {
    "all_except_low": RetireProfile("All except low", "low", True),
    "all": RetireProfile("All severities", None, True),
    "high": RetireProfile("High and critical", "medium", True),
}

NMAP_PROFILES = {
    "quick": NmapProfile("Quick", "-T3 -F"),
    "standard": NmapProfile("Standard", "-sV -sC --top-ports 1000 -T3"),
    "deep": NmapProfile("Deep", "-sV -sC -p- -T3"),
    "aggressive": NmapProfile("Aggressive", "-sV -sC -p- -T4"),
}


def _get_profile(profiles: dict, name: str):
    try:
        return profiles[name]
    except KeyError as exc:
        raise ValueError(f"Unknown scanner profile: {name}") from exc


def get_amass_profile(name: str = "standard_passive") -> AmassProfile:
    return _get_profile(AMASS_PROFILES, name)


def get_web_scanner_profile(name: str = "medium") -> WebScannerProfile:
    return _get_profile(WEB_SCANNER_PROFILES, name)


def get_retire_profile(name: str = "all_except_low") -> RetireProfile:
    return _get_profile(RETIRE_PROFILES, name)


def get_nmap_profile(name: str = "standard") -> NmapProfile:
    return _get_profile(NMAP_PROFILES, name)
