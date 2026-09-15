"""GeoIP enrichment: country code and ASN for a source IP, via MaxMind GeoLite2."""

import sys
from dataclasses import dataclass

from honeypot.core.config import settings


@dataclass
class GeoInfo:
    country_code: str | None
    asn: int | None
    asn_org: str | None


_geoip_city_reader = None
_geoip_asn_reader = None


def _get_geoip_city():
    global _geoip_city_reader
    if _geoip_city_reader is not None:
        return _geoip_city_reader
    db_path = settings.geoip_db_path
    if not db_path.exists():
        print(f"[geoip] GeoLite2-City.mmdb not found at {db_path}", file=sys.stderr)
        return None
    try:
        import maxminddb
        _geoip_city_reader = maxminddb.open_database(str(db_path))
        return _geoip_city_reader
    except Exception as exc:
        print(f"[geoip] City load failed: {exc}", file=sys.stderr)
        return None


def _get_geoip_asn():
    global _geoip_asn_reader
    if _geoip_asn_reader is not None:
        return _geoip_asn_reader
    db_path = settings.geoip_asn_db_path
    if not db_path.exists():
        print(f"[geoip] GeoLite2-ASN.mmdb not found at {db_path}", file=sys.stderr)
        return None
    try:
        import maxminddb
        _geoip_asn_reader = maxminddb.open_database(str(db_path))
        return _geoip_asn_reader
    except Exception as exc:
        print(f"[geoip] ASN load failed: {exc}", file=sys.stderr)
        return None


def enrich(source_ip: str) -> GeoInfo:
    """Return country code and ASN for an IP. Missing DBs yield None fields."""
    country_code = None
    city = _get_geoip_city()
    if city is not None:
        try:
            rec = city.get(source_ip)
            if rec:
                country_code = (rec.get("country", {}).get("iso_code")
                                or rec.get("registered_country", {}).get("iso_code"))
        except Exception as exc:
            print(f"[geoip] city lookup error for {source_ip}: {exc}", file=sys.stderr)

    asn = asn_org = None
    asndb = _get_geoip_asn()
    if asndb is not None:
        try:
            rec = asndb.get(source_ip)
            if rec:
                asn = rec.get("autonomous_system_number")
                asn_org = rec.get("autonomous_system_organization")
        except Exception as exc:
            print(f"[geoip] asn lookup error for {source_ip}: {exc}", file=sys.stderr)

    return GeoInfo(country_code=country_code, asn=asn, asn_org=asn_org)
