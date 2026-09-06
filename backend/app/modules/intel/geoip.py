"""Structured, opt-in IP infrastructure enrichment."""

from __future__ import annotations

import ipaddress
from typing import Any

import requests

GEOIP_URL = "https://ipwho.is/{ip}"


def lookup_ip(ip: str, *, timeout_seconds: float = 5.0) -> dict[str, Any]:
    """Return location/ISP intelligence for a public IP without raising.

    GeoIP is intentionally opt-in at the orchestration layer: querying a
    third-party provider shares an address extracted from email evidence.
    Private, loopback, reserved, and malformed addresses are never sent.
    """
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return {"ip": ip, "status": "invalid", "location": None, "isp": None}
    if not ipaddress.ip_address(normalized_ip).is_global:
        return {"ip": normalized_ip, "status": "not_public", "location": None, "isp": None}
    try:
        response = requests.get(GEOIP_URL.format(ip=normalized_ip), timeout=timeout_seconds)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        return {"ip": normalized_ip, "status": "unavailable", "location": None, "isp": None, "error": str(exc)}
    if data.get("success") is False:
        return {"ip": normalized_ip, "status": "unavailable", "location": None, "isp": None, "error": data.get("message", "Provider lookup failed")}
    return {
        "ip": normalized_ip,
        "status": "ok",
        "location": {
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
        },
        "isp": data.get("connection", {}).get("isp"),
        "asn": data.get("connection", {}).get("asn"),
    }


def get_coordinates(ips: list[str]) -> list[tuple[float, float]]:
    """Compatibility helper returning only successful latitude/longitude pairs."""
    coordinates: list[tuple[float, float]] = []
    for ip in ips:
        result = lookup_ip(ip)
        location = result.get("location") or {}
        latitude, longitude = location.get("latitude"), location.get("longitude")
        if isinstance(latitude, (int, float)) and isinstance(longitude, (int, float)):
            coordinates.append((float(latitude), float(longitude)))
    return coordinates
