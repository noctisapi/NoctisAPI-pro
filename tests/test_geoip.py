import app.geoip as geoip


def test_get_geoip_db_path_prefers_explicit_value(monkeypatch):
    monkeypatch.setenv("HP_ASN_RESOLVER_URL", "https://resolver.example/{ip}")
    monkeypatch.setenv("HP_GEO_RESOLVER_URL", "https://fallback.example/{ip}")
    assert geoip.get_geoip_db_path("https://explicit.example/{ip}") == "https://explicit.example/{ip}"


def test_get_geoip_db_path_falls_back_to_resolver_env(monkeypatch):
    monkeypatch.delenv("HP_GEO_RESOLVER_URL", raising=False)
    monkeypatch.setenv("HP_ASN_RESOLVER_URL", "https://resolver.example/{ip}")
    assert geoip.get_geoip_db_path() == "https://resolver.example/{ip}"


def test_get_country_code_delegates_to_asn_resolver(monkeypatch):
    monkeypatch.setattr(
        geoip.asn_resolver,
        "get_country_code",
        lambda ip, configured_url=None, logger=None: "US" if ip == "8.8.8.8" else None,
    )
    assert geoip.get_country_code("8.8.8.8") == "US"
    assert geoip.get_country_code("192.168.1.1") is None


def test_lookup_country_normalizes_asn_resolver_payload(monkeypatch):
    monkeypatch.setattr(
        geoip.asn_resolver,
        "lookup_country",
        lambda ip, configured_url=None, logger=None: {
            "country_code": "us",
            "country_name": "United States",
        },
    )
    geo = geoip.lookup_country("8.8.8.8")
    assert geo["country_iso2"] == "US"
    assert geo["country_code"] == "US"
    assert geo["country_name"] == "United States"
    assert geo["flag"]


def test_parse_geo_from_extra_json_keeps_public_shape():
    parsed = geoip.parse_geo_from_extra_json(
        {"geo": {"country_iso2": "ES", "country_name": "Spain"}}
    )
    assert parsed == {
        "geo_flag": geoip.flag_emoji_from_iso2("ES"),
        "geo_iso2": "ES",
        "geo_country_code": "ES",
        "geo_name": "Spain",
    }
