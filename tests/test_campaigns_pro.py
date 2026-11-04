import unittest

from honey_licensing.feature_flags import enabled_features, set_pro_enabled_provider
from app import campaigns_pro


class TestFeatureFlagsCampaigns(unittest.TestCase):
    def setUp(self):
        set_pro_enabled_provider(None)

    def tearDown(self):
        set_pro_enabled_provider(None)

    def test_without_runtime_provider_no_pro_features_are_enabled(self):
        features = enabled_features()
        self.assertEqual(features, set())

    def test_runtime_provider_controls_pro_features(self):
        set_pro_enabled_provider(lambda: True)
        features = enabled_features()
        self.assertIn("campaigns", features)
        self.assertIn("cases", features)


class TestNormalizeUaFingerprint(unittest.TestCase):
    def test_empty_returns_empty(self):
        self.assertEqual(campaigns_pro.normalize_ua_fingerprint(""), "")

    def test_strips_version_numbers(self):
        ua = "Mozilla/5.0 Python-httpx/0.27.0"
        result = campaigns_pro.normalize_ua_fingerprint(ua)
        self.assertNotIn("/5.0", result)
        self.assertNotIn("/0.27.0", result)

    def test_strips_parenthesised_build_info(self):
        ua = "curl/7.88.1 (x86_64-pc-linux-gnu)"
        result = campaigns_pro.normalize_ua_fingerprint(ua)
        self.assertNotIn("x86_64", result)

    def test_lowercases_result(self):
        ua = "GoHttpClient"
        result = campaigns_pro.normalize_ua_fingerprint(ua)
        self.assertEqual(result, result.lower())

    def test_same_ua_different_version_same_fingerprint(self):
        ua1 = "python-requests/2.28.0"
        ua2 = "python-requests/2.31.0"
        self.assertEqual(
            campaigns_pro.normalize_ua_fingerprint(ua1),
            campaigns_pro.normalize_ua_fingerprint(ua2),
        )

    def test_long_ua_returns_hash_prefix(self):
        ua = "A" * 200
        result = campaigns_pro.normalize_ua_fingerprint(ua)
        self.assertEqual(len(result), 24)
        # should be hex
        int(result, 16)

    def test_whitespace_normalised(self):
        ua = "foo   bar   baz"
        result = campaigns_pro.normalize_ua_fingerprint(ua)
        self.assertNotIn("  ", result)


class TestExtractTokenPrefix(unittest.TestCase):
    def test_empty_returns_empty(self):
        self.assertEqual(campaigns_pro.extract_token_prefix(""), "")

    def test_short_token_returns_empty(self):
        self.assertEqual(campaigns_pro.extract_token_prefix("ab"), "")

    def test_returns_8_char_hex(self):
        result = campaigns_pro.extract_token_prefix("supersecrettoken123")
        self.assertEqual(len(result), 8)
        int(result, 16)

    def test_bearer_prefix_stripped(self):
        raw = "sometoken1234"
        with_bearer = "Bearer sometoken1234"
        self.assertEqual(
            campaigns_pro.extract_token_prefix(raw),
            campaigns_pro.extract_token_prefix(with_bearer),
        )

    def test_token_prefix_stripped(self):
        raw = "sometoken1234"
        with_token = "Token sometoken1234"
        self.assertEqual(
            campaigns_pro.extract_token_prefix(raw),
            campaigns_pro.extract_token_prefix(with_token),
        )

    def test_basic_prefix_stripped(self):
        raw = "sometoken1234"
        with_basic = "Basic sometoken1234"
        self.assertEqual(
            campaigns_pro.extract_token_prefix(raw),
            campaigns_pro.extract_token_prefix(with_basic),
        )

    def test_case_insensitive_prefix(self):
        lower = campaigns_pro.extract_token_prefix("bearer mytoken123")
        upper = campaigns_pro.extract_token_prefix("BEARER mytoken123")
        self.assertEqual(lower, upper)

    def test_different_tokens_different_prefix(self):
        a = campaigns_pro.extract_token_prefix("tokenAAAA1234")
        b = campaigns_pro.extract_token_prefix("tokenBBBB5678")
        self.assertNotEqual(a, b)


class TestHeaderFingerprint(unittest.TestCase):
    def test_no_relevant_headers_returns_consistent_hash(self):
        # Headers with no stable signal values still produce a consistent hash
        # (key names are included in the signature)
        r1 = campaigns_pro.header_fingerprint({})
        r2 = campaigns_pro.header_fingerprint({})
        self.assertEqual(r1, r2)
        # A dict with only irrelevant keys should also produce a consistent result
        r3 = campaigns_pro.header_fingerprint({"x-custom": "value"})
        self.assertEqual(r1, r3)

    def test_returns_12_char_hex(self):
        headers = {"accept": "application/json", "accept-language": "en-US"}
        result = campaigns_pro.header_fingerprint(headers)
        self.assertEqual(len(result), 12)
        int(result, 16)

    def test_same_headers_same_fingerprint(self):
        h1 = {"accept": "text/html", "connection": "keep-alive"}
        h2 = {"accept": "text/html", "connection": "keep-alive"}
        self.assertEqual(
            campaigns_pro.header_fingerprint(h1),
            campaigns_pro.header_fingerprint(h2),
        )

    def test_different_values_different_fingerprint(self):
        h1 = {"accept": "application/json"}
        h2 = {"accept": "text/html"}
        self.assertNotEqual(
            campaigns_pro.header_fingerprint(h1),
            campaigns_pro.header_fingerprint(h2),
        )

    def test_case_insensitive_key_lookup(self):
        lower = campaigns_pro.header_fingerprint({"accept": "text/html"})
        title = campaigns_pro.header_fingerprint({"Accept": "text/html"})
        upper = campaigns_pro.header_fingerprint({"ACCEPT": "text/html"})
        self.assertEqual(lower, title)
        self.assertEqual(lower, upper)

    def test_session_specific_headers_ignored(self):
        # Authorization and Cookie are not in the stable header set
        h1 = {"accept": "application/json", "authorization": "Bearer token1"}
        h2 = {"accept": "application/json", "authorization": "Bearer token2"}
        self.assertEqual(
            campaigns_pro.header_fingerprint(h1),
            campaigns_pro.header_fingerprint(h2),
        )


class TestIpSubnet(unittest.TestCase):
    def test_ipv4_returns_first_two_octets(self):
        self.assertEqual(campaigns_pro.ip_subnet("192.168.1.100"), "192.168")

    def test_ipv4_another(self):
        self.assertEqual(campaigns_pro.ip_subnet("10.0.0.1"), "10.0")

    def test_ipv6_returns_empty(self):
        self.assertEqual(campaigns_pro.ip_subnet("2001:db8::1"), "")

    def test_empty_returns_empty(self):
        self.assertEqual(campaigns_pro.ip_subnet(""), "")

    def test_invalid_returns_empty(self):
        self.assertEqual(campaigns_pro.ip_subnet("notanip"), "")

    def test_partial_ip_handled(self):
        result = campaigns_pro.ip_subnet("192.168")
        # Only one dot — should return "192.168" since there are 2 parts
        self.assertIn(result, ("192.168", ""))


class TestClassifyBehaviorPattern(unittest.TestCase):
    def test_infrastructure_probing(self):
        result = campaigns_pro.classify_behavior_pattern(
            ["infra_vault", "root_console"], [], set()
        )
        self.assertEqual(result, "infrastructure_probing")

    def test_data_exfiltration(self):
        result = campaigns_pro.classify_behavior_pattern(
            ["backup_download", "backup_list"], [], set()
        )
        self.assertEqual(result, "data_exfiltration")

    def test_key_theft(self):
        result = campaigns_pro.classify_behavior_pattern(
            ["keys_issued"], [], set()
        )
        self.assertEqual(result, "key_theft")

    def test_credential_harvesting(self):
        result = campaigns_pro.classify_behavior_pattern(
            ["auth_login", "unknown_token"], [], set()
        )
        self.assertEqual(result, "credential_harvesting")

    def test_reconnaissance_from_techniques(self):
        result = campaigns_pro.classify_behavior_pattern(
            ["probe", "recon_openapi"], [], set()
        )
        self.assertEqual(result, "reconnaissance")

    def test_severity_tiebreak_favors_higher(self):
        # infrastructure_probing beats credential_harvesting when scores are equal
        result = campaigns_pro.classify_behavior_pattern(
            ["infra_vault", "auth_login"], [], set()
        )
        self.assertEqual(result, "infrastructure_probing")

    def test_fallback_recon_paths(self):
        result = campaigns_pro.classify_behavior_pattern(
            [], ["/docs", "/openapi.json", "/swagger.json"], set()
        )
        self.assertEqual(result, "reconnaissance")

    def test_fallback_admin_paths(self):
        result = campaigns_pro.classify_behavior_pattern(
            [], ["/admin", "/internal", "/vault"], set()
        )
        self.assertEqual(result, "targeted_attack")

    def test_fallback_broad_scanning(self):
        endpoints = [f"/path{i}" for i in range(15)]
        result = campaigns_pro.classify_behavior_pattern([], endpoints, set())
        self.assertEqual(result, "broad_scanning")

    def test_empty_returns_unknown(self):
        result = campaigns_pro.classify_behavior_pattern([], [], set())
        self.assertEqual(result, "unknown")

    def test_feature_set_path_used_as_fallback(self):
        feature_set = {f"path::/docs", "path::/openapi.json", "path::/swagger.json"}
        result = campaigns_pro.classify_behavior_pattern([], [], feature_set)
        self.assertEqual(result, "reconnaissance")


class TestCampaignCacheConfigKey(unittest.TestCase):
    def test_returns_only_extraction_keys(self):
        config = campaigns_pro.campaign_config_from_env()
        cache_key = campaigns_pro.campaign_cache_config_key(config)
        extraction_keys = {"max_sessions", "path_ngram_top_k", "path_top_k",
                           "max_steps_per_session", "max_events_per_actor"}
        self.assertEqual(set(cache_key.keys()), extraction_keys)

    def test_weight_changes_do_not_affect_cache_key(self):
        config_a = campaigns_pro.campaign_config_from_env()
        config_b = dict(config_a)
        config_b["w_ua"] = 99.0
        config_b["w_tok"] = 0.1
        self.assertEqual(
            campaigns_pro.campaign_cache_config_key(config_a),
            campaigns_pro.campaign_cache_config_key(config_b),
        )

    def test_extraction_param_change_affects_cache_key(self):
        config_a = campaigns_pro.campaign_config_from_env()
        config_b = dict(config_a)
        config_b["max_sessions"] = config_a["max_sessions"] + 1
        self.assertNotEqual(
            campaigns_pro.campaign_cache_config_key(config_a),
            campaigns_pro.campaign_cache_config_key(config_b),
        )


class TestCampaignConfigFromEnv(unittest.TestCase):
    def test_all_signal_weights_present(self):
        config = campaigns_pro.campaign_config_from_env()
        for key in ("w_path", "w_stage", "w_time", "w_err", "w_ua", "w_geo", "w_tok", "w_hdr", "w_subnet"):
            self.assertIn(key, config)

    def test_defaults_are_numeric(self):
        config = campaigns_pro.campaign_config_from_env()
        for key, val in config.items():
            self.assertIsInstance(val, (int, float), f"{key} should be numeric")


if __name__ == "__main__":
    unittest.main()
