"""Unit tests for app/internal/analysis_engine/.

Coverage:
  - Each of the 8 signal functions (boundary conditions + representative cases)
  - AttackAnalyzer.analyze() for automated, targeted, and mixed patterns
  - compute_typical_behavior() majority-vote logic
  - compute_campaign_attack_ratios() aggregation
  - Output determinism: same input → same output on repeated calls

All tests are pure: no I/O, no DB, no network.
"""
from __future__ import annotations

import pytest

from app.internal.analysis_engine.models import AttackAnalysisResult, RequestEvent
from app.internal.analysis_engine.signals import (
    adaptation_score,
    header_consistency_score,
    multi_step_behavior_score,
    path_entropy_score,
    request_rate_score,
    timing_uniformity_score,
    traversal_logic_score,
    user_agent_score,
)
from app.internal.analysis_engine.analyzer import (
    AttackAnalyzer,
    compute_typical_behavior,
)
from app.campaigns_pro import compute_campaign_attack_ratios


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(
    *,
    path: str = "/api/v1/users",
    method: str = "GET",
    ua: str = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36",
    headers: dict | None = None,
    query_params: dict | None = None,
    status: int = 200,
    body_size: int = 512,
    session_request_count: int = 0,
    interval_ms: float = 5000.0,
    recent_statuses: tuple = (),
    recent_paths: tuple = (),
    recent_intervals_ms: tuple = (),
) -> RequestEvent:
    default_headers = {
        "accept": "application/json",
        "accept-language": "en-US,en;q=0.9",
        "accept-encoding": "gzip, deflate, br",
        "user-agent": ua,
    }
    return RequestEvent(
        path=path,
        method=method,
        ua=ua,
        headers=headers if headers is not None else default_headers,
        query_params=query_params or {},
        status=status,
        body_size=body_size,
        session_request_count=session_request_count,
        interval_ms=interval_ms,
        recent_statuses=recent_statuses,
        recent_paths=recent_paths,
        recent_intervals_ms=recent_intervals_ms,
    )


# ===========================================================================
# 1. request_rate_score
# ===========================================================================

class TestRequestRateScore:
    def test_first_request_no_interval(self):
        assert request_rate_score(_event(interval_ms=0.0)) == 0.0

    def test_very_fast_is_automated(self):
        assert request_rate_score(_event(interval_ms=50.0)) == 1.0

    def test_fast_is_high(self):
        score = request_rate_score(_event(interval_ms=300.0))
        assert 0.7 < score < 1.0

    def test_moderate_interval_is_medium(self):
        score = request_rate_score(_event(interval_ms=1500.0))
        assert 0.3 < score < 0.7

    def test_slow_interval_is_low(self):
        score = request_rate_score(_event(interval_ms=30_000.0))
        assert score < 0.2

    def test_very_slow_is_zero(self):
        assert request_rate_score(_event(interval_ms=120_000.0)) == 0.0

    def test_output_in_range(self):
        for ms in (0, 50, 200, 1000, 5000, 30000, 120000):
            s = request_rate_score(_event(interval_ms=float(ms)))
            assert 0.0 <= s <= 1.0


# ===========================================================================
# 2. path_entropy_score
# ===========================================================================

class TestPathEntropyScore:
    def test_simple_api_path_is_low(self):
        score = path_entropy_score(_event(path="/api/v1/users"))
        assert score < 0.5

    def test_uuid_path_is_high(self):
        score = path_entropy_score(
            _event(path="/api/v1/users/3f6c8b2a-e4d1-4f5e-9a2b-1c3d4e5f6a7b")
        )
        assert score >= 0.6

    def test_long_hex_segment_is_high(self):
        score = path_entropy_score(
            _event(path="/data/deadbeefcafebabe01234567")
        )
        assert score >= 0.5

    def test_root_path_is_low(self):
        score = path_entropy_score(_event(path="/"))
        assert score < 0.3

    def test_output_in_range(self):
        for p in ("/", "/api", "/api/v1/users/42", "/x" * 20):
            s = path_entropy_score(_event(path=p))
            assert 0.0 <= s <= 1.0


# ===========================================================================
# 3. header_consistency_score
# ===========================================================================

class TestHeaderConsistencyScore:
    def test_full_browser_headers_is_zero(self):
        score = header_consistency_score(_event())
        assert score == 0.0

    def test_missing_all_browser_headers_is_high(self):
        score = header_consistency_score(_event(headers={"host": "example.com"}))
        assert score >= 0.8

    def test_missing_accept_language(self):
        score = header_consistency_score(
            _event(headers={"accept": "*/*", "accept-encoding": "gzip"})
        )
        assert score > 0.0

    def test_two_headers_only_adds_penalty(self):
        score_minimal = header_consistency_score(
            _event(headers={"host": "x", "content-type": "application/json"})
        )
        score_full = header_consistency_score(_event())
        assert score_minimal > score_full

    def test_output_in_range(self):
        for h in ({}, {"host": "x"}, {"accept": "*/*", "accept-language": "en"}):
            s = header_consistency_score(_event(headers=h))
            assert 0.0 <= s <= 1.0


# ===========================================================================
# 4. user_agent_score
# ===========================================================================

class TestUserAgentScore:
    def test_empty_ua_is_one(self):
        assert user_agent_score(_event(ua="")) == 1.0

    def test_curl_is_high(self):
        assert user_agent_score(_event(ua="curl/7.88.0")) >= 0.85

    def test_python_requests_is_high(self):
        assert user_agent_score(_event(ua="python-requests/2.28.2")) >= 0.85

    def test_nikto_is_high(self):
        assert user_agent_score(_event(ua="Nikto/2.1.6 (Evasion=None)")) >= 0.85

    def test_real_browser_is_zero(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        assert user_agent_score(_event(ua=ua)) == 0.0

    def test_short_ua_is_medium(self):
        score = user_agent_score(_event(ua="SomeBot"))
        assert score >= 0.6

    def test_non_mozilla_ua_is_medium(self):
        score = user_agent_score(_event(ua="Googlebot/2.1 (+http://www.google.com/bot.html)"))
        # "bot/" matches _TOOL_UA_FRAGMENTS
        assert score >= 0.85

    def test_output_in_range(self):
        for ua in ("", "curl/7.88", "Mozilla/5.0 Chrome/113", "x"):
            s = user_agent_score(_event(ua=ua))
            assert 0.0 <= s <= 1.0


# ===========================================================================
# 5. timing_uniformity_score
# ===========================================================================

class TestTimingUniformityScore:
    def test_no_intervals_is_zero(self):
        assert timing_uniformity_score(_event(recent_intervals_ms=())) == 0.0

    def test_single_interval_is_zero(self):
        assert timing_uniformity_score(_event(recent_intervals_ms=(500.0,))) == 0.0

    def test_perfectly_uniform_is_one(self):
        score = timing_uniformity_score(
            _event(recent_intervals_ms=(1000.0, 1000.0, 1000.0, 1000.0))
        )
        assert score == 1.0

    def test_near_uniform_is_high(self):
        score = timing_uniformity_score(
            _event(recent_intervals_ms=(1000.0, 1005.0, 998.0, 1002.0))
        )
        assert score >= 0.7

    def test_highly_variable_is_low(self):
        score = timing_uniformity_score(
            _event(recent_intervals_ms=(100.0, 5000.0, 200.0, 8000.0, 50.0))
        )
        assert score < 0.3

    def test_output_in_range(self):
        for ivs in (
            (100.0, 100.0),
            (1000.0, 2000.0, 3000.0),
            (10.0, 5000.0, 20.0, 4000.0),
        ):
            s = timing_uniformity_score(_event(recent_intervals_ms=ivs))
            assert 0.0 <= s <= 1.0


# ===========================================================================
# 6. traversal_logic_score
# ===========================================================================

class TestTraversalLogicScore:
    def test_single_path_is_zero(self):
        assert traversal_logic_score(_event(recent_paths=())) == 0.0

    def test_common_prefix_raises_score(self):
        score = traversal_logic_score(
            _event(
                path="/api/v1/users/123/orders",
                recent_paths=("/api/v1/users/123/settings", "/api/v1/users/123"),
            )
        )
        assert score > 0.3

    def test_random_unrelated_paths_is_low(self):
        score = traversal_logic_score(
            _event(
                path="/zxqw/random/abc",
                recent_paths=(
                    "/foo/bar/baz",
                    "/qux/quux",
                    "/aaa/bbb/ccc",
                    "/xyz",
                ),
            )
        )
        assert score < 0.4

    def test_revisiting_same_paths_raises_score(self):
        repeated = ("/api/v1/users/1",) * 8
        score = traversal_logic_score(
            _event(path="/api/v1/users/1", recent_paths=repeated)
        )
        assert score >= 0.2

    def test_output_in_range(self):
        score = traversal_logic_score(
            _event(
                path="/api/v1/resource/42",
                recent_paths=("/api/v1/resource/42", "/api/v1/resource"),
            )
        )
        assert 0.0 <= score <= 1.0


# ===========================================================================
# 7. multi_step_behavior_score
# ===========================================================================

class TestMultiStepBehaviorScore:
    def test_first_request_is_zero(self):
        score = multi_step_behavior_score(_event(session_request_count=0))
        assert score == 0.0

    def test_many_steps_raises_score(self):
        score = multi_step_behavior_score(_event(session_request_count=25))
        assert score >= 0.4

    def test_post_method_raises_score(self):
        get_score  = multi_step_behavior_score(_event(method="GET",  session_request_count=0))
        post_score = multi_step_behavior_score(_event(method="POST", session_request_count=0))
        assert post_score > get_score

    def test_auth_header_raises_score(self):
        without = multi_step_behavior_score(_event(headers={"accept": "*/*"}))
        with_auth = multi_step_behavior_score(
            _event(headers={"accept": "*/*", "authorization": "Bearer tok"})
        )
        assert with_auth > without

    def test_output_in_range(self):
        for count in (0, 1, 5, 10, 20, 50):
            s = multi_step_behavior_score(_event(session_request_count=count))
            assert 0.0 <= s <= 1.0


# ===========================================================================
# 8. adaptation_score
# ===========================================================================

class TestAdaptationScore:
    def test_no_history_is_zero(self):
        assert adaptation_score(_event()) == 0.0

    def test_path_change_after_403_raises_score(self):
        score = adaptation_score(
            _event(
                path="/api/v1/admin",
                recent_statuses=(403,),
                recent_paths=("/api/v1/users",),
            )
        )
        assert score >= 0.4

    def test_same_path_after_error_is_lower(self):
        change_score = adaptation_score(
            _event(
                path="/new/path",
                recent_statuses=(401,),
                recent_paths=("/old/path",),
            )
        )
        repeat_score = adaptation_score(
            _event(
                path="/same/path",
                recent_statuses=(401,),
                recent_paths=("/same/path",),
            )
        )
        assert change_score > repeat_score

    def test_mixed_success_and_failure_raises_score(self):
        score = adaptation_score(
            _event(
                path="/api/v1/data",
                recent_statuses=(200, 403, 200, 404, 200),
                recent_paths=("/api/v1/a", "/api/v1/b", "/api/v1/c"),
            )
        )
        assert score >= 0.2

    def test_post_with_history_raises_score(self):
        get_score = adaptation_score(
            _event(method="GET",  session_request_count=5, recent_statuses=(200,), recent_paths=("/x",))
        )
        post_score = adaptation_score(
            _event(method="POST", session_request_count=5, recent_statuses=(200,), recent_paths=("/x",))
        )
        assert post_score >= get_score

    def test_output_in_range(self):
        for st, pa in (
            ((404,), ("/a",)),
            ((200, 200, 200), ("/b", "/b", "/b")),
            ((401, 403, 200), ("/c", "/d", "/e")),
        ):
            s = adaptation_score(_event(recent_statuses=st, recent_paths=pa))
            assert 0.0 <= s <= 1.0


# ===========================================================================
# 9. AttackAnalyzer — automated patterns
# ===========================================================================

class TestAnalyzerAutomatedPatterns:
    """Scanner / burst-mode patterns should classify as automated."""

    def _scanner_event(self) -> RequestEvent:
        return _event(
            path="/api/v1/users/3f6c8b2a-e4d1-4f5e-9a2b-1c3d4e5f6a7b",
            method="GET",
            ua="python-requests/2.28.2",
            headers={"host": "target.example.com"},   # no browser headers
            interval_ms=80.0,                          # very fast
            session_request_count=0,
            recent_intervals_ms=(80.0, 80.0, 80.0),   # perfectly uniform
        )

    def test_scanner_is_automated(self):
        result = AttackAnalyzer().analyze(self._scanner_event())
        assert result.attack_type == "automated"

    def test_scanner_has_positive_confidence(self):
        result = AttackAnalyzer().analyze(self._scanner_event())
        assert result.confidence_score > 0.0

    def test_missing_ua_burst_is_automated(self):
        ev = _event(
            ua="",
            headers={},
            interval_ms=50.0,
            recent_intervals_ms=(50.0, 51.0, 49.0),
        )
        result = AttackAnalyzer().analyze(ev)
        assert result.attack_type == "automated"

    def test_curl_burst_is_automated(self):
        ev = _event(
            ua="curl/7.88.0",
            headers={},
            interval_ms=200.0,
            recent_intervals_ms=(200.0, 201.0),
        )
        result = AttackAnalyzer().analyze(ev)
        assert result.attack_type == "automated"


# ===========================================================================
# 10. AttackAnalyzer — targeted patterns
# ===========================================================================

class TestAnalyzerTargetedPatterns:
    """Goal-directed multi-step patterns should classify as targeted."""

    def _targeted_event(self) -> RequestEvent:
        return _event(
            path="/api/v1/users/123/orders/456",
            method="POST",
            ua="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            headers={
                "accept": "application/json",
                "accept-language": "en-US,en;q=0.9",
                "accept-encoding": "gzip, deflate, br",
                "authorization": "Bearer eyJhbGc...",
            },
            interval_ms=8_000.0,                # human-paced
            session_request_count=12,           # deep session
            recent_statuses=(200, 401, 200, 200),
            recent_paths=(
                "/api/v1/users/123/orders",
                "/api/v1/users/123",
                "/api/v1/users",
                "/api/v1/auth/login",
            ),
            recent_intervals_ms=(7_000.0, 9_500.0, 6_800.0),  # variable
        )

    def test_targeted_event_is_targeted(self):
        result = AttackAnalyzer().analyze(self._targeted_event())
        assert result.attack_type == "targeted"

    def test_targeted_event_has_positive_confidence(self):
        result = AttackAnalyzer().analyze(self._targeted_event())
        assert result.confidence_score > 0.0

    def test_multi_step_with_auth_and_adaptation_is_targeted(self):
        ev = _event(
            method="DELETE",
            ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
            headers={
                "accept": "application/json",
                "accept-language": "en-US",
                "accept-encoding": "gzip",
                "authorization": "Bearer tok",
            },
            interval_ms=12_000.0,
            session_request_count=18,
            recent_statuses=(200, 403, 200),
            recent_paths=("/api/v1/admin/users/1", "/api/v1/admin"),
            recent_intervals_ms=(11_000.0, 13_500.0, 10_200.0),
        )
        result = AttackAnalyzer().analyze(ev)
        assert result.attack_type == "targeted"


# ===========================================================================
# 11. AttackAnalyzer — result structure
# ===========================================================================

class TestAnalyzerResultStructure:
    _EXPECTED_SIGNALS = {
        "request_rate", "path_entropy", "header_consistency", "user_agent",
        "timing_uniformity", "traversal_logic", "multi_step_behavior", "adaptation",
    }

    def test_all_signals_present(self):
        result = AttackAnalyzer().analyze(_event())
        assert set(result.signals.keys()) == self._EXPECTED_SIGNALS

    def test_all_signals_in_range(self):
        result = AttackAnalyzer().analyze(_event())
        for name, score in result.signals.items():
            assert 0.0 <= score <= 1.0, f"Signal {name} out of range: {score}"

    def test_confidence_in_range(self):
        result = AttackAnalyzer().analyze(_event())
        assert 0.0 <= result.confidence_score <= 1.0

    def test_attack_type_is_valid(self):
        result = AttackAnalyzer().analyze(_event())
        assert result.attack_type in ("automated", "targeted")

    def test_result_is_frozen_dataclass(self):
        result = AttackAnalyzer().analyze(_event())
        assert isinstance(result, AttackAnalysisResult)
        with pytest.raises((AttributeError, TypeError)):
            result.attack_type = "other"  # type: ignore[misc]


# ===========================================================================
# 12. Determinism
# ===========================================================================

class TestDeterminism:
    """Same input must always produce the same output."""

    def _make_event(self) -> RequestEvent:
        return _event(
            path="/api/v1/resource/99",
            method="GET",
            ua="python-requests/2.28",
            headers={"host": "x"},
            interval_ms=150.0,
            session_request_count=3,
            recent_statuses=(200, 404),
            recent_paths=("/api/v1/resource", "/api/v1"),
            recent_intervals_ms=(150.0, 148.0),
        )

    def test_same_input_same_output(self):
        ev = self._make_event()
        r1 = AttackAnalyzer().analyze(ev)
        r2 = AttackAnalyzer().analyze(ev)
        assert r1.attack_type      == r2.attack_type
        assert r1.confidence_score == r2.confidence_score
        assert r1.signals          == r2.signals

    def test_independent_instances_agree(self):
        ev = self._make_event()
        assert AttackAnalyzer().analyze(ev) == AttackAnalyzer().analyze(ev)

    def test_scanner_event_stable(self):
        ev = _event(ua="", headers={}, interval_ms=50.0)
        results = [AttackAnalyzer().analyze(ev) for _ in range(5)]
        assert all(r == results[0] for r in results)


# ===========================================================================
# 13. compute_typical_behavior
# ===========================================================================

class TestComputeTypicalBehavior:
    def test_empty_list_returns_mixed(self):
        # No case data → counts are both 0 → tie → "mixed"
        assert compute_typical_behavior([]) == "mixed"

    def test_all_automated(self):
        assert compute_typical_behavior(["automated"] * 5) == "automated"

    def test_all_targeted(self):
        assert compute_typical_behavior(["targeted"] * 5) == "targeted"

    def test_majority_automated(self):
        assert compute_typical_behavior(["automated", "automated", "targeted"]) == "automated"

    def test_majority_targeted(self):
        assert compute_typical_behavior(["targeted", "targeted", "automated"]) == "targeted"

    def test_tie_is_mixed(self):
        assert compute_typical_behavior(["automated", "targeted"]) == "mixed"

    def test_unknown_values_ignored(self):
        # Only "automated" and "targeted" are counted
        result = compute_typical_behavior(["automated", "unknown", "automated"])
        assert result == "automated"

    def test_result_is_one_of_three_values(self):
        for types in (
            [],
            ["automated"],
            ["targeted"],
            ["automated", "targeted"],
            ["automated"] * 3 + ["targeted"] * 2,
        ):
            assert compute_typical_behavior(types) in ("automated", "targeted", "mixed")


# ===========================================================================
# 14. compute_campaign_attack_ratios
# ===========================================================================

class TestComputeCampaignAttackRatios:
    def test_empty_list(self):
        r = compute_campaign_attack_ratios([])
        assert r == {"automated_ratio": 0.0, "targeted_ratio": 0.0}

    def test_all_automated(self):
        r = compute_campaign_attack_ratios(["automated"] * 4)
        assert r["automated_ratio"] == 1.0
        assert r["targeted_ratio"]  == 0.0

    def test_all_targeted(self):
        r = compute_campaign_attack_ratios(["targeted"] * 4)
        assert r["automated_ratio"] == 0.0
        assert r["targeted_ratio"]  == 1.0

    def test_half_half(self):
        r = compute_campaign_attack_ratios(["automated", "targeted"])
        assert r["automated_ratio"] == 0.5
        assert r["targeted_ratio"]  == 0.5

    def test_ratios_sum_to_at_most_one(self):
        for types in (
            ["automated"] * 3,
            ["targeted"] * 3,
            ["automated", "targeted", "automated"],
        ):
            r = compute_campaign_attack_ratios(types)
            assert r["automated_ratio"] + r["targeted_ratio"] <= 1.0 + 1e-9

    def test_unknown_values_do_not_inflate_ratios(self):
        r = compute_campaign_attack_ratios(["automated", "unknown", "unknown"])
        # 1/3 automated, 0 targeted; unknown entries are not counted
        assert r["automated_ratio"] == pytest.approx(1 / 3, abs=0.001)
        assert r["targeted_ratio"]  == 0.0
