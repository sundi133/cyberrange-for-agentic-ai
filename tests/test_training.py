"""Tests for the CTF / scoring training engine."""

import pytest

from cyberange.scenarios import SCENARIOS
from cyberange.training.ctf import (
    CHALLENGES, Scoreboard, build_challenges, grade, TRACKS,
)


def test_three_challenges_per_scenario():
    assert len(build_challenges()) == len(SCENARIOS) * 3
    for sc in SCENARIOS:
        for track in TRACKS:
            assert f"{track}-{sc.id}" in CHALLENGES


def test_grade_red_correct_and_wrong():
    ok, _ = grade(CHALLENGES["red-SC-001"], "data_exfiltration")
    assert ok
    bad, _ = grade(CHALLENGES["red-SC-001"], "shell_executed")
    assert not bad


def test_grade_blue_accepts_firing_rule():
    ok, _ = grade(CHALLENGES["blue-SC-001"], "DR-003-sensitive-egress")
    assert ok
    bad, _ = grade(CHALLENGES["blue-SC-001"], "DR-005-cross-tenant")
    assert not bad


def test_grade_purple_runs_engine():
    # A correct mapped control blocks it...
    ok, _ = grade(CHALLENGES["purple-SC-008"], "tool_permission_model")
    assert ok
    # ...an unrelated control does not.
    bad, _ = grade(CHALLENGES["purple-SC-008"], "dlp_egress")
    assert not bad
    # Unknown control is rejected with a helpful message.
    unknown, msg = grade(CHALLENGES["purple-SC-001"], "not_a_control")
    assert not unknown and "Unknown" in msg


def test_purple_universal_control_always_validates():
    for sc in SCENARIOS:
        ok, _ = grade(CHALLENGES[f"purple-{sc.id}"], "untrusted_content_separation")
        assert ok, f"separation should defend {sc.id}"


def test_scoreboard_award_flag_and_idempotent(tmp_path):
    sb = Scoreboard(root=str(tmp_path))
    r1 = sb.submit("alice", "red-SC-001", "data_exfiltration")
    assert r1.correct and r1.points > 0
    assert r1.flag == "CYBERANGE{red-SC-001}"

    # Re-submitting the same challenge does not double-count.
    r2 = sb.submit("alice", "red-SC-001", "data_exfiltration")
    assert r2.already_solved and r2.points == 0

    score = sb.score("alice")
    assert score["total"] == r1.points
    assert score["solved"] == 1


def test_scoreboard_wrong_answer_no_points(tmp_path):
    sb = Scoreboard(root=str(tmp_path))
    res = sb.submit("bob", "purple-SC-001", "memory_write_approval")
    assert not res.correct
    assert sb.score("bob")["total"] == 0


def test_leaderboard_ranks_by_points(tmp_path):
    sb = Scoreboard(root=str(tmp_path))
    sb.submit("alice", "purple-SC-008", "tool_permission_model")  # 70
    sb.submit("bob", "red-SC-003", "external_post")               # 35
    board = sb.leaderboard()
    assert [r["participant"] for r in board] == ["alice", "bob"]
    assert board[0]["total"] >= board[1]["total"]


def test_unknown_challenge():
    sb_result = Scoreboard(root="/tmp/cyberange-ctf-test").submit(
        "x", "red-SC-999", "y")
    assert not sb_result.correct
