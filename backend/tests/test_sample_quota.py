"""测试：采样计划名额分配、借用、退回与调用链去重扣额。

覆盖需求：
- 去重保留的原事件决定采样候选，实际归并代表按代表写名额，同一代表只扣一格
- 常规先占首格、第二格可借用；罕见优先权在预领/结算两个时点的差异
- 归并实际使用计划配置的五分钟时间窗，同客户跨窗代表各自占额
- 代表正式退回后本轮回执不变、下一轮释放额度；重复退回不多释放、未退回不可重领
- 批量结算/并发确认沿调用链不重复扣额，样本与借用回执可核对
"""
from __future__ import annotations

import os
import sys
import threading
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.models import (
    DedupFilter, EventRecord, EventTypeDef, SampleConfig,
)
from app.core.dedup_sample import (
    DedupSamplePipeline, MergeRepresentative, PlanQuotaLedger, SLOTS_PER_ROUND,
)
from app.core.pipeline import IngestPipeline


ACCESS_TYPE = EventTypeDef(
    type_id="EVEN-0001", type_name="访问事件",
    category_tag="access", severity="INFO",
)
RARE_TYPE = EventTypeDef(
    type_id="EVEN-0009", type_name="罕见事件",
    category_tag="rare", severity="HIGH",
)

DEDUP_RULE = DedupFilter(
    rule_id="DEDU-TEST",
    event_type_id="EVEN-0001",
    dedup_fields=["client_ip", "url"],
    window_minutes=5,
)

SAMPLE_PLAN = SampleConfig(
    plan_id="SAMP-TEST",
    event_type_id="EVEN-0001",
    sample_ratio=1.0,
    merge_key="client_ip",
    merge_window_minutes=5,
    retain_policy="latest",
)

BASE = datetime(2026, 11, 24, 9, 0, 0)


def make_event(rid: str, client_ip: str, url: str = "/api/demo",
               event_time: datetime = BASE, rare: bool = False) -> EventRecord:
    return EventRecord(
        record_id=rid,
        event_type=RARE_TYPE if rare else ACCESS_TYPE,
        original_content=f"raw {rid}",
        parsed_fields={"client_ip": client_ip, "url": url},
        masked_fields={},
        enriched_fields={},
        event_time=event_time,
        source_host=client_ip,
        store_partition="20261124",
    )


def rep_id(plan_id: str, client_ip: str, window_start: datetime) -> str:
    return f"{plan_id}:{client_ip}:{window_start.isoformat()}"


class TestMergeWindow:
    """五分钟归并时间窗：同客户跨窗代表各自占额。"""

    def test_same_key_in_two_windows_two_representatives(self):
        pipeline = DedupSamplePipeline(dedup_rules=[DEDUP_RULE],
                                       sample_configs=[SAMPLE_PLAN])
        e1 = make_event("EV-0901", "10.0.0.7", event_time=datetime(2026, 11, 24, 9, 1, 0))
        e2 = make_event("EV-0908", "10.0.0.7", event_time=datetime(2026, 11, 24, 9, 8, 0))

        reps = pipeline.merge_representatives([e1, e2], SAMPLE_PLAN)

        assert len(reps) == 2  # 不能把整段只留一条
        assert {r.window_start for r in reps} == {
            datetime(2026, 11, 24, 9, 0, 0),
            datetime(2026, 11, 24, 9, 5, 0),
        }
        # 归并使用去重处理输出的原事件
        assert {r.record_id for r in reps} == {"EV-0901", "EV-0908"}

    def test_same_key_within_window_keeps_latest_original(self):
        pipeline = DedupSamplePipeline(dedup_rules=[DEDUP_RULE],
                                       sample_configs=[SAMPLE_PLAN])
        old = make_event("EV-OLD", "10.0.0.8", event_time=BASE + timedelta(seconds=30))
        new = make_event("EV-NEW", "10.0.0.8", event_time=BASE + timedelta(minutes=4))

        reps = pipeline.merge_representatives([old, new], SAMPLE_PLAN)

        assert len(reps) == 1
        assert reps[0].record_id == "EV-NEW"

    def test_window_representatives_each_occupy_a_slot(self):
        """用 09:01 和 09:08 的同键原行核对两个窗口：各占一格，合计两格。"""
        pipeline = DedupSamplePipeline(dedup_rules=[DEDUP_RULE],
                                       sample_configs=[SAMPLE_PLAN])
        e1 = make_event("EV-0901", "10.0.0.7", event_time=datetime(2026, 11, 24, 9, 1))
        e2 = make_event("EV-0908", "10.0.0.7", event_time=datetime(2026, 11, 24, 9, 8))

        out = pipeline.submit_round(SAMPLE_PLAN, [e1, e2], round_no=1)
        samples = pipeline.settle_round(SAMPLE_PLAN, 1)

        assert len(out["receipts"]) == 2
        assert out["receipts"][0].kind == "regular"
        assert out["receipts"][1].kind == "borrow"
        assert len(samples) == 2
        assert pipeline.reconcile(SAMPLE_PLAN, 1)["ok"] is True


class TestQuotaAndReturn:
    """预领/结算/确认/退回的名额语义。"""

    def test_regular_first_slot_borrow_second_slot(self):
        pipeline = DedupSamplePipeline(dedup_rules=[DEDUP_RULE],
                                       sample_configs=[SAMPLE_PLAN])
        events = [
            make_event("EV-A", "10.0.0.1", url="/a"),
            make_event("EV-B", "10.0.0.2", url="/b"),
            make_event("EV-C", "10.0.0.3", url="/c"),
        ]
        out = pipeline.submit_round(SAMPLE_PLAN, events, round_no=1)

        assert len(out["receipts"]) == SLOTS_PER_ROUND
        assert out["receipts"][0].slot_no == 1 and out["receipts"][0].kind == "regular"
        assert out["receipts"][1].slot_no == 2 and out["receipts"][1].kind == "borrow"
        assert len(out["pending"]) == 1

    def test_same_representative_charged_once_on_duplicate_submit(self):
        pipeline = DedupSamplePipeline(dedup_rules=[DEDUP_RULE],
                                       sample_configs=[SAMPLE_PLAN])
        events = [make_event("EV-A", "10.0.0.1", event_time=BASE)]
        pipeline.submit_round(SAMPLE_PLAN, events, round_no=1, request_id="REQ-1")
        # 同 request_id / 同代表重复提交
        again = pipeline.submit_round(SAMPLE_PLAN, events, round_no=1, request_id="REQ-1")
        again2 = pipeline.submit_round(SAMPLE_PLAN, events, round_no=1, request_id="REQ-2")

        samples = pipeline.settle_round(SAMPLE_PLAN, 1)
        ledger = pipeline.ledger_for(SAMPLE_PLAN)
        assert len(samples) == 1
        assert len(ledger.delivered_reps) == 1
        assert pipeline.reconcile(SAMPLE_PLAN, 1)["ok"] is True

    def test_concurrent_confirm_charges_once(self):
        pipeline = DedupSamplePipeline(dedup_rules=[DEDUP_RULE],
                                       sample_configs=[SAMPLE_PLAN])
        events = [make_event("EV-A", "10.0.0.1")]
        out = pipeline.submit_round(SAMPLE_PLAN, events, round_no=1)
        rep_id_value = out["receipts"][0].representative_id
        charged_flags: list[bool] = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            _, charged = pipeline.confirm_representative(SAMPLE_PLAN, rep_id_value)
            charged_flags.append(charged)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(1 for flag in charged_flags if flag) == 1
        ledger = pipeline.ledger_for(SAMPLE_PLAN)
        assert ledger.rep_receipt[rep_id_value].confirmations == 8

    def test_return_keeps_current_receipt_and_releases_next_round(self):
        pipeline = DedupSamplePipeline(dedup_rules=[DEDUP_RULE],
                                       sample_configs=[SAMPLE_PLAN])
        e1 = make_event("EV-A", "10.0.0.1", event_time=datetime(2026, 11, 24, 9, 1))
        e2 = make_event("EV-B", "10.0.0.1", event_time=datetime(2026, 11, 24, 9, 8))
        out = pipeline.submit_round(SAMPLE_PLAN, [e1, e2], round_no=1)
        samples_r1 = pipeline.settle_round(SAMPLE_PLAN, 1)
        assert len(samples_r1) == 2
        returned_rep = out["receipts"][0].representative_id
        receipt_before = pipeline.ledger_for(SAMPLE_PLAN).rep_receipt[returned_rep]

        registered, released = pipeline.return_representative(SAMPLE_PLAN, returned_rep)
        # 重复退回不能多释放
        registered_again, released_again = pipeline.return_representative(
            SAMPLE_PLAN, returned_rep)

        assert registered is True and released == 1
        assert registered_again is False and released_again == 0
        # 本轮已交付回执保持原样
        assert receipt_before.status == "delivered"
        assert pipeline.reconcile(SAMPLE_PLAN, 1)["sample_count"] == 2
        # 下一轮拿到 2 基础名额 + 1 退回释放名额
        next_state = pipeline.ledger_for(SAMPLE_PLAN).open_round(2)
        assert next_state.capacity == 3 and next_state.bonus_slots == 1

    def test_returned_and_unreturned_representatives_cannot_reclaim(self):
        pipeline = DedupSamplePipeline(dedup_rules=[DEDUP_RULE],
                                       sample_configs=[SAMPLE_PLAN])
        e1 = make_event("EV-A", "10.0.0.1", event_time=datetime(2026, 11, 24, 9, 1))
        e2 = make_event("EV-B", "10.0.0.1", event_time=datetime(2026, 11, 24, 9, 8))
        out = pipeline.submit_round(SAMPLE_PLAN, [e1, e2], round_no=1)
        pipeline.settle_round(SAMPLE_PLAN, 1)
        rep1, rep2 = (r.representative_id for r in out["receipts"])
        pipeline.return_representative(SAMPLE_PLAN, rep1)

        # 已交付（无论退回与否）的代表都不能重新领取
        ledger = pipeline.ledger_for(SAMPLE_PLAN)
        ledger.open_round(2)
        receipt1 = ledger.reserve(
            MergeRepresentative(rep1, "10.0.0.1",
                                datetime(2026, 11, 24, 9, 0), e1), round_no=2)
        receipt2 = ledger.reserve(
            MergeRepresentative(rep2, "10.0.0.1",
                                datetime(2026, 11, 24, 9, 5), e2), round_no=2)

        assert receipt1 is not None and receipt1.status == "delivered"  # 只回原回执
        assert receipt2 is not None and receipt2.status == "delivered"
        ledger = pipeline.ledger_for(SAMPLE_PLAN)
        assert len(ledger.rounds[2].reservations) == 0


class TestRarePriority:
    """A1 重复提交 / A2 / A3 与迟到罕见事件 R 的两条优先权路径。"""

    def _build_a1a2a3(self):
        # A1 旧版与 A2 新版同键（同 client_ip，不同 url），A1 另有一份重复提交
        a1_old = make_event("A1-OLD", "203.0.113.1", url="/login-v1", event_time=BASE)
        a1_dup = make_event("A1-DUP", "203.0.113.1", url="/login-v1",
                            event_time=BASE + timedelta(seconds=30))
        a2 = make_event("A2", "203.0.113.1", url="/login-v2",
                        event_time=BASE + timedelta(minutes=1))
        a3 = make_event("A3", "203.0.113.3", url="/login",
                        event_time=BASE + timedelta(minutes=2))
        return a1_old, a1_dup, a2, a3

    def test_dedup_drops_duplicate_a1_and_merges_a2_a3(self):
        pipeline = DedupSamplePipeline(dedup_rules=[DEDUP_RULE],
                                       sample_configs=[SAMPLE_PLAN])
        a1_old, a1_dup, a2, a3 = self._build_a1a2a3()
        deduped, hits, _ = pipeline.deduplicate([a1_old, a1_dup, a2, a3], DEDUP_RULE)

        assert hits == 1
        assert {r.record_id for r in deduped} == {"A1-OLD", "A2", "A3"}
        # 归并按 merge_key=client_ip：同键的 A1/A2 合成一个代表并保留最新的 A2，
        # 另一组 A3 是第二个可领取代表
        reps = pipeline.merge_representatives(deduped, SAMPLE_PLAN)
        assert sorted(r.record_id for r in reps) == ["A2", "A3"]
        assert len(reps) == 2

    def test_rare_priority_settled_at_settlement_picks_a2_and_r(self):
        """保留到结算的罕见优先权：当轮选 A2 和 R，A3 顺延下一轮并进入实际样本。"""
        pipeline = DedupSamplePipeline(dedup_rules=[DEDUP_RULE],
                                       sample_configs=[SAMPLE_PLAN],
                                       rare_priority=True)
        a1_old, a1_dup, a2, a3 = self._build_a1a2a3()

        out = pipeline.submit_round(SAMPLE_PLAN, [a1_old, a1_dup, a2, a3], round_no=1)
        # A1 被去重剔除，A2 占首格；A3 预领备用位
        assert len(out["receipts"]) == 2
        assert [r.record_id for r in out["receipts"]] == ["A2", "A3"]

        # 结算前迟到的罕见事件 R 通过去重（不同键），与已预领备用位冲突
        r_event = make_event("R", "198.51.100.9", url="/rare",
                             event_time=BASE + timedelta(minutes=3), rare=True)
        rare_out = pipeline.submit_round(SAMPLE_PLAN, [r_event], round_no=1, rare=True)
        assert rare_out["receipts"] == []  # 预领阶段不抢占，只登记罕见候选

        samples = pipeline.settle_round(SAMPLE_PLAN, 1)
        assert sorted(r.record_id for r in samples) == ["A2", "R"]
        assert len(samples) <= SLOTS_PER_ROUND
        ledger = pipeline.ledger_for(SAMPLE_PLAN)
        # A3 被释放且不扣额
        assert any(
            r.status == "released" and r.record_id == "A3"
            for r in ledger.rep_receipt.values()
        )
        assert pipeline.reconcile(SAMPLE_PLAN, 1)["ok"] is True

        # 下一轮：A3 作为合法代表自动进入实际样本
        samples_r2 = pipeline.settle_round(SAMPLE_PLAN, 2)
        assert [r.record_id for r in samples_r2] == ["A3"]
        assert pipeline.reconcile(SAMPLE_PLAN, 2)["ok"] is True

    def test_rare_priority_resolved_at_reserve_picks_a2_and_a3(self):
        """预领即结清：R 迟到时备用位已结清，当轮选 A2 和 A3。"""
        pipeline = DedupSamplePipeline(dedup_rules=[DEDUP_RULE],
                                       sample_configs=[SAMPLE_PLAN],
                                       rare_priority=False)
        a1_old, a1_dup, a2, a3 = self._build_a1a2a3()

        out = pipeline.submit_round(SAMPLE_PLAN, [a1_old, a1_dup, a2, a3], round_no=1)
        assert all(r.status == "delivered" for r in out["receipts"])
        r_event = make_event("R", "198.51.100.9", url="/rare",
                             event_time=BASE + timedelta(minutes=3), rare=True)
        rare_out = pipeline.submit_round(SAMPLE_PLAN, [r_event], round_no=1, rare=True)
        assert rare_out["receipts"] == []

        samples = pipeline.settle_round(SAMPLE_PLAN, 1)
        assert sorted(r.record_id for r in samples) == ["A2", "A3"]
        ledger = pipeline.ledger_for(SAMPLE_PLAN)
        # R 顺延到下一轮候选
        samples_r2 = pipeline.settle_round(SAMPLE_PLAN, 2)
        assert [r.record_id for r in samples_r2] == ["R"]

    def test_two_plans_have_independent_quotas(self):
        """多计划样本名额分配：两个计划各自两格，互不挤占。"""
        plan_b = SampleConfig(
            plan_id="SAMP-OTHER", event_type_id="EVEN-0001",
            sample_ratio=1.0, merge_key="url", merge_window_minutes=5,
        )
        pipeline = DedupSamplePipeline(dedup_rules=[],
                                       sample_configs=[SAMPLE_PLAN, plan_b])
        events = [
            make_event("EV-A", "10.0.0.1", url="/a"),
            make_event("EV-B", "10.0.0.2", url="/b"),
            make_event("EV-C", "10.0.0.3", url="/c"),
        ]
        out1 = pipeline.submit_round(SAMPLE_PLAN, events, round_no=1)
        out2 = pipeline.submit_round(plan_b, events, round_no=1)

        assert len(out1["receipts"]) == 2 and len(out2["receipts"]) == 2
        assert {r.plan_id for r in out1["receipts"]} == {"SAMP-TEST"}
        assert {r.plan_id for r in out2["receipts"]} == {"SAMP-OTHER"}
        assert pipeline.reconcile(SAMPLE_PLAN, 1)["ok"] is True
        assert pipeline.reconcile(plan_b, 1)["ok"] is True


class TestCallChainDedupCharge:
    """批量结算沿采样调用链修复重复扣额（IngestPipeline 侧）。"""

    def test_dedup_retained_records_drive_sample_and_no_double_charge(self):
        chain = IngestPipeline()
        events = [
            make_event("EV-A", "10.0.0.1", url="/x", event_time=BASE),
            make_event("EV-A-DUP", "10.0.0.1", url="/x", event_time=BASE + timedelta(minutes=2)),
            make_event("EV-B", "10.0.0.2", url="/y",
                       event_time=BASE + timedelta(minutes=6)),
            make_event("EV-C", "10.0.0.3", url="/z",
                       event_time=BASE + timedelta(minutes=11)),
        ]
        deduped = chain.dedup_events(events, ["client_ip", "url"], window_minutes=5)
        # 同窗同键重复提交被去重剔除，保留记录决定采样候选
        assert {r.record_id for r in deduped} == {"EV-A", "EV-B", "EV-C"}

        first = chain.sample_events(deduped, sample_ratio=1.0, merge_key="client_ip",
                                    merge_window_minutes=5)
        # 批量重试/重复结算同一批候选
        second = chain.sample_events(deduped, sample_ratio=1.0, merge_key="client_ip",
                                     merge_window_minutes=5)
        third = chain.sample_events(deduped, sample_ratio=1.0, merge_key="client_ip",
                                    merge_window_minutes=5)

        assert sorted(r.record_id for r in first) == ["EV-A", "EV-B", "EV-C"]
        assert {r.record_id for r in second} == {r.record_id for r in first}
        assert {r.record_id for r in third} == {r.record_id for r in first}
        summary = chain.sample_charge_summary("client_ip")
        assert summary["charged_slots"] == 3 and summary["representatives"] == 3

    def test_cross_window_same_key_charges_two_slots_in_chain(self):
        chain = IngestPipeline()
        events = [
            make_event("EV-0901", "10.0.0.7", event_time=datetime(2026, 11, 24, 9, 1)),
            make_event("EV-0908", "10.0.0.7", event_time=datetime(2026, 11, 24, 9, 8)),
        ]
        deduped = chain.dedup_events(events, ["client_ip", "url"], window_minutes=5)
        samples = chain.sample_events(deduped, 1.0, merge_key="client_ip",
                                      merge_window_minutes=5)
        assert len(samples) == 2
        assert chain.sample_charge_summary("client_ip")["charged_slots"] == 2


if __name__ == "__main__":
    import traceback

    test_classes = [TestMergeWindow, TestQuotaAndReturn, TestRarePriority, TestCallChainDedupCharge]
    passed = failed = 0
    for cls in test_classes:
        for name in sorted(dir(cls)):
            if not name.startswith("test_"):
                continue
            try:
                getattr(cls(), name)()
                passed += 1
                print(f"  PASS  test_sample_quota: {cls.__name__}.{name}")
            except Exception:
                failed += 1
                print(f"  FAIL  test_sample_quota: {cls.__name__}.{name}")
                traceback.print_exc()

    print(f"\ntest_sample_quota: {passed} passed, {failed} failed, {passed + failed} total")
    sys.exit(1 if failed else 0)
