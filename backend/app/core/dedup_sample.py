"""拾音工坊去重与采样归并管道：event_type→dedup_filter→sample_job。

数据流：事件分类 → 去重过滤 → 采样归并
涉及模块：event_type, dedup_filter, sample_job

名额模型（多计划样本名额分配）：
- 每个采样计划独立维护一个 ``PlanQuotaLedger``，一轮两个名额：
  常规代表先占首格（slot 1），第二格为可借用备用位（slot 2），
  被调查员退回的代表在新一轮释放额外名额（bonus slot）。
- 采样归并只消费去重保留下来的原事件；同一归并代表（merge_key +
  计划配置的归并时间窗）在整个链条里只扣一格，重复预领/重复确认幂等。
- 罕见事件优先权可保留到结算时刻：预领阶段只挂预留，结算时罕见代表
  可以挤掉常规代表对备用位的预留（被挤掉者不扣额、顺延下一轮）。
"""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.core.models import DedupFilter, EventRecord, SampleConfig


# ---------- 预置去重过滤规则 ----------

PRESET_DEDUP_RULES: list[DedupFilter] = [
    DedupFilter(
        rule_id="DEDU-0001",
        event_type_id="EVEN-0001",
        dedup_fields=["client_ip", "url"],
        window_minutes=60,
        fingerprint_algo="sha256",
    ),
    DedupFilter(
        rule_id="DEDU-0002",
        event_type_id="EVEN-0002",
        dedup_fields=["level", "message"],
        window_minutes=10,
        fingerprint_algo="sha256",
    ),
]

# ---------- 预置采样归并配置 ----------

PRESET_SAMPLE_CONFIGS: list[SampleConfig] = [
    SampleConfig(
        plan_id="SAMP-0001",
        event_type_id="EVEN-0001",
        sample_ratio=0.5,
        merge_key="client_ip",
        merge_window_minutes=5,
        retain_policy="latest",
    ),
    SampleConfig(
        plan_id="SAMP-0002",
        event_type_id="EVEN-0002",
        sample_ratio=1.0,
        merge_key="message",
        merge_window_minutes=10,
        retain_policy="latest",
    ),
]

# 每轮基础名额：常规首格 + 可借用备用格
SLOTS_PER_ROUND = 2


def window_bucket(event_time: datetime, window_minutes: int) -> datetime:
    """按固定窗口把事件时间对齐到窗起点（如 5 分钟窗：09:01→09:00、09:08→09:05）。"""
    minutes = event_time.minute - (event_time.minute % max(1, window_minutes))
    return event_time.replace(minute=minutes, second=0, microsecond=0)


@dataclass
class MergeRepresentative:
    """一个实际归并代表：同 merge_key 且同一归并时间窗内只保留一个原事件。"""

    representative_id: str
    merge_key: str
    window_start: datetime
    record: EventRecord
    rare: bool = False

    @property
    def record_id(self) -> str:
        return self.record.record_id


@dataclass
class SlotReceipt:
    """名额回执：一个代表一格，记录占用/借用/交付/释放的完整事实。"""

    receipt_id: str
    plan_id: str
    round_no: int
    slot_no: int
    kind: str  # regular=常规首格 / borrow=借用备用位 / bonus=退回释放的追加名额
    representative_id: str
    record_id: str
    merge_key: str
    window_start: datetime
    rare: bool
    status: str = "reserved"  # reserved=预领 / delivered=已交付 / released=结算前释放
    confirmations: int = 0
    request_id: str | None = None


@dataclass
class RoundState:
    """单轮名额状态。"""

    round_no: int
    capacity: int
    bonus_slots: int = 0
    reservations: dict[str, SlotReceipt] = field(default_factory=dict)
    rare_contenders: list[str] = field(default_factory=list)
    delivered: list[str] = field(default_factory=list)
    released: list[str] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)
    receipts: list[SlotReceipt] = field(default_factory=list)


class PlanQuotaLedger:
    """单个采样计划的名额账本：预领、结算、确认、退回全部幂等。

    扣额口径：一个归并代表在一个计划里至多产生一张 delivered 回执；
    预领后若在结算前被罕见优先权挤掉，回执置 released 且不扣额，
    代表顺延到下一轮候选队列。
    """

    def __init__(self, config: SampleConfig, rare_priority: bool = True):
        self.config = config
        # True：罕见优先权保留到结算；False：预领即结清（结算时不再调整）
        self.rare_priority = rare_priority
        self.rounds: dict[int, RoundState] = {}
        self.rep_records: dict[str, MergeRepresentative] = {}
        self.rep_receipt: dict[str, SlotReceipt] = {}
        self.delivered_reps: set[str] = set()
        self.returned_reps: set[str] = set()
        self.counted_returns: set[str] = set()
        self.confirmed_reps: set[str] = set()
        self._requests: dict[str, SlotReceipt] = {}
        self._pending_queue: list[str] = []
        self._seq = 0
        self._lock = threading.RLock()

    # ---------- 轮次与名额 ----------

    def open_round(self, round_no: int) -> RoundState:
        """开启一轮；退回事实只在开启下一轮时释放为追加名额。"""
        with self._lock:
            existing = self.rounds.get(round_no)
            if existing is not None:
                return existing
            new_returns = [r for r in self.returned_reps if r not in self.counted_returns]
            bonus = len(new_returns)
            self.counted_returns.update(new_returns)
            state = RoundState(
                round_no=round_no,
                capacity=SLOTS_PER_ROUND + bonus,
                bonus_slots=bonus,
            )
            self.rounds[round_no] = state
            # 上一轮被释放/未排上的合法代表优先在新一轮预领
            for rep_id in list(self._pending_queue):
                self._pending_queue.remove(rep_id)
                rep = self.rep_records.get(rep_id)
                if rep is not None:
                    self.reserve(rep, round_no, rare=rep.rare)
            return state

    def reserve(self, rep: MergeRepresentative, round_no: int,
                rare: bool = False, request_id: str | None = None) -> SlotReceipt | None:
        """预领一个名额。返回回执；无名额/不可领取时返回 None。幂等。"""
        with self._lock:
            rep.rare = rare or rep.rare
            if request_id and request_id in self._requests:
                return self._requests[request_id]
            # 已交付（含已退回）的代表不能重新领取
            if rep.representative_id in self.delivered_reps or rep.representative_id in self.returned_reps:
                return self.rep_receipt.get(rep.representative_id)
            self.rep_records.setdefault(rep.representative_id, rep)
            state = self.open_round(round_no)
            existing = state.reservations.get(rep.representative_id)
            if existing is not None:
                if request_id:
                    self._requests.setdefault(request_id, existing)
                return existing
            occupied = len(state.reservations)
            if occupied >= state.capacity:
                if rare and self.rare_priority:
                    # 罕见候选先登记，结算时再按罕见优先权竞争备用位
                    if rep.representative_id not in state.rare_contenders:
                        state.rare_contenders.append(rep.representative_id)
                    return None
                if rep.representative_id not in self._pending_queue:
                    self._pending_queue.append(rep.representative_id)
                return None
            self._seq += 1
            slot_no = occupied + 1
            kind = "regular" if slot_no == 1 else ("borrow" if slot_no == SLOTS_PER_ROUND else "bonus")
            receipt = SlotReceipt(
                receipt_id=f"{self.config.plan_id}-R{round_no}-{self._seq:03d}",
                plan_id=self.config.plan_id,
                round_no=round_no,
                slot_no=slot_no,
                kind=kind,
                representative_id=rep.representative_id,
                record_id=rep.record_id,
                merge_key=rep.merge_key,
                window_start=rep.window_start,
                rare=rep.rare,
                request_id=request_id,
            )
            if not self.rare_priority:
                # 预领即结清：备用位一旦被常规代表结清，迟到的罕见事件无法挤入
                receipt.status = "delivered"
                state.delivered.append(rep.representative_id)
                self.delivered_reps.add(rep.representative_id)
            state.reservations[rep.representative_id] = receipt
            state.receipts.append(receipt)
            self.rep_receipt[rep.representative_id] = receipt
            if request_id:
                self._requests[request_id] = receipt
            return receipt

    def settle_round(self, round_no: int) -> list[MergeRepresentative]:
        """结算一轮：应用保留到结算的罕见优先权，交付实际样本。"""
        with self._lock:
            state = self.open_round(round_no)
            if self.rare_priority:
                for rep_id in list(state.rare_contenders):
                    rep = self.rep_records.get(rep_id)
                    if rep is None or rep_id in state.reservations:
                        continue
                    # 从最高槽位的常规预留里挤掉一个（首格常规优先保留）
                    victim = None
                    for receipt in sorted(state.reservations.values(),
                                          key=lambda r: r.slot_no, reverse=True):
                        if not receipt.rare and receipt.status == "reserved":
                            victim = receipt
                            break
                    if victim is None:
                        if rep_id not in self._pending_queue:
                            self._pending_queue.append(rep_id)
                        continue
                    state.reservations.pop(victim.representative_id)
                    victim.status = "released"
                    state.released.append(victim.representative_id)
                    self._pending_queue.append(victim.representative_id)
                    rep.rare = True
                    receipt = SlotReceipt(
                        receipt_id=victim.receipt_id,
                        plan_id=self.config.plan_id,
                        round_no=round_no,
                        slot_no=victim.slot_no,
                        kind=victim.kind,
                        representative_id=rep.representative_id,
                        record_id=rep.record_id,
                        merge_key=rep.merge_key,
                        window_start=rep.window_start,
                        rare=True,
                    )
                    state.reservations[rep.representative_id] = receipt
                    state.receipts.append(receipt)
                    self.rep_receipt[rep.representative_id] = receipt
                state.rare_contenders.clear()
            delivered: list[MergeRepresentative] = []
            for receipt in state.reservations.values():
                if receipt.status == "reserved":
                    receipt.status = "delivered"
                    state.delivered.append(receipt.representative_id)
                    self.delivered_reps.add(receipt.representative_id)
                if receipt.status == "delivered":
                    rep = self.rep_records.get(receipt.representative_id)
                    if rep is not None:
                        delivered.append(rep)
            return delivered

    # ---------- 确认与退回 ----------

    def confirm(self, representative_id: str,
                request_id: str | None = None) -> tuple[SlotReceipt | None, bool]:
        """并发/重复确认同一代表只扣一次：首次确认 charged=True，其余幂等返回。"""
        with self._lock:
            if request_id and request_id in self._requests:
                return self._requests[request_id], False
            receipt = self.rep_receipt.get(representative_id)
            if receipt is None:
                return None, False
            first = representative_id not in self.confirmed_reps
            if first:
                self.confirmed_reps.add(representative_id)
            receipt.confirmations += 1
            if request_id:
                self._requests[request_id] = receipt
            return receipt, first

    def return_representative(self, representative_id: str) -> tuple[bool, int]:
        """调查员正式退回。

        已交付回执保持原样；退回事实只释放下一轮可用额度。
        重复退回不重复释放。返回 (是否本次新登记, 释放的追加名额)。
        """
        with self._lock:
            if representative_id not in self.delivered_reps:
                return False, 0
            if representative_id in self.returned_reps:
                return False, 0
            self.returned_reps.add(representative_id)
            return True, 1

    # ---------- 核对 ----------

    def reconcile(self, round_no: int) -> dict[str, object]:
        """核对一轮的实际样本与名额回执：样本数=交付回执数，每代表仅扣一格。"""
        state = self.rounds.get(round_no)
        if state is None:
            return {"ok": False, "reason": "round_not_open"}
        delivered_receipts = [
            r for r in state.receipts if r.status == "delivered"
        ]
        receipt_reps = {r.representative_id for r in delivered_receipts}
        sample_reps = set(state.delivered)
        charged_once = len(receipt_reps) == len(delivered_receipts)
        return {
            "ok": receipt_reps == sample_reps and charged_once,
            "round_no": round_no,
            "capacity": state.capacity,
            "sample_count": len(sample_reps),
            "receipt_count": len(delivered_receipts),
            "released": list(state.released),
            "pending": list(self._pending_queue),
            "bonus_slots": state.bonus_slots,
        }


class DedupSamplePipeline:
    """去重与采样归并处理管道。

    接收 EventRecord 集合 → dedup_filter 去重 → sample_job 采样归并
    """

    def __init__(self, dedup_rules: list[DedupFilter] | None = None,
                 sample_configs: list[SampleConfig] | None = None,
                 rare_priority: bool = True):
        if dedup_rules is None:
            dedup_rules = PRESET_DEDUP_RULES
        if sample_configs is None:
            sample_configs = PRESET_SAMPLE_CONFIGS
        self.dedup_rules = dedup_rules
        self.sample_configs = sample_configs
        # rule_id → 指纹 → 去重保留事件的事件时间（窗口外指纹可再次通过）
        self._fingerprint_store: dict[str, dict[str, list[datetime]]] = {}
        self._ledgers: dict[str, PlanQuotaLedger] = {
            config.plan_id: PlanQuotaLedger(config, rare_priority=rare_priority)
            for config in sample_configs
        }

    # ---------- 数据流 4: event_type → dedup_filter → sample_job ----------

    def deduplicate(self, records: list[EventRecord],
                    dedup_rule: DedupFilter) -> tuple[list[EventRecord], int, int]:
        """对事件集合按 dedup_filter 执行窗口去重。

        对每条事件按去重字段生成 SHA256 指纹；同一指纹只在去重窗口内
        （按 event_time 时间差）判重，窗口外的同指纹事件作为新记录保留。

        返回：(去重后保留记录列表, 本次命中次数, 累计忽略次数)
        """
        key = dedup_rule.rule_id
        store = self._fingerprint_store.setdefault(key, {})
        deduped: list[EventRecord] = []
        hit = 0
        window_seconds = dedup_rule.window_minutes * 60

        for record in records:
            fp = dedup_rule.fingerprint(record)
            retained_times = store.setdefault(fp, [])
            within_window = any(
                abs((record.event_time - kept).total_seconds()) <= window_seconds
                for kept in retained_times
            )
            if within_window:
                dedup_rule.hit_count += 1
                hit += 1
                dedup_rule.ignore_count += 1
                continue
            retained_times.append(record.event_time)
            deduped.append(record)

        return deduped, hit, dedup_rule.ignore_count

    def deduplicate_all(self, records: list[EventRecord]) -> list[EventRecord]:
        """按事件类型匹配去重规则批量去重。

        每种事件类型匹配对应的 dedup_filter 规则。
        """
        result: list[EventRecord] = list(records)
        for dedup_rule in self.dedup_rules:
            target_type_id = dedup_rule.event_type_id
            target_records = [r for r in result if r.event_type.type_id == target_type_id]
            other_records = [r for r in result if r.event_type.type_id != target_type_id]
            deduped, _, _ = self.deduplicate(target_records, dedup_rule)
            result = deduped + other_records
        return result

    def merge_representatives(self, records: list[EventRecord],
                              config: SampleConfig) -> list[MergeRepresentative]:
        """按计划的 merge_key 与 merge_window_minutes 归并出实际代表。

        输入必须是去重保留下来的原事件；同键且落在同一归并时间窗的
        事件只保留一个代表（retain_policy=latest 时保留最新原事件），
        同键跨窗的代表各自独立占额。
        """
        if not config.merge_key:
            return [
                MergeRepresentative(
                    representative_id=f"{config.plan_id}:{r.record_id}",
                    merge_key="",
                    window_start=window_bucket(r.event_time, config.merge_window_minutes),
                    record=r,
                )
                for r in records
            ]
        groups: dict[str, MergeRepresentative] = {}
        order: list[str] = []
        for record in records:
            mkey = record.parsed_fields.get(config.merge_key, "")
            if not mkey:
                continue
            ws = window_bucket(record.event_time, config.merge_window_minutes)
            rep_id = f"{config.plan_id}:{mkey}:{ws.isoformat()}"
            if rep_id not in groups:
                order.append(rep_id)
            current = groups.get(rep_id)
            if current is None or (
                config.retain_policy == "latest"
                and record.event_time > current.record.event_time
            ):
                groups[rep_id] = MergeRepresentative(
                    representative_id=rep_id,
                    merge_key=mkey,
                    window_start=ws,
                    record=record,
                )
        return [groups[rep_id] for rep_id in order]

    def ledger_for(self, config: SampleConfig) -> PlanQuotaLedger:
        """获取（或创建）某采样计划的独立名额账本。"""
        ledger = self._ledgers.get(config.plan_id)
        if ledger is None:
            ledger = PlanQuotaLedger(config)
            self._ledgers[config.plan_id] = ledger
        return ledger

    def submit_round(self, config: SampleConfig, records: list[EventRecord],
                     round_no: int, rare: bool = False,
                     request_id: str | None = None,
                     dedup_rule: DedupFilter | None = None
                     ) -> dict[str, object]:
        """串联入口：去重 → 归并代表 → 按计划名额预领。

        去重保留记录决定采样候选；每个实际归并代表只预领一格，
        同一代表/同一 request_id 重复提交不会重复扣额。
        """
        rule = dedup_rule or self._rule_for(config.event_type_id)
        if rule is None:
            deduped = list(records)
            hit = 0
            ignored = 0
        else:
            deduped, hit, ignored = self.deduplicate(records, rule)
        reps = self.merge_representatives(deduped, config)
        ledger = self.ledger_for(config)
        ledger.open_round(round_no)
        receipts: list[SlotReceipt] = []
        pending: list[str] = []
        for rep in reps:
            receipt = ledger.reserve(rep, round_no, rare=rare, request_id=request_id)
            if receipt is not None:
                receipts.append(receipt)
            else:
                pending.append(rep.representative_id)
        return {
            "plan_id": config.plan_id,
            "round_no": round_no,
            "dedup_retained": len(deduped),
            "dedup_hits": hit,
            "dedup_ignored": ignored,
            "candidates": reps,
            "receipts": receipts,
            "pending": pending,
        }

    def settle_round(self, config: SampleConfig,
                     round_no: int) -> list[EventRecord]:
        """结算某计划一轮，返回实际交付样本（最多一轮名额数）。"""
        ledger = self.ledger_for(config)
        reps = ledger.settle_round(round_no)
        return [rep.record for rep in reps]

    def confirm_representative(self, config: SampleConfig, representative_id: str,
                               request_id: str | None = None
                               ) -> tuple[SlotReceipt | None, bool]:
        """确认代表交付；并发/重复确认同一代表只扣一次额度。"""
        return self.ledger_for(config).confirm(representative_id, request_id)

    def return_representative(self, config: SampleConfig,
                              representative_id: str) -> tuple[bool, int]:
        """正式退回代表；本轮回执不变，下一轮释放名额，重复退回不重复释放。"""
        return self.ledger_for(config).return_representative(representative_id)

    def reconcile(self, config: SampleConfig, round_no: int) -> dict[str, object]:
        """核对计划某轮实际样本与借用/名额回执是否对得上。"""
        return self.ledger_for(config).reconcile(round_no)

    def sample(self, records: list[EventRecord],
               config: SampleConfig) -> list[EventRecord]:
        """按采样配置进行无状态采样归并（兼容旧调用）。

        有状态、带名额/借用/退回语义的路径请走 ``submit_round`` +
        ``settle_round``；本方法保留“按比例截断 + 按键归并保留最新”的
        旧口径，不做任何名额扣减。
        """
        # 采样
        threshold = max(1, int(len(records) * config.sample_ratio))
        sampled = list(records[:threshold])

        # 归并
        if config.merge_key:
            merged: dict[str, EventRecord] = {}
            for record in sampled:
                mkey = record.parsed_fields.get(config.merge_key, "")
                if not mkey:
                    continue
                existing = merged.get(mkey)
                if existing is None or record.event_time > existing.event_time:
                    merged[mkey] = record
            return list(merged.values())
        return sampled

    def sample_all(self, records: list[EventRecord]) -> list[EventRecord]:
        """按事件类型匹配采样配置批量采样归并。"""
        result: list[EventRecord] = []
        handled_type_ids: set[str] = set()
        for config in self.sample_configs:
            target_type_id = config.event_type_id
            target_records = [r for r in records if r.event_type.type_id == target_type_id]
            handled_type_ids.add(target_type_id)
            sampled = self.sample(target_records, config)
            result.extend(sampled)
        # 未匹配采样配置的事件保留原样
        for record in records:
            if record.event_type.type_id not in handled_type_ids:
                result.append(record)
        return result

    def get_stats(self) -> dict[str, dict[str, int]]:
        """获取去重规则统计数据。"""
        stats: dict[str, dict[str, int]] = {}
        for rule in self.dedup_rules:
            stats[rule.rule_id] = {
                "hit_count": rule.hit_count,
                "ignore_count": rule.ignore_count,
            }
        return stats

    def reset_fingerprints(self):
        """重置指纹缓存（窗口周期结束或测试隔离用）。"""
        self._fingerprint_store.clear()

    def _rule_for(self, event_type_id: str) -> DedupFilter | None:
        for rule in self.dedup_rules:
            if rule.event_type_id == event_type_id:
                return rule
        return None


def make_dedup_sample_pipeline() -> DedupSamplePipeline:
    """工厂函数：创建预配置的去重采样管道实例。"""
    return DedupSamplePipeline()
