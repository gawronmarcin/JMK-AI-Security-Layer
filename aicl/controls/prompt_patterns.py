from typing import Any
from aicl.models import RequestContext, Decision, Action, Match, Stage, Origin
from aicl import feeds


@register_control
class InjectionPatternsControl:
    id: str = "C-INJ-PAT"
    stages: tuple[Stage, ...] = (Stage.input, Stage.tool_result)
    priority: int = 20  # < 100, szybka kontrola deterministyczna

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        snap = feeds.current()

        # Pobranie konfiguracji z polityki YAML
        sig_sets = cfg.params.get("signature_sets", ["injection"]) if hasattr(cfg, "params") else ["injection"]
        min_severity_cfg = cfg.min_severity if hasattr(cfg, "min_severity") else "low"
        target_action = Action(cfg.action) if hasattr(cfg, "action") else Action.block

        active_signatures = []
        for s_set in sig_sets:
            active_signatures.extend(snap.for_set(s_set))

        matches = []
        threat_ids = set()
        accumulated_risk = 0.0
        highest_severity_val = 0

        # Wagi do stopniowania ryzyka (graded risk - nie tylko hit/no-hit)
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        risk_weights = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
        min_severity_val = severity_map.get(min_severity_cfg, 1)

        for segment in ctx.segments:
            # Skanujemy tylko niezaufane źródła i wejście użytkownika
            if segment.origin not in (Origin.user, Origin.tool_result, Origin.retrieved, Origin.artifact):
                continue

            for sig in active_signatures:
                pattern = snap.regex(sig.id)
                if not pattern:
                    continue

                sig_sev_val = severity_map.get(sig.severity, 1)
                match_found = False

                # Zgodnie z sekcją 5.2 - dopasowanie na widoku znormalizowanym
                if pattern.search(segment.norm):
                    matches.append(Match(
                        kind=sig.kind,
                        segment_idx=segment.idx,
                        in_decoded=False
                    ))
                    match_found = True

                # Dopasowanie w zdekodowanych fragmentach (Base64, URL, etc.)
                for decoded_text in segment.decoded:
                    if pattern.search(decoded_text):
                        matches.append(Match(
                            kind=sig.kind,
                            segment_idx=segment.idx,
                            in_decoded=True
                        ))
                        match_found = True

                if match_found:
                    threat_ids.update(sig.refs)
                    accumulated_risk += risk_weights.get(sig.severity, 0.5)
                    highest_severity_val = max(highest_severity_val, sig_sev_val)

        # Ograniczenie ryzyka do maksymalnej wartości 1.0 dla sędziego semantycznego
        final_risk = min(accumulated_risk, 1.0)

        # Decyzja na podstawie najwyższego wykrytego zagrożenia i progu z profilu
        final_action = Action.allow
        severity_str = "low"

        if matches and highest_severity_val >= min_severity_val:
            final_action = target_action
            # Mapowanie odwrotne wartości na string
            for k, v in severity_map.items():
                if v == highest_severity_val:
                    severity_str = k
                    break

        # Jeżeli brak dopasowań i zdefiniowanych tagów, kontrolka używa domyślnych dla siebie
        final_threats = list(threat_ids) if threat_ids else ["TH-01", "TH-02"]

        return Decision(
            control_id=self.id,
            threat_ids=final_threats,
            action=final_action,
            severity=severity_str,
            risk=final_risk,
            matches=matches
        )