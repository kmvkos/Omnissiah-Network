"""Regression checks for Russian VPN UI without changing VPN state."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "templates" / "vpn_overview.html"


def test_critical_operator_labels_are_in_russian():
    page = PAGE.read_text()
    for label in (
        "Обзор VPN-сети", "1. Состояние узлов",
        "2. Соответствие конфигурации", "3. Предпросмотр изменений",
        "Ожидание", "Успешно завершено", "Требует восстановления",
        "Есть расхождения", "Совпадает", "Ожидается пиров",
        "Обнаружено пиров", "VPN-связи, заданные администратором",
    ):
        assert label in page
    for legacy_label in ("Preview Changes", "Desired / Actual", "In sync", "'Drift'", "'Unknown'", ">Desired</span>"):
        assert legacy_label not in page


def test_status_codes_preserved_for_logic_only_text_is_translated():
    page = PAGE.read_text()
    assert "item.state === 'in_sync'" in page
    assert "item.state === 'drift'" in page
    assert "item.reason === 'route_changes_validated_but_not_applied'" in page
    assert "item.transaction_available === true" in page
    assert "typeof item.preview_revision === 'string'" in page
    assert "vpnJournalStateRu(item.state)" in page
    assert "vpnJournalPhaseRu(item.phase)" in page
    assert "vpnReasonRu(item.reason)" in page
    assert "document.createElement('td')" in page
    assert "cell.textContent" in page
    assert "row.innerHTML" not in page


def test_safe_operation_fencing_and_preview_unchanged():
    page = PAGE.read_text()
    for guard in (
        "X-VPN-Explicit-Apply", "crypto.randomUUID()",
        "expected_revision: previewRevision", "operation_id: operationId",
        "prompt('Для подтверждения введите имя узла:",
        "vpnPreviewRows", "vpnTxHealthRows", "vpnReconcileRows",
    ):
        assert guard in page
    assert 'href="#vpn-health"' in page
    assert 'href="#vpn-compare"' in page
    assert 'href="#vpn-plan"' in page
    assert 'href="#vpn-journal"' in page
