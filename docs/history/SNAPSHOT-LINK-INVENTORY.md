# Frozen snapshot link inventory

The pre-redesign architecture, module snapshot and their manifest remain **immutable historical evidence**. Their original link destinations are intentionally not rewritten when current documents move. These are an explicit exception to the current-document no-broken-links requirement; no compatibility copy, stub or symlink is added. Use the replacements below for present-day navigation, not as a claim that the historical snapshot now describes implemented or qualified behavior.

Paths below are relative to `docs/history/`; source line numbers refer to the unchanged snapshot bytes.

| Frozen snapshot | Line | Original destination (retained as text) | Current destination |
|---|---:|---|---|
| [2026-10-02-pre-redesign-ARCHITECTURE.md](2026-10-02-pre-redesign-ARCHITECTURE.md) | 3 | `../superpowers/plans/2026-10-01-native-protocol-implementation.md` | [Current document](plans/2026-10-01-native-protocol-implementation.md) |
| [2026-10-02-pre-redesign-ARCHITECTURE.md](2026-10-02-pre-redesign-ARCHITECTURE.md) | 54 | `../SETTLEMENT-RESEARCH.md#42-positive-conflict-refund-candidate--audit-bổ-sung-2026-10-01` | [Current document](../research/SETTLEMENT-RESEARCH.md#42-positive-conflict-refund-candidate--audit-bổ-sung-2026-10-01) |
| [2026-10-02-pre-redesign-ARCHITECTURE.md](2026-10-02-pre-redesign-ARCHITECTURE.md) | 162 | `../SETTLEMENT-RESEARCH.md#42-positive-conflict-refund-candidate--audit-bổ-sung-2026-10-01` | [Current document](../research/SETTLEMENT-RESEARCH.md#42-positive-conflict-refund-candidate--audit-bổ-sung-2026-10-01) |
| [2026-10-02-pre-redesign-ARCHITECTURE.md](2026-10-02-pre-redesign-ARCHITECTURE.md) | 162 | `../ARCHITECTURE-AUDIT.md#9-positive-conflict-alternative--không-assume-exclusion-bắt-buộc` | [Current document](../research/ARCHITECTURE-AUDIT.md#9-positive-conflict-alternative--không-assume-exclusion-bắt-buộc) |
| [2026-10-02-pre-redesign-ARCHITECTURE.md](2026-10-02-pre-redesign-ARCHITECTURE.md) | 167 | `../SETTLEMENT-RESEARCH.md#41-absence-branch-research-construction-exact-payment-proof-aware-escrow` | [Current document](../research/SETTLEMENT-RESEARCH.md#41-absence-branch-research-construction-exact-payment-proof-aware-escrow) |
| [2026-10-02-pre-redesign-ARCHITECTURE.md](2026-10-02-pre-redesign-ARCHITECTURE.md) | 169 | `../SETTLEMENT-RESEARCH.md#3-refund-before-fund-recovery-component-chưa-complete-fair-exchange` | [Current document](../research/SETTLEMENT-RESEARCH.md#3-refund-before-fund-recovery-component-chưa-complete-fair-exchange) |
| [2026-10-02-pre-redesign-ARCHITECTURE.md](2026-10-02-pre-redesign-ARCHITECTURE.md) | 182 | `../superpowers/plans/2026-10-01-native-protocol-implementation.md` | [Current document](plans/2026-10-01-native-protocol-implementation.md) |
| [2026-10-02-pre-redesign-MODULES.md](2026-10-02-pre-redesign-MODULES.md) | 3 | `../superpowers/plans/2026-10-01-native-protocol-implementation.md` | [Current document](plans/2026-10-01-native-protocol-implementation.md) |
| [2026-10-02-pre-redesign-MODULES.md](2026-10-02-pre-redesign-MODULES.md) | 195 | `../SETTLEMENT-RESEARCH.md` | [Current document](../research/SETTLEMENT-RESEARCH.md) |
| [2026-10-02-pre-redesign-MODULES.md](2026-10-02-pre-redesign-MODULES.md) | 199 | `../SETTLEMENT-RESEARCH.md#42-positive-conflict-refund-candidate--audit-bổ-sung-2026-10-01` | [Current document](../research/SETTLEMENT-RESEARCH.md#42-positive-conflict-refund-candidate--audit-bổ-sung-2026-10-01) |
| [2026-10-02-pre-redesign-MODULES.md](2026-10-02-pre-redesign-MODULES.md) | 199 | `../ARCHITECTURE-AUDIT.md#9-positive-conflict-alternative--không-assume-exclusion-bắt-buộc` | [Current document](../research/ARCHITECTURE-AUDIT.md#9-positive-conflict-alternative--không-assume-exclusion-bắt-buộc) |

The native implementation plan now lives in `docs/history/plans/`; settlement research and architecture audit live in `docs/research/`. Their historical findings and incomplete task lists are not the active V1 guide. Follow the [Z2Z-V1 implementation prompt](../Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md) and [native implementation status](../NATIVE-IMPLEMENTATION-STATUS.md) for current requirements and exercised evidence.

## Separately retained imported-source exception

The imported Kerb design retains the inherited fragment `zoss/docs/ARCHITECTURE.md#5-interface-proposed`, which no longer exists in the sibling architecture. This pre-existing source issue is documented in the unchanged [import link report](../imports/kerb/LINK-REPORT.json); it is not a new relocation failure. Use the current [Zoss architecture](../../../zoss/docs/ARCHITECTURE.md) and [DEX integration boundary](../../../zoss/docs/private_dex.md). The imported source bytes and manifest remain unchanged.
