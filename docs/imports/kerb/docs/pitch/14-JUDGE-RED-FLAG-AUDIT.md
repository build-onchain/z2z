# Kerb — judge red-flag audit

Status: DRAFT / PROPOSED; this is a pre-submission refusal screen, not a judge's actual score.

Owner role: Colosseum mentor and pre-seed VC refusal-screen perspective only, not a claim of appointment, inside access or official judging.

Date: 2026-09-28

Evidence legend: P = primary source, S = secondary source, I = inference, **U = unverified**. Facts marked U are unverified. [INFERENCE] marks analyst judgment. [00-CANONICAL](../00-CANONICAL.md) is the proposed, unimplemented, unbenchmarked consistency reference; canonical wins on conflicts and sets the forbidden-claim boundary.

**Authority banner 2026-10-01:** this refusal screen preserves historical public-Solana claims/ratings, not a current audit or overall architecture authority. [Current docs decision](../00-CANONICAL.md#0-current-documentation-authority) adopts shared libraries only; optional messaging stays OFF/non-money and the unapproved Oct1 financial/private candidate retains **GD2 structural FAIL**. No privacy/runtime/financial approval or publication follows; canonical precedence below is dossier-local.

## Basis and audit rule

Every individual team flag (25) and pitch-deck red/yellow flag (25) below comes from Josip Volarević's [Colosseum playbook post](../sources/x/status-2038643299221729462.md), §2, retrieved 2026-09-28. This is one founder's advice, **not** the official judging rubric. `OK` = the *specified draft control* is present and verifiable, not that a final submission passed; `RISK` = a known deficiency or missing artifact; `UNKNOWN` = private founder fact or unmeasured result. The founder must answer questions with evidence; silence never becomes a favorable team assumption. No working deck, video, team roster, customers or code are evidenced here. Official criteria are functionality, impact, novelty, UX, open source and business plan ([rules](https://colosseum.com/legal/Crypto%20World's%20Fair%20Hackathon%20Rules.pdf), E15).

The post's flags about fluent English, shared native language, timezone, overtime, quitting jobs and pay are *heuristics in that author's list*, not moral judgments or official entry requirements. Clear communication and reliable collaboration can be demonstrated in other ways; do not exclude founders by nationality, native language or disability. The contest's actual eligibility and English-language submission rules are in its official rules, not the post.

## Team screen — all 25 post-listed flags

Evidence shorthand: **U team** = no founder roster, biography, employment, equity or work log supplied in the canonical record; **U field** = no directly observed field activity. Questions are to the founder, not statements of fact about the founder.

| # | Post flag | Kerb status | Evidence | Fix / specific founder question |
|---|---|---|---|---|
| T01 | Some team members are part-time | UNKNOWN | U team | Who is full-time now, and what commitment is feasible after the event? Show dated individual commitments, not assumptions. |
| T02 | Hackathon-only mindset | UNKNOWN | U team; [roadmap](../product/16-ROADMAP-AND-DECISIONS.md) is intent, not founder commitment | Will each founder continue past October 12, and under what milestone or stop rule? |
| T03 | Founders have not left other jobs for this product | UNKNOWN | U team | What employment or contractual conflicts exist? State truthfully whether anyone has left or will leave work; quitting is not an official eligibility test. |
| T04 | Afraid or unable to wear multiple hats | UNKNOWN | U team | What customer, engineering and support tasks has each founder personally completed? |
| T05 | Poor storytellers | UNKNOWN | No recorded founder pitch | Record a plain-language explanation and obtain unprompted comprehension feedback. |
| T06 | Cannot speak fluent English | UNKNOWN | No recording; official submission content must be in English | Can a speaker produce a clear English video or accurate narration/captions? Fluency or native accent is not the criterion. |
| T07 | Cannot explain the idea clearly and simply | RISK | [13 script](13-PITCH-NARRATIVE.md) is draft, untested | Give an outsider the first 20 seconds; ask them to state user, order flow and unknowns. Revise until correct without coaching. |
| T08 | Wrong domain / vertical / direction | UNKNOWN | Product hypothesis only; E17 U | Which founder has relevant market-structure, issuer, token-program or distributor operating experience? Show attributable work. |
| T09 | Founders are not technical | UNKNOWN | No roster or code ownership | Which founder owns program implementation and security review? Demonstrate personally built code. |
| T10 | Founders do not talk to users directly | RISK | E18: no buyer/seller/distributor commitment; no interviews in evidence register | Which founder directly documents at least ten substantive conversations across distributor decision-makers, actual eligible buyers/sellers and makers? See [validation gate](../business/12-GTM-AND-VALIDATION.md). |
| T11 | Do not take distribution seriously | RISK | Distributor route is hypothetical; no trials (E18) | Who secures two trial tickets and determines eligible onboarding channels? |
| T12 | Lack focus and clarity | RISK | Narrow proposed mechanism, but cross, residual and issuer guards could distract | Which one-mint demo and one distributor cohort are in scope? Cut competing scope and refuse parallel chain work. |
| T13 | Different timezones | UNKNOWN | U team | What are members' working overlaps and handoff rules? Separate coordination risk from geography. |
| T14 | Different native languages | UNKNOWN | U team | What shared working language and artifact-review process actually works? Do not select founders by native language. |
| T15 | Not working overtime | UNKNOWN | U team; no hours recorded | What work capacity and dated outputs can the team actually sustain? Avoid unverifiable hours as proof of competence. |
| T16 | Ownership unclear: who builds? | UNKNOWN | No founder ownership map | Name accountable authors for program, client, user research and submission with actual code/artifact evidence. |
| T17 | Unreasonably unequal equity | UNKNOWN | No cap table | Do founders understand allocation, vesting and decision rights? Review privately; never invent percentages. |
| T18 | Team too large (post says usually ≤4) | UNKNOWN | No roster | How many entrants contribute, and what owned outputs justify each role? |
| T19 | Solo founder / team too small | UNKNOWN | No roster | If solo, who gives independent code review and customer access? Do not claim a cofounder exists. |
| T20 | High burn / founder pay above minimum | UNKNOWN | No payroll or runway | What is actual burn, runway and salary policy? Assess sustainability without inventing pay or equating low pay with virtue. |
| T21 | Majority nontechnical | UNKNOWN | No roster | What fraction writes/operates core code? Show ownership rather than job titles. |
| T22 | All-technical team without generalist/product thinking | UNKNOWN | No roster | Who owns discovery, distributor workflows, issuer/legal diligence and communication? |
| T23 | Project-manager role without execution | UNKNOWN | No roster | Is every listed member shipping a verifiable output rather than solely coordinating? |
| T24 | Outsourced development or marketing | UNKNOWN | No provenance of code or creative work | Who authored each material? Disclose any contractor and licensing/IP rights truthfully. |
| T25 | Slow iteration | UNKNOWN | Nothing built, no revision log | Show dated hypothesis → observation → changed code/copy decisions, not activity metrics. |

## Deck screen — all 25 post-listed red/yellow flags

The proposed ten-slide copy exists in [13](13-PITCH-NARRATIVE.md); an actual deck and video do not. `OK` below means the named *copy constraint* is met in the outline only. Any design or runtime check remains RISK until a real artifact is inspected.

| # | Post flag | Kerb status | Evidence | Fix / acceptance test |
|---|---|---|---|---|
| D01 | Too much text | OK | Ten outlined slides, each ≤20 words | Count all visible copy in exported deck again, including captions and footers. |
| D02 | Too many product features | RISK | Scope includes cross, residual and issuer guards | Spend demo time on cross, one residual and one refusal; push roadmap beyond demo. |
| D03 | Too many slides | OK | Ten-slide maximum in 13 | Export at most ten; cut, do not split into more. |
| D04 | Font too small | RISK | No rendered deck | Inspect on phone; use large readable text, no tiny footnotes. |
| D05 | Hard-to-read font | RISK | No rendered deck | Select one simple readable typeface; verify phone view. |
| D06 | Low contrast | RISK | No rendered deck | Test foreground/background contrast on mobile and projector. |
| D07 | Complex screenshots | RISK | Proposed demo has receipts and accounts, no footage | Crop to one labeled fill at a time; use actual demo video instead of dense UI screenshot. |
| D08 | No clear story | OK | 13 orders customer → substitute → cross → proof gate | Ask three outsiders to retell story; revise if not understood. |
| D09 | Slides require reading rather than scanning | RISK | No rendered deck | Five-second glance per slide: outsider states its one idea. |
| D10 | Buzzword-driven copy | OK | Draft slide copy uses concrete orders, escrow, test receipts | Review final slide/video text against canonical §5 disallowed language. |
| D11 | Words not simple enough | RISK | Technical terms “mint,” “escrow,” “residual” still present | Define each once in voiceover; test comprehension with an unfamiliar judge. |
| D12 | Unnecessary complexity or multiple revenue streams | OK | One proposed, untested fee model, no token/points; [canonical](../00-CANONICAL.md) §3.5 | Test 5 bps per user side, not a proven price: CROSS has two charged sides, RESIDUAL one; evaluate residual fee/rebate alternatives in [ADR-009](../product/16-ROADMAP-AND-DECISIONS.md). |
| D13 | No clearly defined user | OK | Proposed distributor customer is an integration decision-maker; eligible holders supply orders; no buyer commitment (E18) | Name exact first distributor cohort if validated; distinguish app from end users. |
| D14 | Vague or generic problem | RISK | Off-hours spread hypothesis has no measured incidence | Bring a paired executable quote and actual same-mint timing evidence; no invented baseline. |
| D15 | “Building for everyone” positioning | OK | One same-mint eligible segment | Reject generic stock-trading claim and prohibited jurisdictions. |
| D16 | “Everything app” positioning | OK | Auction plus separate optional residual; no other lanes | Do not expand deck to lending, issuance or derivatives. |
| D17 | No working demo or unclear product | RISK | No code/product built at date of record | Run a **SYNTHETIC** localnet/devnet auction with CROSS, residual, a permitted pre-clear refund and issuer-blocked/shortfall examples; if unavailable, admit it. |
| D18 | Problem too general | OK | Same-mint opposite flow within short windows | Retain exact mint/window and distributor job. |
| D19 | Problem too narrow / market too small | RISK | E13 is contrary evidence for off-hours depth; E17 U | Bottom-up count qualified distributor order overlap and net-fee opportunity; kill if insufficient. |
| D20 | Circular “lack of solution” problem | OK | Causal cost hypothesis is dealer spreads for two contra orders, not “no auction” | Validate actual cost versus quotes; do not claim only missing feature. |
| D21 | Vanity metrics | OK | No claimed signups, revenue, quote wins, activity or traction | Include only measured repeat overlap, executable net savings, trials, retained usage. |
| D22 | Cookie-cutter “Problem / Solution / Team” headings | OK | Specific action headings in 13 | Preserve concrete slide headers in export. |
| D23 | No clear competition understanding | RISK | Named substitutes in 13, but no side-by-side quote measurements | Document route-specific limits and real executable comparisons. See [10](../business/10-MARKET-AND-COMPETITION.md). |
| D24 | Competitor matrix | OK | No matrix in proposed deck | Explain competing jobs in one sentence; don't introduce quadrant tables. |
| D25 | Matrix depicting all competitors as bad and Kerb as good | OK | No matrix; JupiterZ, AMMs and xChange credited explicitly | Keep honest limitations and CoW/Archer batch prior art in speaker notes. |

## Kerb-specific rejection paths

| Rejection path | Status / evidence | Required disposition |
|---|---|---|
| No users, counterparties or committed distributor/maker | **RISK**: E17–E18 U; explicitly none committed | Run [preregistered validation](../business/12-GTM-AND-VALIDATION.md); do not substitute hackathon votes for order flow. |
| Batch crossing is established prior art | **RISK**: Archer's dual-flow auctions (E7); CoW's [same-asset coincidence of wants](https://docs.cow.fi/cow-protocol/concepts/how-it-works/coincidence-of-wants) (retrieved 2026-09-28) | Present exact-mint Token-2022 issuer guards and deterministic on-program price as a narrow design, not novelty proven commercially. Document comparative limits. |
| Cheaper execution not demonstrated | **RISK**: canonical §2 calls cost a hypothesis | Three paired executable quote windows with *both sides* better net of fees, network and wait; else remove savings language. |
| Securities venue and distribution controls | **RISK**: xStocks are bearer debt securities restricted by jurisdiction (E4); venue classification unresolved | Counsel opinion and issuer/market-by-market qualification before any live venue; synthetic demo only. See [09](../legal/09-REGULATORY-AND-LEGAL.md). |
| Issuer freeze and vault shortfall | **RISK**: §3.6–3.7; V1 refuses any mint with a permanent delegate; candidate xStock compatibility U | Per-epoch PDA vaults isolate exposure. Pre-clear shortfall leaves nominal claims equal to original deposits; post-clear leaves entitlements unchanged. An `Impaired` leg stops payouts and may never recover: V1 has no recovery path. Frozen vault or paused mint can strand funds indefinitely despite permissionless calls. The other leg may continue; disclose all this before pitching availability. |
| Production asset eligibility | **RISK**: canonical §3.7 explicitly BLOCKS production; no exact mainnet xStock/issuer mint checked against allowlist | Qualify one exact mint, including permanent-delegate absence and all extension/authority and jurisdiction rules, before claiming live support. Named xStocks are not deemed eligible; demos remain SYNTHETIC. |
| Compute/atomicity could break proposed economics | **RISK**: 64 orders/epoch and 8 levels/side × 4 makers are provisional, unbenchmarked scale targets; hackathon MVP ≤8 orders, 1 maker, 1 level/side | Benchmark LiteSVM/SBF compute units and transaction size; verify marginal-plateau midpoint, deterministic rationing and backing. Settle/refund one recipient leg per instruction across many transactions. See [08](../security/08-TEST-AND-VERIFICATION-PLAN.md). |
| Founder fit and ownership | **UNKNOWN**: no names or contributions provided | Name verifiable founders, work history, full-time intent and code authorship; never create résumé facts in slides. |

## Owner inputs missing before submission

- **U — team:** named founders, roles, full-time intent, individual code ownership and attributable shipped work. Complete T01–T25 honestly; do not infer biography, employment or equity from a draft.
- **U — identity:** Kerb trademark, domain, X-handle and Colosseum project-name availability are **NOT CHECKED** (canonical §1). Owner must check each before public naming or submission.
- **U — eligibility:** ask Colosseum whether one entry may compete in multiple tracks (E16); Solana is the primary track, no second-track permission assumed.
- **U — validation:** report actual dated outcomes for all five [business/12 gates](../business/12-GTM-AND-VALIDATION.md#preregistered-gates-and-stop-rules-for-the-2026-10-12-decision): ≥10 substantive discovery conversations, ≥3 independent repeated-flow windows, ≥2 specific trial tickets, 1 written non-binding maker indication and ≥3 paired executable-quote windows improving **both** sides net. Include denominators, failures and independent stop conditions; none is a reported result today.
- **U — legal:** obtain qualified counsel's review of [legal/09's questions](../legal/09-REGULATORY-AND-LEGAL.md) and issuer/jurisdiction-specific approval path before real-asset activity; the question list itself is not an opinion or clearance.

## Additional commercial rejection path

**Residual routing economics — RISK.** Fee plus distributor rebate on the residual user side may make routing worse than trading the same maker directly. Compare actual executable net alternatives for that side before claiming an edge; alternatives in [ADR-009](../product/16-ROADMAP-AND-DECISIONS.md) remain undecided. Do not apply ≈10 bps CROSS revenue to RESIDUAL, which has one charged side (≈5 bps) and a zero-fee maker.

## VC roleplay: 0–10 per category, evidence-based, not an official score

Scoring anchors: 0 = no attributable artifact; 5 = credible working evidence with key gaps; 10 = reproducible execution plus repeat demand/qualified route. A zero for undisclosed team facts is **missing evidence, not a negative judgment about people**. No aggregate score is meaningful while team and market evidence are missing.

| Category | Current evidence score | Why it is not higher | Evidence that raises it |
|---|---:|---|---|
| Team | **0/10** | Roster, commitments, domain fit and authorship U | Named builders, directly attributable shipped work, stated post-hackathon commitment, direct distributor/maker interviews. |
| Product | **1/10** | Canonical mechanism is precise but not implemented or demand-tested | End-to-end user path, issuer-shortfall `Impaired` receipt and refund/blocked states, executable alternative comparison. |
| Traction | **0/10** | No users, revenue, repeated flow, maker or distributor commitment | Preregistered independent overlapping orders, two trial tickets, written maker indication and repeats; do not count synthetic fills. |
| Presentation | **2/10** | Story and ≤20-word draft exist; no deck, Loom or comprehension test | Under-three-minute real synthetic demo video, phone-legible deck, verified team intro, blind retell. |
| Code | **0/10** | Nothing built; no source or tests | Public, reproducible program/client; run CROSS→RESIDUAL→settle, pre-clear guard/refund, post-clear blocked leg, permanent-delegate mint refusal and shortfall impairment cases. |

## Colosseum thesis and fine details

Official Colosseum [guide](https://blog.colosseum.com/how-to-win-a-colosseum-hackathon/) (retrieved 2026-09-28) frames its hackathon as an engineering and business sprint oriented to founders intending to build full-time, prioritizes a working devnet demo, early user feedback and open-building. Whether Kerb founders intend full-time is **UNKNOWN**. The official contest [rules](https://colosseum.com/legal/Crypto%20World's%20Fair%20Hackathon%20Rules.pdf) score functionality, impact, novelty, UX, open source and business plan; E15 is P. [INFERENCE] If implemented, a composable Solana route for exact-mint two-sided flow could add value to eligible distributor apps. There is **no** issuer/Colosseum portfolio partnership or proven portfolio uplift. Archer (E7) is prior art and possible comparison, not a design partner. Solana track remains primary; multi-track entry is U (E16).

Fine-detail checklist from the X author's §5, with unperformed items left unchecked; public activity is *not* market proof:

- [ ] Identify publicly announced judges on X, read their work and engage substantively; do not imply private judge access or preferential treatment. Ask for product/pitch feedback only through allowed channels, without requesting favorable judging.
- [ ] Request help from an appropriate Superteam or builder community (including Superteam Balkan if relevant), and record what guidance was actually received. There is no support/endorsement today.
- [ ] Build in public with honest synthetic-only scope, user-facing learnings and uncertainty, not progress theatre. Seek feedback from actual eligible distributors and potential makers without claims of commitment.
- [ ] Publish a concise launch/teaser video only after a real synthetic run is reproducible. Clearly label test mint/test quote; no real liquidity inference.
- [ ] Show ecosystem knowledge and measurable repeat-use potential, not an ungrounded total-addressable-market number or forced portfolio name-drop. Cite competing execution routes fairly.
- [ ] Verify founder ownership, licensing, public repo, usable Loom and submission metadata before deadline; [15 checklist](../product/15-HACKATHON-PLAN.md) is the source for actual execution planning.
