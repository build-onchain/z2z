# Source: Superteam Vietnam Idea Bank, row #5

Retrieved 2026-09-28 via Notion's unauthenticated public `queryCollection` endpoint.
Collection "Superteam Idea Bank" (view `ec2c5ae0-b573-82c6-a2ee-08c1fe40f60e`), 18 rows,
`hasMore: false`. Row pages have no body content; all content is in row properties, copied
verbatim below. Public page:
https://silent-neptune-5fe.notion.site/717c5ae0b57382798a0401597742b43f

Provenance: public page URL above; collection view id `ec2c5ae0-b573-82c6-a2ee-08c1fe40f60e`;
row = property `Ref = 5`. The row's own block id was **not recorded** at capture; re-capture it
before external citation. Retrieval date 2026-09-28. This is a local copy of an
unauthenticated API response, not proof that the page is unchanged since.
Every claim in this row is the author's hypothesis. The row is labelled "T2 – Verify first".

| Property | Value |
|---|---|
| Ref | 5 |
| Idea | Dark Pool (spot tokenized stocks) |
| Tier | T2 - Verify first |
| Category | Privacy x RWA |
| Summary | Dark pool for spot tokenized stocks, no Arcium required. Three viable architectures: RFQ or sealed-bid batch auction with commit-reveal running purely on Solana; a matcher running inside a self-operated TEE that settles onchain; or a MagicBlock ephemeral rollup. |
| Where to start | Start with the RFQ model (simplest; Jupiter RFQ is the precedent): quotes are private by nature, no new cryptography needed. Upgrade to batch auction later. Idea 43 is a cheaper way to learn TEE attestation first. |
| What unblocks it | Grant / Jito plugin batch |
| What to watch | A TEE requires trusting the operator. Institutional clients generally accept this because traditional dark pools work the same way, but it must be stated clearly in the pitch. |
| Region & fit | The most viable architecture is to build it as a BAM plugin: BAM already runs in a TEE, has attestation ordering, and comes with a revenue model that shares fees with validators. Target customers are desks in SG, HK and Brazil, sold remotely as B2B. |

## How Kerb departs from this row

**Historical interpretation (2026-09-28), not current overall Kerb architecture.** The verbatim source table above is retained unchanged. [Current documentation authority](../../00-CANONICAL.md#0-current-documentation-authority) adopts shared Zoss libraries as docs direction only; the Oct1 financial/private candidate remains unapproved with GD2 structural FAIL. The public-Solana V1 comparisons below are dated context, not a financial cutover or runtime/privacy result.

- No privacy, dark-pool, TEE, BAM or MagicBlock claim in V1. BAM's Maker Priority Plugin is
  sequencing for enrolled maker price updates, not confidentiality (see `00-CANONICAL.md` E6).
- Plain RFQ is already served by JupiterZ (E1); Kerb is a same-mint periodic call auction
  instead.
- The row's customer claim (SG/HK/Brazil desks) is unverified and is carried into Kerb only
  as a validation target.
