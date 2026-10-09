pub mod flow;
pub mod wire;
use litesvm::{types::TransactionMetadata, LiteSVM};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use spl_token_interface::state::{Account as TokenAccount, Mint};

pub const PROGRAM: Address = Address::new_from_array([0x4b; 32]);
pub const LOCAL_GENESIS: [u8; 32] = [0x47; 32];
pub const DEPLOYMENT: [u8; 32] = [0x44; 32];
pub const PAIR_ID: [u8; 32] = [0x50; 32];
pub const DECIMALS: u8 = 6;
pub const PAIR_LEN: usize = 503;

pub fn old(key: &Address) -> Pubkey {
    Pubkey::new_from_array(key.to_bytes())
}

pub fn token_program() -> Address {
    Address::new_from_array(spl_token_interface::ID.to_bytes())
}

pub fn system_program() -> Address {
    Address::new_from_array([0; 32])
}

/// Exact shared Domain325 fixture bytes; deliberately not built by product codecs.
pub fn domain_bytes(mint: Address, epoch: u64) -> Vec<u8> {
    let mut out = b"KERBDM01".to_vec();
    out.extend_from_slice(&1u16.to_le_bytes());
    for id in [
        DEPLOYMENT,
        LOCAL_GENESIS,
        PROGRAM.to_bytes(),
        mint.to_bytes(),
        token_program().to_bytes(),
    ] {
        out.extend_from_slice(&id);
    }
    out.extend_from_slice(&[2, 4]);
    out.extend_from_slice(&0x37a5_165bu32.to_le_bytes());
    out.extend_from_slice(&6u32.to_le_bytes());
    for id in [[0x5a; 32], [0x52; 32], PAIR_ID] {
        out.extend_from_slice(&id);
    }
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&[0x55; 32]);
    out.extend_from_slice(&1u64.to_le_bytes());
    out.push(1);
    assert_eq!(out.len(), 325);
    out
}

#[derive(Clone, Copy)]
pub struct BaseAmounts {
    pub maximum: u64,
    pub filled: u64,
    pub unused: u64,
}
impl BaseAmounts {
    pub const UNIT_FIXTURE: Self = Self {
        maximum: 34,
        filled: 25,
        unused: 9,
    };
    pub const DRIVER_FIXTURE: Self = Self {
        maximum: 7,
        filled: 5,
        unused: 2,
    };
}
#[derive(Debug)]
pub struct TransactionFailure {
    pub err: TransactionError,
    pub logs: Vec<String>,
}
pub struct Fixture {
    pub svm: LiteSVM,
    pub admin: Keypair,
    pub seller: Keypair,
    pub buyer: Keypair,
    pub authorizers: [Keypair; 3],
    pub mint: Address,
    pub seller_token: Address,
    pub buyer_token: Address,
    pub pair: Address,
    pub amounts: BaseAmounts,
    pub roster: [[u8; 32]; 3],
    pub policy_signing_enabled: bool,
    pub last_packet_bytes: usize,
    pub max_packet_bytes: usize,
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_authorizers(
            std::array::from_fn(|_| Keypair::new()),
            BaseAmounts::UNIT_FIXTURE,
        )
    }

    pub fn with_authorizers(authorizers: [Keypair; 3], amounts: BaseAmounts) -> Self {
        assert!(
            amounts.filled > 0
                && amounts.unused > 0
                && amounts.filled.checked_add(amounts.unused) == Some(amounts.maximum),
            "explicit local base partition must conserve maximum"
        );
        let elf = std::env::var_os("Z2Z_SBF_ELF").expect(
            "Z2Z_SBF_ELF must name target/z2z-sbf/ziquid_solana.so; no native processor fallback",
        );
        let mut svm = LiteSVM::new();
        svm.add_program_from_file(PROGRAM, elf)
            .expect("load exact compiled Z2Z ELF");
        let admin = Keypair::new();
        let seller = Keypair::new();
        let buyer = Keypair::new();
        svm.airdrop(&admin.pubkey(), 10_000_000_000).unwrap();
        svm.airdrop(&seller.pubkey(), 1_000_000_000).unwrap();
        let mint_key = Keypair::new();
        let seller_token_key = Keypair::new();
        let buyer_token_key = Keypair::new();
        let mint = mint_key.pubkey();
        let seller_token = seller_token_key.pubkey();
        let buyer_token = buyer_token_key.pubkey();
        let create = |key: Address, len: usize| {
            solana_system_interface::instruction::create_account(
                &old(&admin.pubkey()),
                &old(&key),
                svm.minimum_balance_for_rent_exemption(len),
                len as u64,
                &spl_token_interface::ID,
            )
        };
        let instructions = [
            create(mint, Mint::LEN),
            spl_token_interface::instruction::initialize_mint2(
                &spl_token_interface::ID,
                &old(&mint),
                &old(&admin.pubkey()),
                Some(&old(&admin.pubkey())),
                DECIMALS,
            )
            .unwrap(),
            create(seller_token, TokenAccount::LEN),
            spl_token_interface::instruction::initialize_account3(
                &spl_token_interface::ID,
                &old(&seller_token),
                &old(&mint),
                &old(&seller.pubkey()),
            )
            .unwrap(),
            create(buyer_token, TokenAccount::LEN),
            spl_token_interface::instruction::initialize_account3(
                &spl_token_interface::ID,
                &old(&buyer_token),
                &old(&mint),
                &old(&buyer.pubkey()),
            )
            .unwrap(),
            spl_token_interface::instruction::mint_to_checked(
                &spl_token_interface::ID,
                &old(&mint),
                &old(&seller_token),
                &old(&admin.pubkey()),
                &[],
                100,
                DECIMALS,
            )
            .unwrap(),
        ];
        let tx = Transaction::new_signed_with_payer(
            &instructions,
            Some(&admin.pubkey()),
            &[&admin, &mint_key, &seller_token_key, &buyer_token_key],
            svm.latest_blockhash(),
        );
        svm.send_transaction(tx)
            .expect("real legacy SPL mint/account initialization and mint_to_checked");
        let context = ziquid_protocol::market::Domain::decode(&domain_bytes(mint, 0))
            .expect("exact local canonical domain");
        let pair = Address::new_from_array(ziquid_solana_interface::pair_address(
            &context,
            &admin.pubkey().to_bytes(),
        ));
        let roster = authorizers.each_ref().map(|key| key.pubkey().to_bytes());
        Self {
            svm,
            admin,
            seller,
            buyer,
            authorizers,
            mint,
            seller_token,
            buyer_token,
            pair,
            amounts,
            roster,
            policy_signing_enabled: true,
            last_packet_bytes: 0,
            max_packet_bytes: 0,
        }
    }

    /// Bootstrap private fixture keys have no funded execution fallback.
    pub fn require_external_policy_signatures(&mut self) {
        self.policy_signing_enabled = false;
        let bootstrap = std::mem::replace(
            &mut self.authorizers,
            std::array::from_fn(|_| Keypair::new()),
        );
        drop(bootstrap);
    }

    pub fn initialize_instruction(&self) -> Instruction {
        let mut data = vec![1];
        data.extend_from_slice(&domain_bytes(self.mint, 0));
        data.extend_from_slice(self.admin.pubkey().as_ref());
        for authorizer in &self.authorizers {
            data.extend_from_slice(authorizer.pubkey().as_ref());
        }
        data.push(DECIMALS);
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.pair, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new_readonly(token_program(), false),
                AccountMeta::new_readonly(system_program(), false),
            ],
            data,
        }
    }

    pub fn send(
        &mut self,
        instructions: &[Instruction],
        seller_signs: bool,
    ) -> Result<TransactionMetadata, TransactionFailure> {
        self.svm.expire_blockhash();
        let mut budgeted = Vec::with_capacity(instructions.len() + 1);
        let mut budget = vec![2];
        budget.extend_from_slice(&1_400_000u32.to_le_bytes());
        budgeted.push(Instruction {
            program_id: Address::from_str_const("ComputeBudget111111111111111111111111111111"),
            accounts: vec![],
            data: budget,
        });
        budgeted.extend_from_slice(instructions);
        let signers = if seller_signs {
            vec![&self.admin, &self.seller]
        } else {
            vec![&self.admin]
        };
        let tx = Transaction::new_signed_with_payer(
            &budgeted,
            Some(&self.admin.pubkey()),
            &signers,
            self.svm.latest_blockhash(),
        );
        let size = bincode::serialize(&tx).unwrap().len();
        assert!(
            size <= 1232,
            "local fixture transaction must fit actual Solana packet, got {size}"
        );
        self.last_packet_bytes = size;
        self.max_packet_bytes = self.max_packet_bytes.max(size);
        let result = self.svm.send_transaction(tx);
        if let Ok(meta) = &result {
            eprintln!(
                "LocalFixture packet_bytes={size} compute_units={} fee={}",
                meta.compute_units_consumed, meta.fee
            );
        }
        result.map_err(|failure| TransactionFailure {
            err: failure.err,
            logs: failure.meta.logs,
        })
    }

    pub fn amount(&self, key: Address) -> u64 {
        TokenAccount::unpack(&self.svm.get_account(&key).unwrap().data)
            .unwrap()
            .amount
    }
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}
