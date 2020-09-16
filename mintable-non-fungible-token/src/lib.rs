// Based on: https://github.com/near-examples/NFT/blob/4c55057523b2c5370fa3f23101e89927c35e0c18/contracts/rust/src/lib.rs

#![deny(warnings)]

use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{UnorderedMap, UnorderedSet};
use near_sdk::{env, near_bindgen, AccountId, ext_contract};
use near_sdk::json_types::U128;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Data that was emitted by the Ethereum event.
pub struct EthEventData {
    pub locker_address: [u8; 20],
    pub token: String,
    pub sender: String,
    pub token_id: u128,
    pub recipient: AccountId,
}

impl EthEventData {
    /// Parse raw log entry data.
    pub fn from_log_entry_data(data: &[u8]) -> Self {
        use eth_types::*;
        use ethabi::{Event, EventParam, Hash, ParamType, RawLog};
        use hex::ToHex;

        let event = Event {
            name: "Locked".to_string(),
            inputs: vec![
                EventParam {
                    name: "token".to_string(),
                    kind: ParamType::Address,
                    indexed: true,
                },
                EventParam {
                    name: "sender".to_string(),
                    kind: ParamType::Address,
                    indexed: true,
                },
                EventParam {
                    name: "amount".to_string(),
                    kind: ParamType::Uint(256),
                    indexed: false,
                },
                EventParam {
                    name: "accountId".to_string(),
                    kind: ParamType::String,
                    indexed: false,
                },
            ],
            anonymous: false,
        };

        let log_entry: LogEntry = rlp::decode(data).unwrap();
        let locker_address = (log_entry.address.clone().0).0;
        let raw_log = RawLog {
            topics: log_entry
                .topics
                .iter()
                .map(|h| Hash::from(&((h.0).0)))
                .collect(),
            data: log_entry.data.clone(),
        };
        let log = event.parse_log(raw_log).unwrap();
        let token = log.params[0].value.clone().to_address().unwrap().0;
        let token = (&token).encode_hex::<String>();
        let sender = log.params[1].value.clone().to_address().unwrap().0;
        let sender = (&sender).encode_hex::<String>();
        let token_id = log.params[2].value.clone().to_uint().unwrap().as_u128();
        let recipient = log.params[3].value.clone().to_string().unwrap();
        Self {
            locker_address,
            token,
            sender,
            token_id,
            recipient,
        }
    }
}

impl std::fmt::Display for EthEventData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "token: {}; sender: {}; token_id: {}; recipient: {}",
            self.token, self.sender, self.token_id, self.recipient
        )
    }
}

#[ext_contract(prover)]
pub trait Prover {
    #[result_serializer(borsh)]
    fn verify_log_entry(
        &self,
        #[serializer(borsh)] log_index: u64,
        #[serializer(borsh)] log_entry_data: Vec<u8>,
        #[serializer(borsh)] receipt_index: u64,
        #[serializer(borsh)] receipt_data: Vec<u8>,
        #[serializer(borsh)] header_data: Vec<u8>,
        #[serializer(borsh)] proof: Vec<Vec<u8>>,
        #[serializer(borsh)] skip_bridge_call: bool,
    ) -> bool;
}

#[cfg(not(test))]
#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct Proof {
    log_index: u64,
    log_entry_data: Vec<u8>,
    receipt_index: u64,
    receipt_data: Vec<u8>,
    header_data: Vec<u8>,
    proof: Vec<Vec<u8>>,
}

#[ext_contract(ext_fungible_token)]
pub trait ExtFungibleToken {
    #[result_serializer(borsh)]
    fn finish_mint(
        &self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] new_owner_id: AccountId,
        #[serializer(borsh)] amount: U128,
    ) -> Promise;
}

/// This trait provides the baseline of functions as described at:
/// https://github.com/nearprotocol/NEPs/blob/nep-4/specs/Standards/Tokens/NonFungibleToken.md
pub trait NEP4 {
    // Grant the access to the given `accountId` for the given `tokenId`.
    // Requirements:
    // * The caller of the function (`predecessor_id`) should have access to the token.
    fn grant_access(&mut self, escrow_account_id: AccountId);

    // Revoke the access to the given `accountId` for the given `tokenId`.
    // Requirements:
    // * The caller of the function (`predecessor_id`) should have access to the token.
    fn revoke_access(&mut self, escrow_account_id: AccountId);

    // Transfer the given `tokenId` to the given `accountId`. Account `accountId` becomes the new owner.
    // Requirements:
    // * The caller of the function (`predecessor_id`) should have access to the token.
    fn transfer_from(&mut self, owner_id: AccountId, new_owner_id: AccountId, token_id: TokenId); 

    // Transfer the given `tokenId` to the given `accountId`. Account `accountId` becomes the new owner.
    // Requirements:
    // * The caller of the function (`predecessor_id`) should be the owner of the token. Callers who have
    // escrow access should use transfer_from.
    fn transfer(&mut self, new_owner_id: AccountId, token_id: TokenId); 

    // Returns `true` or `false` based on caller of the function (`predecessor_id) having access to the token
    fn check_access(&self, account_id: AccountId) -> bool;

    // Get an individual owner by given `tokenId`.
    fn get_token_owner(&self, token_id: TokenId) -> String;
}

/// The token ID type is also defined in the NEP
pub type TokenId = u64;
pub type AccountIdHash = Vec<u8>;

// Begin implementation
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct MintableNonFungibleToken {
    pub token_to_account: UnorderedMap<TokenId, AccountId>,
    pub account_gives_access: UnorderedMap<AccountIdHash, UnorderedSet<AccountIdHash>>, // Vec<u8> is sha256 of account, makes it safer and is how fungible token also works

    /// The account of the prover that we can use to prove
    pub prover_account: AccountId,
    /// Address of the Ethereum locker contract.
    pub locker_address: [u8; 20],
    /// Hashes of the events that were already used.
    pub used_events: UnorderedSet<Vec<u8>>,
}

impl Default for MintableNonFungibleToken {
    fn default() -> Self {
        panic!("NFT should be initialized before usage")
    }
}

#[near_bindgen]
impl MintableNonFungibleToken {
    /// `prover_account`: NEAR account of the Near Prover contract;
    /// `locker_address`: Ethereum address of the locker contract, in hex.
    #[init]
    pub fn new(prover_account: AccountId, locker_address: String) -> Self {
        let data =
        hex::decode(locker_address).expect("`locker_address` should be a valid hex string.");
        assert_eq!(data.len(), 20, "`locker_address` should be 20 bytes long");
        let mut locker_address = [0u8; 20];
        locker_address.copy_from_slice(&data);

        assert!(!env::state_exists(), "Already initialized");
        Self {
            token_to_account: UnorderedMap::new(b"token-belongs-to".to_vec()),
            account_gives_access: UnorderedMap::new(b"gives-access".to_vec()),
            prover_account,
            locker_address,
            used_events: UnorderedSet::new(b"u".to_vec()),
        }
    }
}

#[near_bindgen]
impl NEP4 for MintableNonFungibleToken {
    fn grant_access(&mut self, escrow_account_id: AccountId) {
        let escrow_hash = env::sha256(escrow_account_id.as_bytes());
        let predecessor = env::predecessor_account_id();
        let predecessor_hash = env::sha256(predecessor.as_bytes());

        let mut access_set = match self.account_gives_access.get(&predecessor_hash) {
            Some(existing_set) => {
                existing_set
            },
            None => {
                UnorderedSet::new(b"new-access-set".to_vec())
            }
        };
        access_set.insert(&escrow_hash);
        self.account_gives_access.insert(&predecessor_hash, &access_set);
    }

    fn revoke_access(&mut self, escrow_account_id: AccountId) {
        let predecessor = env::predecessor_account_id();
        let predecessor_hash = env::sha256(predecessor.as_bytes());
        let mut existing_set = match self.account_gives_access.get(&predecessor_hash) {
            Some(existing_set) => existing_set,
            None => env::panic(b"Access does not exist.")
        };
        let escrow_hash = env::sha256(escrow_account_id.as_bytes());
        if existing_set.contains(&escrow_hash) {
            existing_set.remove(&escrow_hash);
            self.account_gives_access.insert(&predecessor_hash, &existing_set);
            env::log(b"Successfully removed access.")
        } else {
            env::panic(b"Did not find access for escrow ID.")
        }
    }

    fn transfer(&mut self, new_owner_id: AccountId, token_id: TokenId) {
        let token_owner_account_id = self.get_token_owner(token_id);
        let predecessor = env::predecessor_account_id();
        if predecessor != token_owner_account_id {
            env::panic(b"Attempt to call transfer on tokens belonging to another account.")
        }
        self.token_to_account.insert(&token_id, &new_owner_id);
    }

    fn transfer_from(&mut self, owner_id: AccountId, new_owner_id: AccountId, token_id: TokenId) {
        let token_owner_account_id = self.get_token_owner(token_id);
        if owner_id != token_owner_account_id {
            env::panic(b"Attempt to transfer a token from a different owner.")
        }

        if !self.check_access(token_owner_account_id) {
            env::panic(b"Attempt to transfer a token with no access.")
        }
        self.token_to_account.insert(&token_id, &new_owner_id);
    }

    fn check_access(&self, account_id: AccountId) -> bool {
        let account_hash = env::sha256(account_id.as_bytes());
        let predecessor = env::predecessor_account_id();
        if predecessor == account_id {
            return true;
        }
        match self.account_gives_access.get(&account_hash) {
            Some(access) => {
                let predecessor = env::predecessor_account_id();
                let predecessor_hash = env::sha256(predecessor.as_bytes());
                access.contains(&predecessor_hash)
            },
            None => false
        }
    }

    fn get_token_owner(&self, token_id: TokenId) -> String {
        match self.token_to_account.get(&token_id) {
            Some(owner_id) => owner_id,
            None => env::panic(b"No owner of the token ID specified")
        }
    }
}

/// Methods not in the strict scope of the NFT spec (NEP4)
#[near_bindgen]
impl MintableNonFungibleToken {
    /// Creates a token for owner_id, doesn't use autoincrement, fails if id is taken
    pub fn mint(&mut self, owner_id: String, token_id: TokenId) {

        // Since Map doesn't have `contains` we use match
        let token_check = self.token_to_account.get(&token_id);
        if token_check.is_some() {
            env::panic(b"Token ID already exists.")
        }
        // No token with that ID exists, mint and add token to data structures
        self.token_to_account.insert(&token_id, &owner_id);
    }
}

// use the attribute below for unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::MockedBlockchain;
    use near_sdk::{testing_env, VMContext};

    fn joe() -> AccountId {
        "joe.testnet".to_string()
    }
    fn robert() -> AccountId {
        "robert.testnet".to_string()
    }
    fn mike() -> AccountId {
        "mike.testnet".to_string()
    }

    // part of writing unit tests is setting up a mock context
    // this is a useful list to peek at when wondering what's available in env::*
    fn get_context(predecessor_account_id: String, storage_usage: u64) -> VMContext {
        VMContext {
            current_account_id: "alice.testnet".to_string(),
            signer_account_id: "jane.testnet".to_string(),
            signer_account_pk: vec![0, 1, 2],
            predecessor_account_id,
            input: vec![],
            block_index: 0,
            block_timestamp: 0,
            account_balance: 0,
            account_locked_balance: 0,
            storage_usage,
            attached_deposit: 0,
            prepaid_gas: 10u64.pow(18),
            random_seed: vec![0, 1, 2],
            is_view: false,
            output_data_receivers: vec![],
            epoch_height: 19,
        }
    }

    #[test]
    fn grant_access() {
        let context = get_context(robert(), 0);
        testing_env!(context);
        let mut contract = MintableNonFungibleToken::new(robert());
        let length_before = contract.account_gives_access.len();
        assert_eq!(0, length_before, "Expected empty account access Map.");
        contract.grant_access(mike());
        contract.grant_access(joe());
        let length_after = contract.account_gives_access.len();
        assert_eq!(1, length_after, "Expected an entry in the account's access Map.");
        let predecessor_hash = env::sha256(robert().as_bytes());
        let num_grantees = contract.account_gives_access.get(&predecessor_hash).unwrap();
        assert_eq!(2, num_grantees.len(), "Expected two accounts to have access to predecessor.");
    }

    #[test]
    #[should_panic(
        expected = r#"Access does not exist."#
    )]
    fn revoke_access_and_panic() {
        let context = get_context(robert(), 0);
        testing_env!(context);
        let mut contract = MintableNonFungibleToken::new(robert());
        contract.revoke_access(joe());
    }

    #[test]
    fn add_revoke_access_and_check() {
        // Joe grants access to Robert
        let mut context = get_context(joe(), 0);
        testing_env!(context);
        let mut contract = MintableNonFungibleToken::new(joe());
        contract.grant_access(robert());

        // does Robert have access to Joe's account? Yes.
        context = get_context(robert(), env::storage_usage());
        testing_env!(context);
        let mut robert_has_access = contract.check_access(joe());
        assert_eq!(true, robert_has_access, "After granting access, check_access call failed.");

        // Joe revokes access from Robert
        context = get_context(joe(), env::storage_usage());
        testing_env!(context);
        contract.revoke_access(robert());

        // does Robert have access to Joe's account? No
        context = get_context(robert(), env::storage_usage());
        testing_env!(context);
        robert_has_access = contract.check_access(joe());
        assert_eq!(false, robert_has_access, "After revoking access, check_access call failed.");
    }

    #[test]
    fn mint_token_get_token_owner() {
        let context = get_context(robert(), 0);
        testing_env!(context);
        let mut contract = MintableNonFungibleToken::new(robert());
        contract.mint_token(mike(), 19u64);
        let owner = contract.get_token_owner(19u64);
        assert_eq!(mike(), owner, "Unexpected token owner.");
    }

    #[test]
    #[should_panic(
        expected = r#"Attempt to transfer a token with no access."#
    )]
    fn transfer_from_with_no_access_should_fail() {
        // Mike owns the token.
        // Robert is trying to transfer it to Robert's account without having access.
        let context = get_context(robert(), 0);
        testing_env!(context);
        let mut contract = MintableNonFungibleToken::new(robert());
        let token_id = 19u64;
        contract.mint_token(mike(), token_id);
        contract.transfer_from(mike(), robert(), token_id.clone());
    }

    #[test]
    fn transfer_from_with_escrow_access() {
        // Escrow account: robert.testnet
        // Owner account: mike.testnet
        // New owner account: joe.testnet
        let mut context = get_context(mike(), 0);
        testing_env!(context);
        let mut contract = MintableNonFungibleToken::new(mike());
        let token_id = 19u64;
        contract.mint_token(mike(), token_id);
        // Mike grants access to Robert
        contract.grant_access(robert());

        // Robert transfers the token to Joe
        context = get_context(robert(), env::storage_usage());
        testing_env!(context);
        contract.transfer_from(mike(), joe(), token_id.clone());

        // Check new owner
        let owner = contract.get_token_owner(token_id.clone());
        assert_eq!(joe(), owner, "Token was not transferred after transfer call with escrow.");
    }

    #[test]
    #[should_panic(
        expected = r#"Attempt to transfer a token from a different owner."#
    )]
    fn transfer_from_with_escrow_access_wrong_owner_id() {
        // Escrow account: robert.testnet
        // Owner account: mike.testnet
        // New owner account: joe.testnet
        let mut context = get_context(mike(), 0);
        testing_env!(context);
        let mut contract = MintableNonFungibleToken::new(mike());
        let token_id = 19u64;
        contract.mint_token(mike(), token_id);
        // Mike grants access to Robert
        contract.grant_access(robert());

        // Robert transfers the token to Joe
        context = get_context(robert(), env::storage_usage());
        testing_env!(context);
        contract.transfer_from(robert(), joe(), token_id.clone());
    }

    #[test]
    fn transfer_from_with_your_own_token() {
        // Owner account: robert.testnet
        // New owner account: joe.testnet

        testing_env!(get_context(robert(), 0));
        let mut contract = MintableNonFungibleToken::new(robert());
        let token_id = 19u64;
        contract.mint_token(robert(), token_id);

        // Robert transfers the token to Joe
        contract.transfer_from(robert(), joe(), token_id.clone());

        // Check new owner
        let owner = contract.get_token_owner(token_id.clone());
        assert_eq!(joe(), owner, "Token was not transferred after transfer call with escrow.");
    }

    #[test]
    #[should_panic(
        expected = r#"Attempt to call transfer on tokens belonging to another account."#
    )]
    fn transfer_with_escrow_access_fails() {
        // Escrow account: robert.testnet
        // Owner account: mike.testnet
        // New owner account: joe.testnet
        let mut context = get_context(mike(), 0);
        testing_env!(context);
        let mut contract = MintableNonFungibleToken::new(mike());
        let token_id = 19u64;
        contract.mint_token(mike(), token_id);
        // Mike grants access to Robert
        contract.grant_access(robert());

        // Robert transfers the token to Joe
        context = get_context(robert(), env::storage_usage());
        testing_env!(context);
        contract.transfer(joe(), token_id.clone());
    }

    #[test]
    fn transfer_with_your_own_token() {
        // Owner account: robert.testnet
        // New owner account: joe.testnet

        testing_env!(get_context(robert(), 0));
        let mut contract = MintableNonFungibleToken::new(robert());
        let token_id = 19u64;
        contract.mint_token(robert(), token_id);

        // Robert transfers the token to Joe
        contract.transfer(joe(), token_id.clone());

        // Check new owner
        let owner = contract.get_token_owner(token_id.clone());
        assert_eq!(joe(), owner, "Token was not transferred after transfer call with escrow.");
    }
}