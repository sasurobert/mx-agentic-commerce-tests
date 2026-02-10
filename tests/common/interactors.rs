use super::{REPUTATION_WASM_PATH, VALIDATION_WASM_PATH};
use multiversx_sc::derive_imports::*;
use multiversx_sc::types::{Address, CodeMetadata, ManagedBuffer};
use multiversx_sc_snippets::imports::*;

pub struct ValidationRegistryInteractor<'a> {
    pub interactor: &'a mut Interactor,
    pub wallet_address: Address,
    pub contract_address: Address,
}

impl<'a> ValidationRegistryInteractor<'a> {
    pub async fn init(
        interactor: &'a mut Interactor,
        wallet_address: Address,
        identity_address: &Address,
    ) -> Self {
        let wasm_bytes =
            std::fs::read(VALIDATION_WASM_PATH).expect("Failed to read validation WASM");
        let code_buf = ManagedBuffer::new_from_bytes(&wasm_bytes);

        // Prepare init arguments: identity_registry_address
        let identity_addr_buf: ManagedBuffer<StaticApi> =
            ManagedBuffer::new_from_bytes(identity_address.as_bytes());

        let contract_address = interactor
            .tx()
            .from(&wallet_address)
            .gas(600_000_000)
            .raw_deploy()
            .code(code_buf)
            .code_metadata(
                CodeMetadata::UPGRADEABLE | CodeMetadata::PAYABLE | CodeMetadata::PAYABLE_BY_SC,
            )
            .argument(&identity_addr_buf)
            .returns(ReturnsNewAddress)
            .run()
            .await;

        println!("Deployed Validation Registry at: {}", contract_address);

        Self {
            interactor,
            wallet_address,
            contract_address,
        }
    }

    pub fn address(&self) -> &Address {
        &self.contract_address
    }
}

pub struct ReputationRegistryInteractor<'a> {
    pub interactor: &'a mut Interactor,
    pub wallet_address: Address,
    pub contract_address: Address,
}

impl<'a> ReputationRegistryInteractor<'a> {
    pub async fn init(
        interactor: &'a mut Interactor,
        wallet_address: Address,
        validation_address: &Address,
        identity_address: &Address,
    ) -> Self {
        let wasm_bytes =
            std::fs::read(REPUTATION_WASM_PATH).expect("Failed to read reputation WASM");
        let code_buf = ManagedBuffer::new_from_bytes(&wasm_bytes);

        let val_addr_buf: ManagedBuffer<StaticApi> =
            ManagedBuffer::new_from_bytes(validation_address.as_bytes());
        let id_addr_buf: ManagedBuffer<StaticApi> =
            ManagedBuffer::new_from_bytes(identity_address.as_bytes());

        let contract_address = interactor
            .tx()
            .from(&wallet_address)
            .gas(600_000_000)
            .raw_deploy()
            .code(code_buf)
            .code_metadata(
                CodeMetadata::UPGRADEABLE | CodeMetadata::PAYABLE | CodeMetadata::PAYABLE_BY_SC,
            )
            .argument(&val_addr_buf)
            .argument(&id_addr_buf)
            .returns(ReturnsNewAddress)
            .run()
            .await;

        println!("Deployed Reputation Registry at: {}", contract_address);

        Self {
            interactor,
            wallet_address,
            contract_address,
        }
    }

    pub fn address(&self) -> &Address {
        &self.contract_address
    }
}
