#[derive(
    TopEncode, TopDecode, ManagedVecItem, NestedEncode, NestedDecode, Clone, PartialEq, Debug,
)]
pub struct JobData<M: ManagedTypeApi> {
    pub job_id: ManagedBuffer<M>,
    pub status: u8, // 0=New, 1=Pending, 2=Verified
    pub employer: ManagedAddress<M>,
    pub agent_nonce: u64,
    pub service_id: u32,
    pub payment_token: TokenIdentifier<M>,
    pub payment_amount: BigUint<M>,
    pub proof_hash: ManagedBuffer<M>,
    pub timestamp: u64,
}

pub struct ValidationRegistryInteractor<'a> {
    pub interactor: &'a mut Interactor,
    pub wallet_address: Address,
    pub contract_address: Address,
}

impl<'a> ValidationRegistryInteractor<'a> {
    pub async fn init(
        interactor: &'a mut Interactor,
        wallet_address: Address,
        identity_registry_address: &Address,
    ) -> Self {
        let wasm_bytes =
            std::fs::read(VALIDATION_WASM_PATH).expect("Failed to read validation WASM");
        let code_buf = ManagedBuffer::new_from_bytes(&wasm_bytes);

        interactor.generate_blocks_until_all_activations().await;

        let identity_addr_managed: ManagedAddress<StaticApi> =
            ManagedAddress::from_address(identity_registry_address);

        let contract_address = interactor
            .tx()
            .from(&wallet_address)
            .gas(600_000_000)
            .raw_deploy()
            .code(code_buf)
            .code_metadata(CodeMetadata::UPGRADEABLE | CodeMetadata::READABLE)
            .argument(&identity_addr_managed)
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

    pub async fn init_job(&mut self, job_id: &str, agent_nonce: u64) -> Result<(), String> {
        let job_id_buf: ManagedBuffer<StaticApi> = ManagedBuffer::new_from_bytes(job_id.as_bytes());

        let result = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(&self.contract_address)
            .gas(600_000_000)
            .raw_call("init_job")
            .argument(&job_id_buf)
            .argument(&agent_nonce)
            .returns(ReturnsResult)
            .run()
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    pub async fn init_job_with_payment(
        &mut self,
        job_id: &str,
        agent_nonce: u64,
        service_id: u32,
        payment_token: &str,
        payment_amount: u64,
    ) -> Result<(), String> {
        let job_id_buf: ManagedBuffer<StaticApi> = ManagedBuffer::new_from_bytes(job_id.as_bytes());
        let token_id: TokenIdentifier<StaticApi> = TokenIdentifier::from(payment_token);
        let amount_big: BigUint<StaticApi> = BigUint::from(payment_amount);

        let result = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(&self.contract_address)
            .gas(600_000_000)
            .single_esdt(&token_id, 0, &amount_big)
            .raw_call("init_job")
            .argument(&job_id_buf)
            .argument(&agent_nonce)
            .argument(&service_id)
            .returns(ReturnsResult)
            .run()
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    pub async fn submit_proof(&mut self, job_id: &str, proof_hash: &str) -> Result<(), String> {
        let job_id_buf: ManagedBuffer<StaticApi> = ManagedBuffer::new_from_bytes(job_id.as_bytes());
        let proof_buf: ManagedBuffer<StaticApi> =
            ManagedBuffer::new_from_bytes(proof_hash.as_bytes());

        let result = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(&self.contract_address)
            .gas(600_000_000)
            .raw_call("submit_proof")
            .argument(&job_id_buf)
            .argument(&proof_buf)
            .returns(ReturnsResult)
            .run()
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    pub async fn validation_request(
        &mut self,
        job_id: &str,
        validator_address: &Address,
        request_uri: &str,
        request_hash: &str,
    ) -> Result<(), String> {
        let job_id_buf: ManagedBuffer<StaticApi> = ManagedBuffer::new_from_bytes(job_id.as_bytes());
        let validator_managed: ManagedAddress<StaticApi> =
            ManagedAddress::from_address(validator_address);
        let uri_buf: ManagedBuffer<StaticApi> =
            ManagedBuffer::new_from_bytes(request_uri.as_bytes());
        let hash_buf: ManagedBuffer<StaticApi> =
            ManagedBuffer::new_from_bytes(request_hash.as_bytes());

        let result = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(&self.contract_address)
            .gas(600_000_000)
            .raw_call("validation_request")
            .argument(&job_id_buf)
            .argument(&validator_managed)
            .argument(&uri_buf)
            .argument(&hash_buf)
            .returns(ReturnsResult)
            .run()
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    pub async fn validation_response(
        &mut self,
        request_hash: &str,
        response: u8,
        response_uri: &str,
        response_hash: &str,
        tag: &str,
    ) -> Result<(), String> {
        let hash_buf: ManagedBuffer<StaticApi> =
            ManagedBuffer::new_from_bytes(request_hash.as_bytes());
        let uri_buf: ManagedBuffer<StaticApi> =
            ManagedBuffer::new_from_bytes(response_uri.as_bytes());
        let resp_hash_buf: ManagedBuffer<StaticApi> =
            ManagedBuffer::new_from_bytes(response_hash.as_bytes());
        let tag_buf: ManagedBuffer<StaticApi> = ManagedBuffer::new_from_bytes(tag.as_bytes());

        let result = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(&self.contract_address)
            .gas(600_000_000)
            .raw_call("validation_response")
            .argument(&hash_buf)
            .argument(&response)
            .argument(&uri_buf)
            .argument(&resp_hash_buf)
            .argument(&tag_buf)
            .returns(ReturnsResult)
            .run()
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    pub async fn get_job_data(&mut self, job_id: &str) -> Option<JobData<StaticApi>> {
        let job_id_buf: ManagedBuffer<StaticApi> = ManagedBuffer::new_from_bytes(job_id.as_bytes());
        // This is a view call, we treat it differently or use vm_query if available.
        // For now, raw_call with proper return type decoding is tricky in common without generic VM return.
        // We will implement basic success/fail and maybe parse manually if needed, or assume caller checks success.
        // Wait, `interactor` supports query.

        // Assuming we can use `query` on interactor if we had sc_proxy.
        // Since we use raw calls, we might need a dedicated `query` method in `common` or just rely on status checks.
        // For now, returning None as placeholder until view-mapper generic is added to common.
        None
    }

    pub fn address(&self) -> &Address {
        &self.contract_address
    }
}
