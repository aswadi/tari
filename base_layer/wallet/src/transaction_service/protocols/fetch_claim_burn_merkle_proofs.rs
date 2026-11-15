// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::{collections::HashSet, sync::Arc, time::Duration};

use blake2::Blake2b;
use digest::consts::U32;
use log::*;
use minotari_node_wallet_client::BaseNodeWalletClient;
use tari_common_types::{
    burn_proof::MAX_MMR_PROOF_HASHES,
    types::{CompressedCommitment, FixedHash},
};
use tari_hashing::BlocksHashDomain;
use tari_shutdown::ShutdownSignal;
use tari_sidechain::{BurnOutputProof, MmrInclusionProof};
use tari_transaction_components::{
    consensus::DomainSeparatedConsensusHasher,
    rpc::models,
    transaction_components::burn_output_proof::{BurnOutputProofExt, OutputHashPreimageExt},
};
use tokio::sync::broadcast;

use crate::{
    connectivity_service::WalletConnectivityInterface,
    transaction_service::{
        error::TransactionStorageError,
        handle::TransactionEvent,
        storage::database::{TransactionBackend, TransactionDatabase},
    },
};

const RETRY_DELAY: Duration = Duration::from_secs(10);
const MAX_ATTEMPTS: usize = 10;
const LOG_TARGET: &str = "wallet::transaction_service::protocols::sync_claim_burn_merkle_proofs";

/// Fetch, verify, and store burn output proofs for `confirmed_burns`, retrying transient failures.
///
/// This holds the wallet database and does remote I/O, so it holds `shutdown_signal` (counting as a listener for the
/// wallet's shutdown drain) and stops at the next await point once shutdown happens. Database calls are synchronous,
/// so stopping never interrupts a write.
pub async fn execute<TBackend, TConnectivity>(
    db: TransactionDatabase<TBackend>,
    connectivity: TConnectivity,
    event_publisher: broadcast::Sender<Arc<TransactionEvent>>,
    confirmed_burns: Vec<FixedHash>,
    mut shutdown_signal: ShutdownSignal,
) where
    TBackend: TransactionBackend + 'static,
    TConnectivity: WalletConnectivityInterface,
{
    tokio::select! {
        biased;
        _ = shutdown_signal.wait() => {
            debug!(target: LOG_TARGET, "sync_claim_burn_merkle_proofs stopped by shutdown signal");
        },
        _ = execute_with_retries(&db, &connectivity, &event_publisher, &confirmed_burns) => {},
    }
}

async fn execute_with_retries<TBackend, TConnectivity>(
    db: &TransactionDatabase<TBackend>,
    connectivity: &TConnectivity,
    event_publisher: &broadcast::Sender<Arc<TransactionEvent>>,
    confirmed_burns: &[FixedHash],
) where
    TBackend: TransactionBackend + 'static,
    TConnectivity: WalletConnectivityInterface,
{
    execute_with_retries_and_delay(db, connectivity, event_publisher, confirmed_burns, RETRY_DELAY).await;
}

async fn execute_with_retries_and_delay<TBackend, TConnectivity>(
    db: &TransactionDatabase<TBackend>,
    connectivity: &TConnectivity,
    event_publisher: &broadcast::Sender<Arc<TransactionEvent>>,
    confirmed_burns: &[FixedHash],
    retry_delay: Duration,
) where
    TBackend: TransactionBackend + 'static,
    TConnectivity: WalletConnectivityInterface,
{
    let mut seen = HashSet::with_capacity(confirmed_burns.len());
    let mut pending: Vec<FixedHash> = confirmed_burns
        .iter()
        .copied()
        .filter(|output_hash| seen.insert(*output_hash))
        .collect();
    if pending.is_empty() {
        return;
    }

    debug!(
        target: LOG_TARGET,
        "Starting sync_claim_burn_merkle_proofs with {} confirmed burns",
        pending.len()
    );

    for attempt in 1..=MAX_ATTEMPTS {
        pending = execute_inner(db, connectivity, &pending, event_publisher).await;
        if pending.is_empty() {
            return;
        }

        if attempt < MAX_ATTEMPTS {
            warn!(
                target: LOG_TARGET,
                "sync_claim_burn_merkle_proofs attempt {}/{} left {} burn output(s) pending; retrying in {:.2?}",
                attempt,
                MAX_ATTEMPTS,
                pending.len(),
                retry_delay
            );
            tokio::time::sleep(retry_delay).await;
        } else {
            error!(
                target: LOG_TARGET,
                "sync_claim_burn_merkle_proofs failed for {} burn output(s) after {} attempts, giving up",
                pending.len(),
                MAX_ATTEMPTS
            );
        }
    }
}

async fn execute_inner<TBackend, TConnectivity>(
    db: &TransactionDatabase<TBackend>,
    connectivity: &TConnectivity,
    pending_burns: &[FixedHash],
    event_publisher: &broadcast::Sender<Arc<TransactionEvent>>,
) -> Vec<FixedHash>
where
    TBackend: TransactionBackend + 'static,
    TConnectivity: WalletConnectivityInterface,
{
    if pending_burns.is_empty() {
        return Vec::new();
    }

    let timer = std::time::Instant::now();
    debug!(
        target: LOG_TARGET,
        "Syncing claim burn merkle proofs for {} confirmed burns. Waiting for client connection...",
        pending_burns.len()
    );
    let client = connectivity.obtain_base_node_wallet_rpc_client().await;
    debug!(
        target: LOG_TARGET,
        "Connected to base node wallet client after {:.2?}",
        timer.elapsed()
    );

    let mut failed = Vec::new();

    for output_hash in pending_burns {
        let burn = match db.fetch_burn_proof(output_hash) {
            Ok(Some(burn)) => burn,
            Ok(None) => {
                warn!(
                    target: LOG_TARGET,
                    "No burn proof found in database for output {}, skipping",
                    output_hash
                );
                continue;
            },
            Err(err) => {
                error!(
                    target: LOG_TARGET,
                    "Failed to read burn proof from database for output {}: {}",
                    output_hash,
                    err
                );
                failed.push(*output_hash);
                continue;
            },
        };

        if burn.burn_output_proof.is_some() {
            // If we're getting the same output again, there could be a reorg so just to be safe we'll refetch.
            warn!(
                target: LOG_TARGET,
                "Burn output {} already has a burn output proof, refetching",
                output_hash
            );
        }

        debug!(
            target: LOG_TARGET,
            "Updating burn output {} with burn output proof",
            output_hash
        );

        let resp = match client.get_burn_output_proof(&burn.burn_proof.commitment).await {
            Ok(resp) => resp,
            Err(err) => {
                error!(
                    target: LOG_TARGET,
                    "Failed to get burn output proof for burn output {}: {}",
                    output_hash,
                    err
                );
                failed.push(*output_hash);
                continue;
            },
        };

        let proof = resp.proof;
        info!(
            target: LOG_TARGET,
            "Received burn output proof for burn output {} mined in block #{} ({})",
            output_hash,
            proof.block_height,
            proof.block_hash
        );

        if let Err(reason) = validate_burn_output_proof_pre_header(output_hash, &burn.burn_proof.commitment, &proof) {
            error!(
                target: LOG_TARGET,
                "Base node returned an invalid burn output proof for output {}: {}",
                output_hash,
                reason
            );
            failed.push(*output_hash);
            continue;
        }

        let header = match client.get_header_by_height(proof.block_height).await {
            Ok(Some(header)) => header,
            Ok(None) => {
                error!(
                    target: LOG_TARGET,
                    "Base node returned no block header at height {} for burn output {}",
                    proof.block_height,
                    output_hash
                );
                failed.push(*output_hash);
                continue;
            },
            Err(err) => {
                error!(
                    target: LOG_TARGET,
                    "Failed to fetch block header at height {} for burn output {}: {}",
                    proof.block_height,
                    output_hash,
                    err
                );
                failed.push(*output_hash);
                continue;
            },
        };

        if let Err(reason) = validate_burn_output_proof_against_header(&proof, &header) {
            error!(
                target: LOG_TARGET,
                "Burn output proof verification failed against block #{} for output {}: {}",
                proof.block_height,
                output_hash,
                reason
            );
            failed.push(*output_hash);
            continue;
        }

        match db.update_burn_proof_set_burn_output_proof(output_hash, &proof) {
            Ok(()) => {
                info!(
                    target: LOG_TARGET,
                    "Successfully updated burn output {} with verified burn output proof (mined in height {})",
                    output_hash,
                    proof.block_height
                );

                let _ignore = event_publisher.send(Arc::new(TransactionEvent::TransactionBurnConfirmed {
                    output_hash: *output_hash,
                    commitment: Box::new(burn.burn_proof.commitment),
                }));
            },
            Err(TransactionStorageError::ValuesNotFound) => {
                warn!(
                    target: LOG_TARGET,
                    "Burn proof entry for output {} was removed before update completed, skipping",
                    output_hash
                );
            },
            Err(err) => {
                error!(
                    target: LOG_TARGET,
                    "Failed to store verified burn output proof for output {}: {}",
                    output_hash,
                    err
                );
                failed.push(*output_hash);
            },
        }
    }

    debug!(
        target: LOG_TARGET,
        "Syncing claim burn merkle proofs pass completed in {:.2?} ({} remaining)",
        timer.elapsed(),
        failed.len()
    );

    failed
}

fn validate_burn_output_proof_pre_header(
    output_hash: &FixedHash,
    expected_commitment: &CompressedCommitment,
    proof: &BurnOutputProof,
) -> Result<(), String> {
    // SQLite stores `mined_in_height` as signed `i64`, and `DbBurnProof::try_from` converts it back with
    // `u64::try_from(i64)`. Reject heights above `i64::MAX` before persisting so an out-of-range HTTP response
    // cannot wrap negative and permanently corrupt burn-proof reads.
    if i64::try_from(proof.block_height).is_err() {
        return Err(format!(
            "block_height {} exceeds maximum storable SQLite height {}",
            proof.block_height,
            i64::MAX
        ));
    }

    validate_mmr_proof_bounds("normal output", &proof.normal_output_proof)?;
    validate_mmr_proof_bounds("block output", &proof.block_output_proof)?;

    if proof.output.commitment != *expected_commitment {
        return Err("proof output commitment does not match expected burn commitment".to_string());
    }

    let features = proof
        .output
        .decode_features()
        .map_err(|err| format!("invalid output features: {err}"))?;
    if !features.output_type.is_burn() {
        return Err(format!(
            "proven output type {:?} is not a burn output",
            features.output_type
        ));
    }

    let proof_output_hash = proof
        .output
        .hash()
        .map_err(|err| format!("invalid output preimage: {err}"))?;
    if proof_output_hash != *output_hash {
        return Err(format!(
            "proof is for output {proof_output_hash} instead of expected {output_hash}"
        ));
    }

    Ok(())
}

fn validate_mmr_proof_bounds(mmr: &'static str, proof: &MmrInclusionProof) -> Result<(), String> {
    for (field, len) in [("path", proof.path.len()), ("peaks", proof.peaks.len())] {
        if len > MAX_MMR_PROOF_HASHES {
            return Err(format!(
                "{mmr} MMR proof {field} has {len} hashes, maximum is {MAX_MMR_PROOF_HASHES}"
            ));
        }
    }
    Ok(())
}

fn validate_burn_output_proof_against_header(
    proof: &BurnOutputProof,
    header: &models::BlockHeader,
) -> Result<(), String> {
    if header.height != proof.block_height {
        return Err(format!(
            "base node returned header at height {} when {} was requested",
            header.height, proof.block_height
        ));
    }

    if header.hash.as_slice() != proof.block_hash.as_slice() {
        return Err(format!(
            "header hash {} at height {} does not match proof block_hash {}",
            header.hash, header.height, proof.block_hash
        ));
    }

    let computed_hash = compute_rpc_header_hash(header);
    if computed_hash != header.hash {
        return Err(format!(
            "header at height {} failed hash integrity check (claimed {}, computed {})",
            header.height, header.hash, computed_hash
        ));
    }

    proof
        .verify(&header.block_output_mr)
        .map_err(|err| format!("MMR inclusion proof verification failed: {err}"))
}

fn compute_rpc_header_hash(header: &models::BlockHeader) -> FixedHash {
    let mining_hash: FixedHash = DomainSeparatedConsensusHasher::<BlocksHashDomain, Blake2b<U32>>::new("block_header")
        .chain(&header.version)
        .chain(&header.height)
        .chain(&header.prev_hash)
        .chain(&header.timestamp)
        .chain(&header.input_mr)
        .chain(&header.output_mr)
        .chain(&header.output_smt_size)
        .chain(&header.block_output_mr)
        .chain(&header.kernel_mr)
        .chain(&header.kernel_mmr_size)
        .chain(&header.total_kernel_offset)
        .chain(&header.total_script_offset)
        .chain(&header.validator_node_mr)
        .chain(&header.validator_node_size)
        .finalize()
        .into();

    DomainSeparatedConsensusHasher::<BlocksHashDomain, Blake2b<U32>>::new("block_header")
        .chain(&mining_hash)
        .chain(&header.pow)
        .chain(&header.nonce)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use std::{
        collections::{HashMap, VecDeque},
        sync::Mutex,
    };

    use digest::Digest;
    use tari_common_types::{
        burn_proof::PartialBurnClaimProof,
        types::{ComAndPubSignature, CompressedPublicKey, CompressedSignature, PrivateKey},
    };
    use tari_hashing::hashers::InputMmrHasherBlake256;
    use tari_node_components::blocks::BlockHeader as NodeBlockHeader;
    use tari_script::TariScript;
    use tari_shutdown::Shutdown;
    use tari_sidechain::OutputHashPreimage;
    use tari_transaction_components::{
        MicroMinotari,
        rpc::models::{
            FeePerGramStat,
            GenerateBurnOutputProofResponse,
            GetUtxosByBlockResponse,
            GetUtxosDeletedInfoResponse,
            GetUtxosMinedInfoResponse,
            SyncUtxosByBlockResponseV0,
            TipInfoResponse,
            TxQueryResponse,
            TxSubmissionResponse,
        },
        tari_proof_of_work::{PowAlgorithm, ProofOfWork},
        transaction_components::{
            EncryptedData,
            KernelFeatures,
            OutputFeatures,
            OutputType,
            Transaction,
            TransactionKernel,
            TransactionKernelVersion,
            TransactionOutput,
            covenants::Covenant,
        },
    };
    use tari_utilities::{ByteArray, SafePassword, epoch_time::EpochTime};
    use tempfile::tempdir;
    use tokio::sync::{mpsc, watch};

    use super::*;
    use crate::{
        connectivity_service::OnlineStatus,
        storage::{database::WalletDatabase, sqlite_utilities::initialize_sqlite_database_backends},
        transaction_service::storage::sqlite_db::TransactionServiceSqliteDatabase,
    };

    #[derive(Clone, Default)]
    struct MockBaseNodeClient {
        state: Arc<Mutex<MockBaseNodeState>>,
    }

    #[derive(Default)]
    struct MockBaseNodeState {
        proof_responses: HashMap<CompressedCommitment, VecDeque<Result<BurnOutputProof, String>>>,
        header_responses: HashMap<u64, VecDeque<Result<Option<models::BlockHeader>, String>>>,
        proof_calls: HashMap<CompressedCommitment, usize>,
        header_calls: HashMap<u64, usize>,
    }

    impl MockBaseNodeClient {
        fn push_proof_response(&self, commitment: CompressedCommitment, response: Result<BurnOutputProof, &str>) {
            let mut state = self.state.lock().unwrap();
            state
                .proof_responses
                .entry(commitment)
                .or_default()
                .push_back(response.map_err(ToString::to_string));
        }

        fn set_repeating_proof_response(
            &self,
            commitment: CompressedCommitment,
            response: Result<BurnOutputProof, &str>,
            count: usize,
        ) {
            for _ in 0..count {
                self.push_proof_response(commitment.clone(), response.clone());
            }
        }

        fn push_header_response(&self, height: u64, response: Result<Option<models::BlockHeader>, &str>) {
            let mut state = self.state.lock().unwrap();
            state
                .header_responses
                .entry(height)
                .or_default()
                .push_back(response.map_err(ToString::to_string));
        }

        fn proof_call_count(&self, commitment: &CompressedCommitment) -> usize {
            self.state
                .lock()
                .unwrap()
                .proof_calls
                .get(commitment)
                .copied()
                .unwrap_or(0)
        }

        fn total_header_calls(&self) -> usize {
            self.state.lock().unwrap().header_calls.values().sum()
        }
    }

    fn clone_rpc_header(header: &models::BlockHeader) -> models::BlockHeader {
        models::BlockHeader {
            hash: header.hash,
            version: header.version,
            height: header.height,
            prev_hash: header.prev_hash,
            timestamp: header.timestamp,
            input_mr: header.input_mr,
            output_mr: header.output_mr,
            block_output_mr: header.block_output_mr,
            output_smt_size: header.output_smt_size,
            kernel_mr: header.kernel_mr,
            kernel_mmr_size: header.kernel_mmr_size,
            total_kernel_offset: header.total_kernel_offset.clone(),
            total_script_offset: header.total_script_offset.clone(),
            validator_node_mr: header.validator_node_mr,
            validator_node_size: header.validator_node_size,
            pow: header.pow.clone(),
            nonce: header.nonce,
        }
    }

    #[async_trait::async_trait]
    impl BaseNodeWalletClient for MockBaseNodeClient {
        async fn get_address(&self) -> String {
            "http://127.0.0.1:18142".to_string()
        }

        async fn is_online(&self) -> bool {
            true
        }

        async fn get_tip_info(&self) -> Result<TipInfoResponse, anyhow::Error> {
            unimplemented!("unused in fetch_claim_burn_merkle_proofs tests")
        }

        async fn get_header_by_height(&self, height: u64) -> Result<Option<models::BlockHeader>, anyhow::Error> {
            let mut state = self.state.lock().unwrap();
            *state.header_calls.entry(height).or_insert(0) += 1;
            match state.header_responses.get_mut(&height).and_then(VecDeque::pop_front) {
                Some(Ok(header)) => Ok(header),
                Some(Err(err)) => Err(anyhow::anyhow!(err)),
                None => Ok(None),
            }
        }

        async fn get_height_at_time(&self, _epoch_time: u64) -> Result<u64, anyhow::Error> {
            unimplemented!("unused in fetch_claim_burn_merkle_proofs tests")
        }

        async fn get_utxos_by_block(&self, _header_hash: Vec<u8>) -> Result<GetUtxosByBlockResponse, anyhow::Error> {
            unimplemented!("unused in fetch_claim_burn_merkle_proofs tests")
        }

        async fn sync_utxos_by_block(
            &self,
            _start_header_hash: Vec<u8>,
            _shutdown: ShutdownSignal,
        ) -> Result<mpsc::Receiver<Result<SyncUtxosByBlockResponseV0, anyhow::Error>>, anyhow::Error> {
            unimplemented!("unused in fetch_claim_burn_merkle_proofs tests")
        }

        async fn get_last_request_latency(&self) -> Option<Duration> {
            None
        }

        async fn get_utxos_mined_info(
            &self,
            _hashes: Vec<Vec<u8>>,
            _version: u32,
        ) -> Result<GetUtxosMinedInfoResponse, anyhow::Error> {
            unimplemented!("unused in fetch_claim_burn_merkle_proofs tests")
        }

        async fn fetch_utxo(&self, _hash: Vec<u8>) -> Result<Option<TransactionOutput>, anyhow::Error> {
            unimplemented!("unused in fetch_claim_burn_merkle_proofs tests")
        }

        async fn query_deleted_utxos(
            &self,
            _hashes: Vec<Vec<u8>>,
            _must_include_header: Vec<u8>,
        ) -> Result<GetUtxosDeletedInfoResponse, anyhow::Error> {
            unimplemented!("unused in fetch_claim_burn_merkle_proofs tests")
        }

        async fn submit_transaction(&self, _transaction: Transaction) -> Result<TxSubmissionResponse, anyhow::Error> {
            unimplemented!("unused in fetch_claim_burn_merkle_proofs tests")
        }

        async fn transaction_query(
            &self,
            _excess_sig_nonce: Vec<u8>,
            _excess_sig_sig: Vec<u8>,
        ) -> Result<TxQueryResponse, anyhow::Error> {
            unimplemented!("unused in fetch_claim_burn_merkle_proofs tests")
        }

        async fn get_mempool_fee_per_gram_stats(&self, _count: u64) -> Result<FeePerGramStat, anyhow::Error> {
            unimplemented!("unused in fetch_claim_burn_merkle_proofs tests")
        }

        async fn get_burn_output_proof(
            &self,
            commitment: &CompressedCommitment,
        ) -> Result<GenerateBurnOutputProofResponse, anyhow::Error> {
            let mut state = self.state.lock().unwrap();
            *state.proof_calls.entry(commitment.clone()).or_insert(0) += 1;
            match state.proof_responses.get_mut(commitment).and_then(VecDeque::pop_front) {
                Some(Ok(proof)) => Ok(GenerateBurnOutputProofResponse { proof }),
                Some(Err(err)) => Err(anyhow::anyhow!(err)),
                None => Err(anyhow::anyhow!("no mock burn output proof configured")),
            }
        }
    }

    #[derive(Clone)]
    struct MockConnectivity {
        client: MockBaseNodeClient,
        status_rx: watch::Receiver<OnlineStatus>,
    }

    impl MockConnectivity {
        fn new(client: MockBaseNodeClient) -> Self {
            let (_tx, status_rx) = watch::channel(OnlineStatus::Online {
                latency_ms: 1,
                url: "http://127.0.0.1:18142".to_string(),
            });
            Self { client, status_rx }
        }
    }

    #[async_trait::async_trait]
    impl WalletConnectivityInterface for MockConnectivity {
        type BaseNodeClient = MockBaseNodeClient;

        async fn obtain_base_node_wallet_rpc_client(&self) -> Self::BaseNodeClient {
            self.client.clone()
        }

        async fn get_connectivity_status(&self) -> OnlineStatus {
            OnlineStatus::Online {
                latency_ms: 1,
                url: "http://127.0.0.1:18142".to_string(),
            }
        }

        fn get_connectivity_status_watch(&self) -> watch::Receiver<OnlineStatus> {
            self.status_rx.clone()
        }

        async fn get_last_request_latency(&self) -> Option<Duration> {
            None
        }

        async fn get_address(&self) -> String {
            "http://127.0.0.1:18142".to_string()
        }
    }

    fn setup_dbs() -> (
        tempfile::TempDir,
        WalletDatabase<crate::storage::sqlite_db::wallet::WalletSqliteDatabase>,
        TransactionDatabase<TransactionServiceSqliteDatabase>,
    ) {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("wallet.sqlite");
        let (wallet_backend, tx_backend, _, _) =
            initialize_sqlite_database_backends(db_path, SafePassword::from("test-passphrase"), 4).unwrap();
        (
            dir,
            WalletDatabase::new(wallet_backend),
            TransactionDatabase::new(tx_backend),
        )
    }

    fn mmr_single_leaf_root<D: Digest>(leaf: &[u8]) -> [u8; 32] {
        let mut hasher = D::new();
        hasher.update(leaf);
        hasher.finalize().as_slice().try_into().unwrap()
    }

    fn build_burn_fixture(
        seed: u64,
        output_type: OutputType,
        height: u64,
    ) -> (
        FixedHash,
        CompressedCommitment,
        PartialBurnClaimProof,
        BurnOutputProof,
        models::BlockHeader,
    ) {
        let sk = PrivateKey::from(seed.max(1));
        let pk = CompressedPublicKey::from_secret_key(&sk);
        let commitment = CompressedCommitment::from_canonical_bytes(pk.as_bytes()).unwrap();

        let tx_output = TransactionOutput::new_current_version(
            OutputFeatures {
                output_type,
                ..Default::default()
            },
            commitment.clone(),
            None,
            TariScript::default(),
            pk.clone(),
            ComAndPubSignature::default(),
            Covenant::default(),
            EncryptedData::default(),
            MicroMinotari::from(0),
        );
        let output_hash = tx_output.hash();

        let single_leaf_proof = MmrInclusionProof {
            leaf_index: 0,
            mmr_size: 1,
            path: Vec::new(),
            peaks: Vec::new(),
        };
        let normal_output_mr_bytes = mmr_single_leaf_root::<InputMmrHasherBlake256>(output_hash.as_slice());
        let block_output_mr_bytes = mmr_single_leaf_root::<InputMmrHasherBlake256>(&normal_output_mr_bytes);
        let block_output_mr = FixedHash::from(block_output_mr_bytes);

        let mut node_header = NodeBlockHeader::new(1);
        node_header.height = height;
        node_header.block_output_mr = block_output_mr;
        node_header.nonce = seed;
        let rpc_header = models::BlockHeader::from(node_header);

        let burn_output_proof = BurnOutputProof {
            block_hash: tari_sidechain::FixedHash::from(<[u8; 32]>::try_from(rpc_header.hash.as_slice()).unwrap()),
            block_height: height,
            output: OutputHashPreimage::from(&tx_output),
            normal_output_proof: single_leaf_proof.clone(),
            normal_output_mr: tari_sidechain::FixedHash::from(normal_output_mr_bytes),
            block_output_proof: single_leaf_proof,
        };

        let partial_burn_proof = PartialBurnClaimProof {
            claim_public_key: pk.clone(),
            commitment: commitment.clone(),
            ownership_proof: CompressedSignature::default(),
            kernel_excess: vec![seed as u8; 32],
            kernel_excess_nonce: vec![0xAA; 32],
            kernel_excess_signature: vec![0xBB; 32],
            sender_offset_public_key: pk,
        };

        (
            output_hash,
            commitment,
            partial_burn_proof,
            burn_output_proof,
            rpc_header,
        )
    }

    fn insert_test_burn_row(
        db: &TransactionDatabase<TransactionServiceSqliteDatabase>,
        output_hash: FixedHash,
        partial_proof: &PartialBurnClaimProof,
    ) {
        let kernel = TransactionKernel::new(
            TransactionKernelVersion::get_current_version(),
            KernelFeatures::create_burn(),
            MicroMinotari::from(100),
            0,
            partial_proof.commitment.clone(),
            CompressedSignature::default(),
            None,
        );
        db.insert_burn_proof(
            output_hash,
            partial_proof,
            &kernel,
            &EncryptedData::default(),
            MicroMinotari::from(1_000),
        )
        .unwrap();
    }

    #[test]
    fn rpc_header_hash_matches_node_block_header_hash() {
        let mut node_header = NodeBlockHeader::new(2);
        node_header.height = 98_765;
        node_header.prev_hash = FixedHash::from([0x11; 32]);
        node_header.timestamp = EpochTime::from(1_700_000_123);
        node_header.input_mr = FixedHash::from([0x22; 32]);
        node_header.output_mr = FixedHash::from([0x33; 32]);
        node_header.output_smt_size = 444;
        node_header.block_output_mr = FixedHash::from([0x44; 32]);
        node_header.kernel_mr = FixedHash::from([0x55; 32]);
        node_header.kernel_mmr_size = 555;
        node_header.total_kernel_offset = PrivateKey::from(666u64);
        node_header.total_script_offset = PrivateKey::from(777u64);
        node_header.validator_node_mr = FixedHash::from([0x88; 32]);
        node_header.validator_node_size = 999;
        node_header.pow = ProofOfWork {
            pow_algo: PowAlgorithm::Sha3x,
            pow_data: vec![1, 2, 3, 4].try_into().unwrap(),
        };
        node_header.nonce = 123_456_789;

        let expected = node_header.hash();
        let rpc_header = models::BlockHeader::from(node_header);
        assert_eq!(rpc_header.hash, expected);
        assert_eq!(compute_rpc_header_hash(&rpc_header), expected);
    }

    #[tokio::test]
    async fn persists_verified_burn_output_proof_and_publishes_event() {
        let (_dir, wallet_db, tx_db) = setup_dbs();
        let (output_hash, commitment, partial_proof, burn_output_proof, rpc_header) =
            build_burn_fixture(1, OutputType::Burn, 42);
        insert_test_burn_row(&tx_db, output_hash, &partial_proof);

        let client = MockBaseNodeClient::default();
        client.push_proof_response(commitment.clone(), Ok(burn_output_proof.clone()));
        client.push_header_response(42, Ok(Some(rpc_header)));
        let connectivity = MockConnectivity::new(client.clone());

        let (event_tx, mut event_rx) = broadcast::channel(8);
        // Pass duplicate output hashes in one batch to verify deduplication.
        execute_with_retries_and_delay(
            &tx_db,
            &connectivity,
            &event_tx,
            &[output_hash, output_hash],
            Duration::ZERO,
        )
        .await;

        assert_eq!(client.proof_call_count(&commitment), 1);
        let stored = tx_db.fetch_burn_proof(&output_hash).unwrap().unwrap();
        assert_eq!(stored.burn_output_proof, Some(burn_output_proof));
        assert_eq!(stored.mined_in_height, Some(42));
        assert_eq!(wallet_db.get_all_burn_proofs().unwrap().len(), 1);

        let event = event_rx.try_recv().unwrap();
        match &*event {
            TransactionEvent::TransactionBurnConfirmed {
                output_hash: ev_hash,
                commitment: ev_commitment,
            } => {
                assert_eq!(*ev_hash, output_hash);
                assert_eq!(**ev_commitment, commitment);
            },
            other => panic!("unexpected event: {other:?}"),
        }
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn rejects_height_above_i64_max_without_corrupting_sqlite() {
        let (_dir, wallet_db, tx_db) = setup_dbs();
        let (output_hash, commitment, partial_proof, mut burn_output_proof, _rpc_header) =
            build_burn_fixture(2, OutputType::Burn, 100);
        insert_test_burn_row(&tx_db, output_hash, &partial_proof);

        burn_output_proof.block_height = u64::MAX;
        let client = MockBaseNodeClient::default();
        client.set_repeating_proof_response(commitment.clone(), Ok(burn_output_proof), MAX_ATTEMPTS);
        let connectivity = MockConnectivity::new(client.clone());

        let (event_tx, mut event_rx) = broadcast::channel(8);
        execute_with_retries_and_delay(&tx_db, &connectivity, &event_tx, &[output_hash], Duration::ZERO).await;

        assert_eq!(client.proof_call_count(&commitment), MAX_ATTEMPTS);
        assert_eq!(client.total_header_calls(), 0);
        let stored = tx_db.fetch_burn_proof(&output_hash).unwrap().unwrap();
        assert!(stored.burn_output_proof.is_none());
        assert!(stored.mined_in_height.is_none());
        assert_eq!(wallet_db.get_all_burn_proofs().unwrap().len(), 1);
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_mmr_proof_hashes() {
        let (_dir, _wallet_db, tx_db) = setup_dbs();
        let (output_hash, commitment, partial_proof, base_proof, _rpc_header) =
            build_burn_fixture(3, OutputType::Burn, 50);
        insert_test_burn_row(&tx_db, output_hash, &partial_proof);

        let oversized = vec![tari_sidechain::FixedHash::from([0xAA; 32]); MAX_MMR_PROOF_HASHES + 1];

        let mut bad_normal_path = base_proof.clone();
        bad_normal_path.normal_output_proof.path = oversized.clone();

        let mut bad_normal_peaks = base_proof.clone();
        bad_normal_peaks.normal_output_proof.peaks = oversized.clone();

        let mut bad_block_path = base_proof.clone();
        bad_block_path.block_output_proof.path = oversized.clone();

        let mut bad_block_peaks = base_proof;
        bad_block_peaks.block_output_proof.peaks = oversized;

        let client = MockBaseNodeClient::default();
        for variant in [bad_normal_path, bad_normal_peaks, bad_block_path, bad_block_peaks] {
            client.push_proof_response(commitment.clone(), Ok(variant));
        }
        let connectivity = MockConnectivity::new(client.clone());

        let (event_tx, mut event_rx) = broadcast::channel(8);
        execute_with_retries_and_delay(&tx_db, &connectivity, &event_tx, &[output_hash], Duration::ZERO).await;

        assert_eq!(client.total_header_calls(), 0);
        let stored = tx_db.fetch_burn_proof(&output_hash).unwrap().unwrap();
        assert!(stored.burn_output_proof.is_none());
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn rejects_non_burn_output_and_mismatched_output() {
        let (_dir, _wallet_db, tx_db) = setup_dbs();
        let (output_hash, commitment, partial_proof, _valid_burn_proof, _header) =
            build_burn_fixture(4, OutputType::Burn, 60);
        insert_test_burn_row(&tx_db, output_hash, &partial_proof);

        // Non-burn output with the exact same commitment and valid MMR root.
        let (_std_hash, _std_commitment, _std_partial, non_burn_proof, _std_header) =
            build_burn_fixture(4, OutputType::Standard, 60);

        // Burn output for a completely different commitment/hash.
        let (_other_hash, _other_commitment, _other_partial, wrong_burn_proof, _other_header) =
            build_burn_fixture(5, OutputType::Burn, 60);

        let client = MockBaseNodeClient::default();
        client.push_proof_response(commitment.clone(), Ok(non_burn_proof));
        client.push_proof_response(commitment.clone(), Ok(wrong_burn_proof));
        let connectivity = MockConnectivity::new(client.clone());

        let (event_tx, mut event_rx) = broadcast::channel(8);
        execute_with_retries_and_delay(&tx_db, &connectivity, &event_tx, &[output_hash], Duration::ZERO).await;

        assert_eq!(client.total_header_calls(), 0);
        let stored = tx_db.fetch_burn_proof(&output_hash).unwrap().unwrap();
        assert!(stored.burn_output_proof.is_none());
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn rejects_forged_headers_and_tampered_mmr_proofs() {
        let (_dir, _wallet_db, tx_db) = setup_dbs();
        let (output_hash, commitment, partial_proof, valid_proof, valid_header) =
            build_burn_fixture(6, OutputType::Burn, 77);
        insert_test_burn_row(&tx_db, output_hash, &partial_proof);

        let client = MockBaseNodeClient::default();

        // Attempt 1: Base node returns None header.
        client.push_proof_response(commitment.clone(), Ok(valid_proof.clone()));
        client.push_header_response(77, Ok(None));

        // Attempt 2: Base node returns header at wrong height.
        let mut wrong_height_header = clone_rpc_header(&valid_header);
        wrong_height_header.height = 78;
        client.push_proof_response(commitment.clone(), Ok(valid_proof.clone()));
        client.push_header_response(77, Ok(Some(wrong_height_header)));

        // Attempt 3: Reorged header (valid self-hash, different block_hash from proof).
        let (_other_h, _other_c, _other_p, _other_proof, reorged_header) = build_burn_fixture(99, OutputType::Burn, 77);
        client.push_proof_response(commitment.clone(), Ok(valid_proof.clone()));
        client.push_header_response(77, Ok(Some(reorged_header)));

        // Attempt 4: Malicious HTTP server mutates `block_output_mr` to match a forged proof while keeping
        // `header.hash` equal to `proof.block_hash` (caught by `compute_rpc_header_hash(&header) !=
        // header.hash`).
        let mut forged_mr_proof = valid_proof.clone();
        forged_mr_proof.normal_output_mr = tari_sidechain::FixedHash::from([0xEE; 32]);
        let forged_block_mr_bytes = mmr_single_leaf_root::<InputMmrHasherBlake256>(&[0xEE; 32]);
        let mut forged_header = clone_rpc_header(&valid_header);
        forged_header.block_output_mr = FixedHash::from(forged_block_mr_bytes);
        client.push_proof_response(commitment.clone(), Ok(forged_mr_proof.clone()));
        client.push_header_response(77, Ok(Some(forged_header)));

        // Attempt 5: Honest header (`compute_rpc_header_hash == header.hash == proof.block_hash`), tampered MMR proof.
        client.push_proof_response(commitment, Ok(forged_mr_proof));
        client.push_header_response(77, Ok(Some(valid_header)));

        let connectivity = MockConnectivity::new(client);
        let (event_tx, mut event_rx) = broadcast::channel(8);
        execute_with_retries_and_delay(&tx_db, &connectivity, &event_tx, &[output_hash], Duration::ZERO).await;

        let stored = tx_db.fetch_burn_proof(&output_hash).unwrap().unwrap();
        assert!(stored.burn_output_proof.is_none());
        assert!(stored.mined_in_height.is_none());
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn retries_only_failed_burns_and_recovers_from_transient_errors() {
        let (_dir, _wallet_db, tx_db) = setup_dbs();
        let (hash_1, comm_1, partial_1, proof_1, header_1) = build_burn_fixture(10, OutputType::Burn, 101);
        let (hash_2, comm_2, partial_2, proof_2, header_2) = build_burn_fixture(11, OutputType::Burn, 102);
        let missing_hash = FixedHash::from([0xFE; 32]);

        insert_test_burn_row(&tx_db, hash_1, &partial_1);
        insert_test_burn_row(&tx_db, hash_2, &partial_2);

        let client = MockBaseNodeClient::default();
        // Burn 1 succeeds immediately on attempt 1.
        client.push_proof_response(comm_1.clone(), Ok(proof_1.clone()));
        client.push_header_response(101, Ok(Some(header_1)));

        // Burn 2 fails RPC on attempt 1, fails header fetch on attempt 2, then succeeds on attempt 3.
        client.push_proof_response(comm_2.clone(), Err("transient HTTP timeout"));
        client.push_proof_response(comm_2.clone(), Ok(proof_2.clone()));
        client.push_header_response(102, Err("header endpoint temporarily unavailable"));
        client.push_proof_response(comm_2.clone(), Ok(proof_2.clone()));
        client.push_header_response(102, Ok(Some(header_2)));

        let connectivity = MockConnectivity::new(client.clone());
        let (event_tx, mut event_rx) = broadcast::channel(8);

        execute_with_retries_and_delay(
            &tx_db,
            &connectivity,
            &event_tx,
            &[hash_1, hash_2, missing_hash],
            Duration::ZERO,
        )
        .await;

        // Burn 1 was fetched and emitted exactly once; Burn 2 took 3 attempts and then succeeded.
        assert_eq!(client.proof_call_count(&comm_1), 1);
        assert_eq!(client.proof_call_count(&comm_2), 3);

        let stored_1 = tx_db.fetch_burn_proof(&hash_1).unwrap().unwrap();
        let stored_2 = tx_db.fetch_burn_proof(&hash_2).unwrap().unwrap();
        assert_eq!(stored_1.burn_output_proof, Some(proof_1));
        assert_eq!(stored_2.burn_output_proof, Some(proof_2));

        let mut confirmed_hashes = Vec::new();
        while let Ok(ev) = event_rx.try_recv() {
            if let TransactionEvent::TransactionBurnConfirmed { output_hash, .. } = &*ev {
                confirmed_hashes.push(*output_hash);
            }
        }
        assert_eq!(confirmed_hashes, vec![hash_1, hash_2]);
    }

    #[tokio::test]
    async fn stops_promptly_when_shutdown_signal_fires() {
        let (_dir, _wallet_db, tx_db) = setup_dbs();
        let (output_hash, commitment, partial_proof, _proof, _header) = build_burn_fixture(20, OutputType::Burn, 200);
        insert_test_burn_row(&tx_db, output_hash, &partial_proof);

        let client = MockBaseNodeClient::default();
        let connectivity = MockConnectivity::new(client.clone());
        let (event_tx, mut event_rx) = broadcast::channel(8);

        let shutdown = Shutdown::new();
        let signal = shutdown.to_signal();
        shutdown.trigger();

        execute(tx_db.clone(), connectivity, event_tx, vec![output_hash], signal).await;

        assert_eq!(client.proof_call_count(&commitment), 0);
        assert!(
            tx_db
                .fetch_burn_proof(&output_hash)
                .unwrap()
                .unwrap()
                .burn_output_proof
                .is_none()
        );
        assert!(event_rx.try_recv().is_err());
    }
}
