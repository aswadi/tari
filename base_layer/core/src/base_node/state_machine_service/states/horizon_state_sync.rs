//   Copyright 2020, The Tari Project
//
//   Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//   following conditions are met:
//
//   1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
//   disclaimer.
//
//   2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//   following disclaimer in the documentation and/or other materials provided with the distribution.
//
//   3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
//   products derived from this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//   INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//   WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
//   USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//! # Horizon state sync
//!
//! Horizon state synchronisation module for pruned mode.

use log::*;
use tari_transaction_components::crypto_factories::CryptoFactories;

use super::{StateEvent, StateInfo};
use crate::{
    base_node::{
        BaseNodeStateMachine,
        state_machine_service::states::StatusInfo,
        sync::{HorizonStateSynchronization, SyncPeer},
    },
    chain_storage::BlockchainBackend,
};
const LOG_TARGET: &str = "c::bn::state_machine_service::states::horizon_state_sync";

#[derive(Clone, Debug)]
pub struct HorizonStateSync {
    sync_peers: Vec<SyncPeer>,
}

impl HorizonStateSync {
    pub fn into_sync_peers(self) -> Vec<SyncPeer> {
        self.sync_peers
    }

    pub async fn next_event<B: BlockchainBackend + 'static>(
        &mut self,
        shared: &mut BaseNodeStateMachine<B>,
    ) -> StateEvent {
        let local_metadata = match shared.db.get_chain_metadata().await {
            Ok(metadata) => metadata,
            Err(err) => return err.into(),
        };

        let sync_peers = &mut self.sync_peers;

        // Target horizon sync height based on the last header we have synced
        let last_header = match shared.db.fetch_last_header().await {
            Ok(h) => h,
            Err(err) => return err.into(),
        };
        let target_horizon_sync_height = local_metadata.pruned_height_at_given_chain_tip(last_header.height);

        // Determine if we need to sync horizon state
        if local_metadata.pruned_height() >= target_horizon_sync_height {
            info!(target: LOG_TARGET, "Horizon state is already synchronized.");
            return StateEvent::HorizonStateSynchronized;
        }
        if local_metadata.best_block_height() >= target_horizon_sync_height {
            info!(
                target: LOG_TARGET,
                "Our tip height is higher than our target pruned height. Horizon state is already synchronized."
            );
            return StateEvent::HorizonStateSynchronized;
        }

        let db = shared.db.clone();
        let config = shared.config.blockchain_sync_config.clone();
        let connectivity = shared.connectivity.clone();
        let rules = shared.consensus_rules.clone();
        let prover = CryptoFactories::default().range_proof;
        let validator = shared.sync_validators.final_horizon_state.clone();
        let mut horizon_sync = HorizonStateSynchronization::new(
            config,
            db,
            connectivity,
            rules,
            sync_peers,
            target_horizon_sync_height,
            prover,
            validator,
        );

        let status_event_sender = shared.status_event_sender.clone();
        let bootstrapped = shared.is_bootstrapped();
        let randomx_vm_cnt = shared.get_randomx_vm_cnt();
        let randomx_vm_flags = shared.get_randomx_vm_flags();
        horizon_sync.on_starting(move |sync_peer| {
            let _result = status_event_sender.send(StatusInfo {
                bootstrapped,
                state_info: StateInfo::Connecting(sync_peer.clone()),
                randomx_vm_cnt,
                randomx_vm_flags,
            });
        });

        let status_event_sender = shared.status_event_sender.clone();
        horizon_sync.on_progress(move |info| {
            let _result = status_event_sender.send(StatusInfo {
                bootstrapped,
                state_info: StateInfo::HorizonSync(info),
                randomx_vm_cnt,
                randomx_vm_flags,
            });
        });

        match horizon_sync.synchronize().await {
            Ok(()) => {
                info!(target: LOG_TARGET, "Horizon state has synchronized.");
                StateEvent::HorizonStateSynchronized
            },
            Err(err) => {
                let _ignore = shared.status_event_sender.send(StatusInfo {
                    bootstrapped,
                    state_info: StateInfo::SyncFailed("HorizonSyncFailed".to_string()),
                    randomx_vm_cnt,
                    randomx_vm_flags,
                });
                warn!(target: LOG_TARGET, "Synchronizing horizon state has failed. {err}");
                StateEvent::HorizonStateSyncFailure(err.to_string())
            },
        }
    }
}

impl From<Vec<SyncPeer>> for HorizonStateSync {
    fn from(sync_peers: Vec<SyncPeer>) -> Self {
        Self { sync_peers }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::indexing_slicing)]
    use std::time::Duration;

    use primitive_types::U512;
    use tari_common_types::{chain_metadata::ChainMetadata, types::FixedHash};
    use tari_comms::{peer_manager::NodeId, test_utils::mocks::create_connectivity_mock};
    use tari_service_framework::reply_channel;
    use tari_shutdown::Shutdown;
    use tokio::sync::{broadcast, watch};

    use super::*;
    use crate::{
        base_node::{
            BaseNodeStateMachineConfig,
            LocalNodeCommsInterface,
            chain_metadata_service::PeerChainMetadata,
            sync::SyncValidators,
        },
        proof_of_work::randomx_factory::RandomXFactory,
        test_helpers::{blockchain::create_new_blockchain, create_consensus_rules, create_peer_manager},
        validation::mocks::MockValidator,
    };

    fn make_peer(height: u64, difficulty: u64, latency: Option<Duration>) -> SyncPeer {
        let metadata =
            ChainMetadata::new(height, FixedHash::zero(), 0, 0, U512::from(difficulty), 0).expect("valid metadata");
        SyncPeer::from(PeerChainMetadata::new(NodeId::new(), metadata, latency))
    }

    #[tokio::test]
    async fn next_event_preserves_incoming_sync_peer_priority_order() {
        let db = create_new_blockchain();
        let (connectivity, _connectivity_mock) = create_connectivity_mock();
        let (_metadata_tx, metadata_rx) = broadcast::channel(10);
        let (_dht_tx, dht_rx) = broadcast::channel(10);
        let (req_tx, _) = reply_channel::unbounded();
        let (block_tx, _) = reply_channel::unbounded();
        let (block_event_tx, _) = broadcast::channel(1);
        let (status_tx, _status_rx) = watch::channel(StatusInfo::new());
        let (event_tx, _event_rx) = broadcast::channel(10);
        let shutdown = Shutdown::new();
        let mut state_machine = BaseNodeStateMachine::new(
            db.into(),
            LocalNodeCommsInterface::new(req_tx, block_tx, block_event_tx),
            connectivity,
            metadata_rx,
            create_peer_manager(),
            dht_rx,
            BaseNodeStateMachineConfig::default(),
            SyncValidators::new(MockValidator::new(true), MockValidator::new(true)),
            status_tx,
            event_tx,
            RandomXFactory::default(),
            create_consensus_rules(),
            shutdown.to_signal(),
        );

        let header_winner = make_peer(100, 150, Some(Duration::from_millis(15)));
        let slow_higher_pow = make_peer(120, 200, Some(Duration::from_millis(900)));
        let fast_tie = make_peer(100, 150, Some(Duration::from_millis(5)));

        let mut horizon_sync =
            HorizonStateSync::from(vec![header_winner.clone(), slow_higher_pow.clone(), fast_tie.clone()]);
        let event = horizon_sync.next_event(&mut state_machine).await;
        assert_eq!(event, StateEvent::HorizonStateSynchronized);

        let peers = horizon_sync.into_sync_peers();
        assert_eq!(peers[0].node_id(), header_winner.node_id());
        assert_eq!(peers[1].node_id(), slow_higher_pow.node_id());
        assert_eq!(peers[2].node_id(), fast_tie.node_id());
    }
}
