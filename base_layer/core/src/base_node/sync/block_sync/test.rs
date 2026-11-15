//  Copyright 2026, The Tari Project
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//  following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
//  disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//  following disclaimer in the documentation and/or other materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
//  products derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
//  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tari_common::configuration::Network;
use tari_common_types::chain_metadata::ChainMetadata;
use tari_comms::{
    connection_manager::ConnectionManagerError,
    connectivity::{ConnectivityError, ConnectivityRequester},
    peer_manager::{NodeId, PeerFeatures},
    protocol::rpc::{
        HandshakeRejectReason,
        NamedProtocolService,
        Request,
        Response,
        RpcError,
        RpcHandshakeError,
        RpcStatus,
        Streaming,
        mock::MockRpcServer,
    },
    test_utils::{
        mocks::{ConnectivityManagerMockState, create_connectivity_mock},
        node_identity::build_node_identity,
    },
};
use tari_node_components::blocks::{ChainBlock, ChainHeader};
use tari_transaction_components::{
    consensus::{ConsensusConstants, consensus_constants::ConsensusConstantsBuilder},
    tari_proof_of_work::{Difficulty, PowAlgorithm},
    transaction_components::RangeProofType,
};
use tokio::sync::mpsc;

use super::synchronizer::{dial_failure_is_peer_caused, rpc_setup_failure_is_peer_caused};
use crate::{
    base_node::{
        chain_metadata_service::PeerChainMetadata,
        sync::{
            BlockSyncError,
            BlockSynchronizer,
            BlockchainSyncConfig,
            SyncPeer,
            mock_sync_peer::{MockSyncPeer, banned_peers, connect_mock_peer, connect_mock_peer_as},
            rpc::{BaseNodeSyncRpcServer, BaseNodeSyncService},
        },
    },
    blocks::BlockHeaderAccumulatedDataBuilder,
    chain_storage::BlockchainDatabase,
    consensus::BaseNodeConsensusManager,
    proof_of_work::AchievedTargetDifficulty,
    proto,
    proto::base_node::{
        FindChainSplitRequest,
        FindChainSplitResponse,
        SyncBlocksRequest,
        SyncHeadersRequest,
        SyncKernelsRequest,
        SyncUtxosRequest,
        SyncUtxosResponse,
    },
    test_helpers::{
        BlockSpecs,
        blockchain::{
            TempDatabase,
            create_chained_blocks,
            create_chained_blocks_with_range_proof_type,
            create_custom_blockchain,
            create_main_chain,
            create_new_blockchain,
        },
    },
    validation::mocks::MockValidator,
};

/// Builds `specs` on the genesis block without adding them, and adds the header of `header_ahead` so that our header
/// chain is one block ahead of our blocks.
fn headers_ahead_of_blocks(
    specs: BlockSpecs,
    header_ahead: &str,
) -> (BlockchainDatabase<TempDatabase>, HashMap<String, Arc<ChainBlock>>) {
    let db = create_new_blockchain();
    let genesis = Arc::new(db.fetch_block(0, true).unwrap().try_into_chain_block().unwrap());
    let (_, chain) = create_chained_blocks(&db, specs, genesis);
    let block = chain.get(header_ahead).unwrap();
    let chain_header = ChainHeader::try_construct(block.header().clone(), block.accumulated_data().clone()).unwrap();
    db.insert_valid_headers(vec![chain_header]).unwrap();
    (db, chain)
}

fn claim_for(block: &ChainBlock) -> ChainMetadata {
    ChainMetadata::new(
        block.height(),
        *block.hash(),
        0,
        0,
        block.accumulated_data().total_accumulated_difficulty,
        0,
    )
    .unwrap()
}

fn short_deadline_config() -> BlockchainSyncConfig {
    BlockchainSyncConfig {
        rpc_deadline: Duration::from_secs(1),
        ..Default::default()
    }
}

async fn sync_blocks(
    db: &BlockchainDatabase<TempDatabase>,
    connectivity: ConnectivityRequester,
    config: BlockchainSyncConfig,
    sync_peers: Vec<SyncPeer>,
) -> Result<(), BlockSyncError> {
    sync_blocks_with_history(db, connectivity, config, sync_peers, &mut HashMap::new()).await
}

async fn sync_blocks_with_history(
    db: &BlockchainDatabase<TempDatabase>,
    connectivity: ConnectivityRequester,
    config: BlockchainSyncConfig,
    mut sync_peers: Vec<SyncPeer>,
    attempts_without_block: &mut HashMap<NodeId, Vec<Instant>>,
) -> Result<(), BlockSyncError> {
    let mut synchronizer = BlockSynchronizer::new(
        config,
        db.clone().into(),
        connectivity,
        &mut sync_peers,
        Arc::new(MockValidator::new(true)),
        attempts_without_block,
    );
    synchronizer.synchronize().await
}

/// A claim for `block`'s work that names a different best block, so a NotFound from the peer is not banned
fn claim_with_another_tip(block: &ChainBlock) -> ChainMetadata {
    ChainMetadata::new(
        block.height(),
        [9u8; 32].into(),
        0,
        0,
        block.accumulated_data().total_accumulated_difficulty,
        0,
    )
    .unwrap()
}

/// A peer that answers `sync_blocks` with NotFound
fn not_found_peer(db: &BlockchainDatabase<TempDatabase>) -> MockSyncPeer {
    let mut peer = MockSyncPeer::new(db, None);
    peer.sync_blocks_not_found = true;
    peer
}

#[tokio::test]
async fn a_peer_that_sends_no_block_in_time_is_banned_and_the_next_peer_is_tried() {
    let (db, chain) = headers_ahead_of_blocks(block_specs!(["A->GB"]), "A");
    let block = chain.get("A").unwrap();
    let (connectivity, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock = connectivity_mock.spawn();
    let mut stalling = MockSyncPeer::new(&db, None);
    stalling.sync_blocks_stall = Duration::from_secs(30);
    let (stalling_peer, _stalling_server) = connect_mock_peer(&connectivity_mock, stalling, claim_for(block)).await;
    let mut serving = MockSyncPeer::new(&db, None);
    serving.blocks_to_serve = vec![block.block().clone()];
    let (serving_peer, _serving_server) = connect_mock_peer(&connectivity_mock, serving, claim_for(block)).await;
    let config = short_deadline_config();
    let short_ban_period = config.short_ban_period;

    let timer = Instant::now();
    sync_blocks(&db, connectivity.clone(), config, vec![
        stalling_peer.clone(),
        serving_peer,
    ])
    .await
    .unwrap();
    let elapsed = timer.elapsed();

    // The budget until the first valid block is 2 x rpc_deadline
    assert!(elapsed >= Duration::from_secs(2), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(4), "{elapsed:?}");
    assert_eq!(db.get_height().unwrap(), 1);
    let banned = banned_peers(connectivity, &connectivity_mock).await;
    let [(banned_peer, ban_duration, ban_reason)] = banned.as_slice() else {
        panic!("expected one ban, got {banned:?}");
    };
    assert_eq!(banned_peer, stalling_peer.node_id());
    assert_eq!(*ban_duration, short_ban_period);
    assert!(ban_reason.contains("did not deliver a valid block"), "{ban_reason}");
}

#[tokio::test]
async fn a_peer_whose_attempts_keep_ending_without_a_block_is_banned() {
    let (db, chain) = headers_ahead_of_blocks(block_specs!(["A->GB"]), "A");
    let block = chain.get("A").unwrap();
    let (connectivity, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock = connectivity_mock.spawn();
    let peer_identity = build_node_identity(PeerFeatures::COMMUNICATION_NODE);
    let config = BlockchainSyncConfig::default();
    let short_ban_period = config.short_ban_period;
    let mut attempts_without_block = HashMap::new();

    for round in 0..3 {
        let service = not_found_peer(&db);
        let (peer, _server) = connect_mock_peer_as(
            peer_identity.clone(),
            &connectivity_mock,
            service,
            claim_with_another_tip(block),
        )
        .await;

        let err = sync_blocks_with_history(
            &db,
            connectivity.clone(),
            config.clone(),
            vec![peer],
            &mut attempts_without_block,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, BlockSyncError::NoMoreSyncPeers(_)), "{err}");
        let banned = banned_peers(connectivity.clone(), &connectivity_mock).await;
        if round < 2 {
            assert!(banned.is_empty(), "round {round}: {banned:?}");
            continue;
        }
        let [(banned_peer, ban_duration, ban_reason)] = banned.as_slice() else {
            panic!("expected one ban, got {banned:?}");
        };
        assert_eq!(banned_peer, peer_identity.node_id());
        assert_eq!(*ban_duration, short_ban_period);
        assert!(ban_reason.contains("without a block"), "{ban_reason}");
    }

    // Delivering a block resets the peer's count
    let mut serving = MockSyncPeer::new(&db, None);
    serving.blocks_to_serve = vec![block.block().clone()];
    let (peer, _server) =
        connect_mock_peer_as(peer_identity.clone(), &connectivity_mock, serving, claim_for(block)).await;
    sync_blocks_with_history(&db, connectivity, config, vec![peer], &mut attempts_without_block)
        .await
        .unwrap();
    assert!(!attempts_without_block.contains_key(peer_identity.node_id()));
}

#[tokio::test]
async fn a_peer_whose_recent_attempts_ended_without_a_block_is_tried_after_the_others() {
    let (db, chain) = headers_ahead_of_blocks(block_specs!(["A->GB"]), "A");
    let block = chain.get("A").unwrap();
    let (connectivity, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock = connectivity_mock.spawn();
    let mut stalling = MockSyncPeer::new(&db, None);
    stalling.sync_blocks_stall = Duration::from_secs(30);
    let (stalling_peer, _stalling_server) = connect_mock_peer(&connectivity_mock, stalling, claim_for(block)).await;
    let mut serving = MockSyncPeer::new(&db, None);
    serving.blocks_to_serve = vec![block.block().clone()];
    let (serving_peer, _serving_server) = connect_mock_peer(&connectivity_mock, serving, claim_for(block)).await;
    let mut attempts_without_block = HashMap::new();
    attempts_without_block.insert(stalling_peer.node_id().clone(), vec![Instant::now()]);

    let timer = Instant::now();
    sync_blocks_with_history(
        &db,
        connectivity.clone(),
        short_deadline_config(),
        vec![stalling_peer, serving_peer],
        &mut attempts_without_block,
    )
    .await
    .unwrap();

    // The stalling peer is listed first but tried last, so it is never reached
    assert!(timer.elapsed() < Duration::from_secs(1), "{:?}", timer.elapsed());
    assert_eq!(db.get_height().unwrap(), 1);
    assert!(banned_peers(connectivity, &connectivity_mock).await.is_empty());
}

#[tokio::test]
async fn a_failure_on_our_side_is_not_recorded_against_the_peer() {
    let (db, chain) = headers_ahead_of_blocks(block_specs!(["A->GB"]), "A");
    let block = chain.get("A").unwrap();
    let (connectivity, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock = connectivity_mock.spawn();
    // The block is stored locally while the peer serves it, so storing it again fails on our side
    let mut serving = MockSyncPeer::new(&db, None);
    serving.blocks_to_serve = vec![block.block().clone()];
    serving.blocks_to_add = vec![block.clone()];
    let (peer, _server) = connect_mock_peer(&connectivity_mock, serving, claim_for(block)).await;
    let mut attempts_without_block = HashMap::new();

    let err = sync_blocks_with_history(
        &db,
        connectivity.clone(),
        BlockchainSyncConfig::default(),
        vec![peer],
        &mut attempts_without_block,
    )
    .await
    .unwrap_err();

    assert!(matches!(err, BlockSyncError::NoMoreSyncPeers(_)), "{err}");
    assert!(attempts_without_block.is_empty(), "{attempts_without_block:?}");
    assert!(banned_peers(connectivity, &connectivity_mock).await.is_empty());
}

#[tokio::test]
async fn not_found_from_a_peer_whose_claim_is_below_our_header_tip_is_not_recorded() {
    let (db, chain) = headers_ahead_of_blocks(block_specs!(["A->GB"]), "A");
    let block = chain.get("A").unwrap();
    let (connectivity, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock = connectivity_mock.spawn();
    // The peer claims only as much work as our best block, which is less than our header tip
    let local = db.get_chain_metadata().unwrap();
    assert!(local.accumulated_difficulty() < block.accumulated_data().total_accumulated_difficulty);
    let claim = ChainMetadata::new(1, [9u8; 32].into(), 0, 0, local.accumulated_difficulty(), 0).unwrap();
    let (peer, _server) = connect_mock_peer(&connectivity_mock, not_found_peer(&db), claim).await;
    let mut attempts_without_block = HashMap::new();

    let err = sync_blocks_with_history(
        &db,
        connectivity.clone(),
        BlockchainSyncConfig::default(),
        vec![peer],
        &mut attempts_without_block,
    )
    .await
    .unwrap_err();

    assert!(matches!(err, BlockSyncError::NoMoreSyncPeers(_)), "{err}");
    assert!(attempts_without_block.is_empty(), "{attempts_without_block:?}");
    assert!(banned_peers(connectivity, &connectivity_mock).await.is_empty());
}

/// Builds blocks A and B as another node's main chain, and adds only their headers to a new database, so that our
/// header tip is two blocks ahead of our blocks. B is built once A is that node's tip: the test helpers only get a
/// block's MMR roots right when its parent is the tip.
fn two_headers_ahead_of_blocks() -> (BlockchainDatabase<TempDatabase>, Arc<ChainBlock>, Arc<ChainBlock>) {
    let other_node = create_new_blockchain();
    let (_, chain) = create_main_chain(&other_node, block_specs!(["A->GB"]));
    let block_a = chain.get("A").unwrap().clone();
    // "GB" names the root of the chain being built, here A
    let (_, chain) = create_chained_blocks(&other_node, block_specs!(["B->GB"]), block_a.clone());
    let block_b = chain.get("B").unwrap().clone();
    let db = create_new_blockchain();
    let headers = [&block_a, &block_b]
        .into_iter()
        .map(|block| ChainHeader::try_construct(block.header().clone(), block.accumulated_data().clone()).unwrap())
        .collect();
    db.insert_valid_headers(headers).unwrap();
    (db, block_a, block_b)
}

#[tokio::test]
async fn an_honest_peer_with_a_stronger_claim_than_our_header_tip_that_supplies_all_requested_blocks_is_not_banned() {
    let (db, chain) = headers_ahead_of_blocks(block_specs!(["A->GB"], ["B->A"]), "A");
    let block_a = chain.get("A").unwrap();
    let block_b = chain.get("B").unwrap();
    let (connectivity, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock = connectivity_mock.spawn();
    let mut serving = MockSyncPeer::new(&db, None);
    serving.blocks_to_serve = vec![block_a.block().clone()];
    let (peer, _server) = connect_mock_peer(&connectivity_mock, serving, claim_for(block_b)).await;

    sync_blocks(&db, connectivity.clone(), BlockchainSyncConfig::default(), vec![peer])
        .await
        .unwrap();

    assert_eq!(db.get_height().unwrap(), 1);
    assert!(banned_peers(connectivity, &connectivity_mock).await.is_empty());
}

#[tokio::test]
async fn a_peer_that_stops_before_our_header_tip_does_not_complete_block_sync_early() {
    let (db, block_a, _) = two_headers_ahead_of_blocks();
    let (connectivity, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock = connectivity_mock.spawn();
    let mut partial = MockSyncPeer::new(&db, None);
    partial.blocks_to_serve = vec![block_a.block().clone()];
    let (partial_peer, _partial_server) = connect_mock_peer(&connectivity_mock, partial, claim_for(&block_a)).await;

    let err = sync_blocks(&db, connectivity.clone(), BlockchainSyncConfig::default(), vec![
        partial_peer.clone(),
    ])
    .await
    .unwrap_err();

    assert!(matches!(err, BlockSyncError::NoMoreSyncPeers(_)), "{err}");
    assert_eq!(db.get_height().unwrap(), 1);
    let banned = banned_peers(connectivity, &connectivity_mock).await;
    let [(banned_peer, _, _)] = banned.as_slice() else {
        panic!("expected one ban, got {banned:?}");
    };
    assert_eq!(banned_peer, partial_peer.node_id());
}

#[tokio::test]
async fn a_peer_with_a_stronger_claim_that_stops_below_our_header_tip_is_banned_and_the_next_peer_completes() {
    let (db, block_a, block_b) = two_headers_ahead_of_blocks();
    let (connectivity, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock = connectivity_mock.spawn();
    let mut partial = MockSyncPeer::new(&db, None);
    partial.blocks_to_serve = vec![block_a.block().clone()];
    let b_difficulty = block_b.accumulated_data().total_accumulated_difficulty;
    let beyond_b = ChainMetadata::new(3, [9u8; 32].into(), 0, 0, b_difficulty + 1, 0).unwrap();
    let (partial_peer, _partial_server) = connect_mock_peer(&connectivity_mock, partial, beyond_b).await;
    // The mock serves its blocks whatever the requested start, so this peer only has what is left after A
    let mut serving = MockSyncPeer::new(&db, None);
    serving.blocks_to_serve = vec![block_b.block().clone()];
    let (serving_peer, _serving_server) = connect_mock_peer(&connectivity_mock, serving, claim_for(&block_b)).await;
    let config = BlockchainSyncConfig::default();
    let short_ban_period = config.short_ban_period;

    sync_blocks(&db, connectivity.clone(), config, vec![
        partial_peer.clone(),
        serving_peer,
    ])
    .await
    .unwrap();

    assert_eq!(db.get_height().unwrap(), 2);
    let banned = banned_peers(connectivity, &connectivity_mock).await;
    let [(banned_peer, ban_duration, ban_reason)] = banned.as_slice() else {
        panic!("expected one ban, got {banned:?}");
    };
    assert_eq!(banned_peer, partial_peer.node_id());
    assert_eq!(*ban_duration, short_ban_period);
    assert!(
        ban_reason.contains("did not supply all the requested blocks"),
        "{ban_reason}"
    );
}

#[test]
fn only_failures_the_peer_caused_are_recorded() {
    let busy = [
        RpcError::HandshakeError(RpcHandshakeError::Rejected(
            HandshakeRejectReason::NoServerSessionsAvailable("full"),
        )),
        RpcError::HandshakeError(RpcHandshakeError::Rejected(
            HandshakeRejectReason::NoClientSessionsAvailable("full"),
        )),
    ];
    for err in busy {
        assert!(!rpc_setup_failure_is_peer_caused(&err), "{err}");
    }
    assert!(rpc_setup_failure_is_peer_caused(&RpcError::ReplyTimeout));

    let our_ban =
        BlockSyncError::ConnectivityError(ConnectivityError::ConnectionFailed(ConnectionManagerError::PeerBanned));
    assert!(!dial_failure_is_peer_caused(&our_ban));
    let unreachable = BlockSyncError::ConnectivityError(ConnectivityError::ConnectionFailed(
        ConnectionManagerError::DialConnectFailedAllAddresses,
    ));
    assert!(dial_failure_is_peer_caused(&unreachable));
}

/// Builds blocks A and B where B is a Cuckaroo (`C29`) block under rules with
/// `!include_c29_accumulated_difficulty_into_total()`, so B leaves `total_accumulated_difficulty` equal to A's.
fn equal_difficulty_c29_headers_ahead_of_blocks() -> (BlockchainDatabase<TempDatabase>, Arc<ChainBlock>, Arc<ChainBlock>)
{
    let without_c29 = ConsensusConstantsBuilder::new(Network::LocalNet)
        .with_consensus_constants(ConsensusConstants::esmeralda().swap_remove(0))
        .with_effective_from_height(0)
        .build();
    assert!(!without_c29.include_c29_accumulated_difficulty_into_total());
    let rules = BaseNodeConsensusManager::builder(Network::LocalNet)
        .add_consensus_constants(without_c29.clone())
        .build()
        .unwrap();

    let other_node = create_custom_blockchain(rules.clone());
    let (_, chain) = create_main_chain(&other_node, block_specs!(["A->GB"]));
    let block_a = chain.get("A").unwrap().clone();
    let (_, chain) = create_chained_blocks(&other_node, block_specs!(["B->GB"]), block_a.clone());
    let raw_b_chain = chain.get("B").unwrap().clone();

    let mut raw_b = raw_b_chain.block().clone();
    raw_b.header.pow.pow_algo = PowAlgorithm::Cuckaroo;
    let b_accum = BlockHeaderAccumulatedDataBuilder::from_previous(block_a.accumulated_data())
        .with_hash(raw_b.hash())
        .with_achieved_target_difficulty(
            AchievedTargetDifficulty::try_construct(
                PowAlgorithm::Cuckaroo,
                Difficulty::min(),
                Difficulty::min(),
                Difficulty::min(),
            )
            .unwrap(),
        )
        .with_total_kernel_offset(raw_b.header.total_kernel_offset.clone())
        .build(&without_c29)
        .unwrap();
    let block_b = Arc::new(ChainBlock::try_construct(Arc::new(raw_b), b_accum).unwrap());
    assert_eq!(
        block_b.accumulated_data().total_accumulated_difficulty,
        block_a.accumulated_data().total_accumulated_difficulty
    );
    assert!(
        block_b.accumulated_data().accumulated_cuckaroo_difficulty >
            block_a.accumulated_data().accumulated_cuckaroo_difficulty
    );

    let db = create_custom_blockchain(rules);
    let headers = [&block_a, &block_b]
        .into_iter()
        .map(|block| ChainHeader::try_construct(block.header().clone(), block.accumulated_data().clone()).unwrap())
        .collect();
    db.insert_valid_headers(headers).unwrap();
    (db, block_a, block_b)
}

#[tokio::test]
async fn partial_stream_ending_before_c29_zero_added_difficulty_tip_is_rejected_and_retried() {
    let (db, block_a, block_b) = equal_difficulty_c29_headers_ahead_of_blocks();
    let (connectivity, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock = connectivity_mock.spawn();

    // First peer stops at A (whose total_accumulated_difficulty already equals B's)
    let mut partial = MockSyncPeer::new(&db, None);
    partial.blocks_to_serve = vec![block_a.block().clone()];
    let (partial_peer, _partial_server) = connect_mock_peer(&connectivity_mock, partial, claim_for(&block_b)).await;

    // Second peer serves the missing C29 tip block B
    let mut serving = MockSyncPeer::new(&db, None);
    serving.blocks_to_serve = vec![block_b.block().clone()];
    let (serving_peer, _serving_server) = connect_mock_peer(&connectivity_mock, serving, claim_for(&block_b)).await;

    let config = BlockchainSyncConfig::default();
    let short_ban_period = config.short_ban_period;

    sync_blocks(&db, connectivity.clone(), config.clone(), vec![
        partial_peer.clone(),
        serving_peer,
    ])
    .await
    .unwrap();

    assert_eq!(db.get_height().unwrap(), 2);
    assert_eq!(db.get_chain_metadata().unwrap().best_block_hash(), block_b.hash());
    let banned = banned_peers(connectivity.clone(), &connectivity_mock).await;
    let [(banned_peer, ban_duration, ban_reason)] = banned.as_slice() else {
        panic!("expected one ban, got {banned:?}");
    };
    assert_eq!(banned_peer, partial_peer.node_id());
    assert_eq!(*ban_duration, short_ban_period);
    assert!(
        ban_reason.contains("did not supply all the requested blocks"),
        "{ban_reason}"
    );

    // Also verify the 0-block empty-stream case when best_block is already at parent A and header B is ahead
    let without_c29 = ConsensusConstantsBuilder::new(Network::LocalNet)
        .with_consensus_constants(ConsensusConstants::esmeralda().swap_remove(0))
        .with_effective_from_height(0)
        .build();
    let rules = BaseNodeConsensusManager::builder(Network::LocalNet)
        .add_consensus_constants(without_c29)
        .build()
        .unwrap();
    let db_at_a = create_custom_blockchain(rules);
    db_at_a.add_block(block_a.to_arc_block()).unwrap();
    let header_b = ChainHeader::try_construct(block_b.header().clone(), block_b.accumulated_data().clone()).unwrap();
    db_at_a.insert_valid_headers(vec![header_b]).unwrap();
    assert_eq!(db_at_a.get_height().unwrap(), 1);
    assert_eq!(db_at_a.fetch_last_chain_header().unwrap().height(), 2);

    let empty_stream = MockSyncPeer::new(&db_at_a, None);
    let (empty_peer, _empty_server) = connect_mock_peer(&connectivity_mock, empty_stream, claim_for(&block_b)).await;

    let err = sync_blocks(&db_at_a, connectivity.clone(), config, vec![empty_peer.clone()])
        .await
        .unwrap_err();
    assert!(matches!(err, BlockSyncError::NoMoreSyncPeers(_)), "{err}");
    assert_eq!(db_at_a.get_height().unwrap(), 1);
    let banned = banned_peers(connectivity, &connectivity_mock).await;
    let [(banned_peer, ban_duration, ban_reason)] = banned.as_slice() else {
        panic!("expected one ban for empty stream, got {banned:?}");
    };
    assert_eq!(banned_peer, empty_peer.node_id());
    assert_eq!(*ban_duration, short_ban_period);
    assert!(
        ban_reason.contains("did not supply all the requested blocks"),
        "{ban_reason}"
    );
}

#[tokio::test]
async fn not_found_from_a_peer_at_parent_of_equal_difficulty_c29_tip_is_not_recorded() {
    let (db, block_a, _block_b) = equal_difficulty_c29_headers_ahead_of_blocks();
    let (connectivity, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock = connectivity_mock.spawn();
    let peer_identity = build_node_identity(PeerFeatures::COMMUNICATION_NODE);
    let mut attempts_without_block = HashMap::new();

    // Peer honestly claims parent A (height 1), which has equal total_accumulated_difficulty to C29 tip B (height 2)
    for _round in 0..3 {
        let (peer, _server) = connect_mock_peer_as(
            peer_identity.clone(),
            &connectivity_mock,
            not_found_peer(&db),
            claim_for(&block_a),
        )
        .await;

        let err = sync_blocks_with_history(
            &db,
            connectivity.clone(),
            BlockchainSyncConfig::default(),
            vec![peer],
            &mut attempts_without_block,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, BlockSyncError::NoMoreSyncPeers(_)), "{err}");
        assert!(attempts_without_block.is_empty(), "{attempts_without_block:?}");
        assert!(banned_peers(connectivity.clone(), &connectivity_mock).await.is_empty());
    }
}

/// Builds a `count`-block main chain using `RevealedValue` range proofs on a scratch node and inserts only the valid
/// headers into a fresh local database so block sync can stream and validate slices across multiple rounds.
fn chain_headers_ahead_of_blocks(count: usize) -> (BlockchainDatabase<TempDatabase>, Vec<Arc<ChainBlock>>) {
    let other_node = create_new_blockchain();
    let mut prev = Arc::new(other_node.fetch_block(0, true).unwrap().try_into_chain_block().unwrap());
    let mut chain_blocks = Vec::with_capacity(count);
    for _ in 0..count {
        let (_, map) = create_chained_blocks_with_range_proof_type(
            &other_node,
            block_specs!(["N->GB"]),
            prev,
            Some(RangeProofType::RevealedValue),
        );
        let next = map.get("N").unwrap().clone();
        other_node.add_block(next.to_arc_block()).unwrap();
        chain_blocks.push(next.clone());
        prev = next;
    }

    let db = create_new_blockchain();
    let headers = chain_blocks
        .iter()
        .map(|block| ChainHeader::try_construct(block.header().clone(), block.accumulated_data().clone()).unwrap())
        .collect();
    db.insert_valid_headers(headers).unwrap();
    (db, chain_blocks)
}

struct StreamingChainPeer {
    genesis_hash: Vec<u8>,
    chain: Vec<Arc<ChainBlock>>,
    per_block_delay: Duration,
}

#[tari_comms::async_trait]
impl BaseNodeSyncService for StreamingChainPeer {
    async fn sync_blocks(
        &self,
        request: Request<SyncBlocksRequest>,
    ) -> Result<Streaming<proto::base_node::BlockBodyResponse>, RpcStatus> {
        let message = request.into_message();
        let start_idx = if message.start_hash == self.genesis_hash {
            0
        } else {
            self.chain
                .iter()
                .position(|b| b.hash().as_slice() == message.start_hash.as_slice())
                .map(|i| i.saturating_add(1))
                .ok_or_else(|| RpcStatus::not_found("start hash not found"))?
        };
        let end_idx = self
            .chain
            .iter()
            .position(|b| b.hash().as_slice() == message.end_hash.as_slice())
            .ok_or_else(|| RpcStatus::not_found("end hash not found"))?;
        let slice = self
            .chain
            .get(start_idx..=end_idx)
            .ok_or_else(|| RpcStatus::bad_request("start after end"))?
            .to_vec();
        let delay = self.per_block_delay;
        let (tx, rx) = mpsc::channel(slice.len().saturating_add(1));
        tokio::spawn(async move {
            for block in slice {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let response = proto::base_node::BlockBodyResponse::try_from(block.block().clone()).unwrap();
                if tx.send(Ok(response)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Streaming::new(rx))
    }

    async fn sync_headers(
        &self,
        _: Request<SyncHeadersRequest>,
    ) -> Result<Streaming<proto::core::BlockHeader>, RpcStatus> {
        Err(RpcStatus::not_implemented("mock"))
    }

    async fn get_header_by_height(&self, _: Request<u64>) -> Result<Response<proto::core::BlockHeader>, RpcStatus> {
        Err(RpcStatus::not_implemented("mock"))
    }

    async fn find_chain_split(
        &self,
        _: Request<FindChainSplitRequest>,
    ) -> Result<Response<FindChainSplitResponse>, RpcStatus> {
        Err(RpcStatus::not_implemented("mock"))
    }

    async fn get_chain_metadata(&self, _: Request<()>) -> Result<Response<proto::base_node::ChainMetadata>, RpcStatus> {
        Err(RpcStatus::not_implemented("mock"))
    }

    async fn sync_kernels(
        &self,
        _: Request<SyncKernelsRequest>,
    ) -> Result<Streaming<proto::types::TransactionKernel>, RpcStatus> {
        Err(RpcStatus::not_implemented("mock"))
    }

    async fn sync_utxos(&self, _: Request<SyncUtxosRequest>) -> Result<Streaming<SyncUtxosResponse>, RpcStatus> {
        Err(RpcStatus::not_implemented("mock"))
    }
}

async fn connect_streaming_peer(
    connectivity_mock: &ConnectivityManagerMockState,
    service: StreamingChainPeer,
    claim: ChainMetadata,
) -> (SyncPeer, MockRpcServer<BaseNodeSyncRpcServer<StreamingChainPeer>>) {
    let peer_identity = build_node_identity(PeerFeatures::COMMUNICATION_NODE);
    let server = BaseNodeSyncRpcServer::new(service);
    let protocol_name = server.as_protocol_name();
    let mut mock_server = MockRpcServer::new(server, peer_identity.clone());
    mock_server.serve();
    let conn = mock_server
        .create_connection(peer_identity.to_peer(), protocol_name.into())
        .await;
    connectivity_mock.add_active_connection(conn).await;
    let sync_peer = SyncPeer::from(PeerChainMetadata::new(peer_identity.node_id().clone(), claim, None));
    (sync_peer, mock_server)
}

#[tokio::test]
async fn slow_peers_are_retried_with_increased_max_latency_without_being_banned() {
    let (db, chain_blocks) = chain_headers_ahead_of_blocks(15);
    let genesis_hash = db.fetch_chain_header(0).unwrap().hash().to_vec();
    let tip_claim = claim_for(chain_blocks.last().unwrap());
    let (connectivity, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock = connectivity_mock.spawn();

    let (peer_a, _server_a) = connect_streaming_peer(
        &connectivity_mock,
        StreamingChainPeer {
            genesis_hash: genesis_hash.clone(),
            chain: chain_blocks.clone(),
            per_block_delay: Duration::from_millis(20),
        },
        tip_claim.clone(),
    )
    .await;
    let (peer_b, _server_b) = connect_streaming_peer(
        &connectivity_mock,
        StreamingChainPeer {
            genesis_hash,
            chain: chain_blocks,
            per_block_delay: Duration::from_millis(20),
        },
        tip_claim,
    )
    .await;

    // Round 1 exceeds `initial_max_sync_latency` (1ms) on both peers after 5 blocks each (reaching height 10);
    // backoff raises `max_latency` by 2s without banning either peer, and Round 2 streams the final 5 blocks to 15.
    let config = BlockchainSyncConfig {
        initial_max_sync_latency: Duration::from_millis(1),
        max_latency_increase: Duration::from_secs(2),
        ..Default::default()
    };
    let mut sync_peers = vec![peer_a, peer_b];
    let mut attempts_without_block = HashMap::new();
    let mut synchronizer = BlockSynchronizer::new(
        config,
        db.clone().into(),
        connectivity.clone(),
        &mut sync_peers,
        Arc::new(MockValidator::new(true)),
        &mut attempts_without_block,
    );
    synchronizer.synchronize().await.unwrap();

    assert_eq!(db.get_height().unwrap(), 15);
    assert!(banned_peers(connectivity, &connectivity_mock).await.is_empty());
    assert_eq!(sync_peers.len(), 2);
    for peer in &sync_peers {
        assert!(!peer.connection().unwrap().is_strong());
        assert!(peer.calc_avg_latency().is_some());
        assert!(peer.latency().unwrap() > Duration::from_millis(1));
    }
}

#[tokio::test]
async fn slow_peers_are_short_banned_when_latency_backoff_aborts() {
    // 1. Single slow peer (`sync_peers.len() < 2`) aborts immediately and issues a short ban
    let (db_single, chain_single) = chain_headers_ahead_of_blocks(6);
    let genesis_hash_single = db_single.fetch_chain_header(0).unwrap().hash().to_vec();
    let tip_single_claim = claim_for(chain_single.last().unwrap());
    let (connectivity, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock = connectivity_mock.spawn();

    let (slow_single, _server_single) = connect_streaming_peer(
        &connectivity_mock,
        StreamingChainPeer {
            genesis_hash: genesis_hash_single,
            chain: chain_single,
            per_block_delay: Duration::from_millis(15),
        },
        tip_single_claim,
    )
    .await;
    let single_node_id = slow_single.node_id().clone();
    let config = BlockchainSyncConfig {
        initial_max_sync_latency: Duration::from_micros(100),
        max_latency_increase: Duration::from_micros(100),
        ..Default::default()
    };
    let short_ban_period = config.short_ban_period;
    let mut single_peers = vec![slow_single];
    let mut attempts_without_block = HashMap::new();
    let mut synchronizer = BlockSynchronizer::new(
        config.clone(),
        db_single.clone().into(),
        connectivity.clone(),
        &mut single_peers,
        Arc::new(MockValidator::new(true)),
        &mut attempts_without_block,
    );
    let err = synchronizer.synchronize().await.unwrap_err();
    assert!(matches!(err, BlockSyncError::AllSyncPeersExceedLatency), "{err}");
    assert!(single_peers.is_empty());
    let banned = banned_peers(connectivity.clone(), &connectivity_mock).await;
    let [(banned_peer, ban_duration, ban_reason)] = banned.as_slice() else {
        panic!("expected one short ban on <2 slow-peer abort, got {banned:?}");
    };
    assert_eq!(*banned_peer, single_node_id);
    assert_eq!(*ban_duration, short_ban_period);
    assert!(
        ban_reason.contains("exceeded maximum permitted sync latency"),
        "{ban_reason}"
    );

    // 2. Two slow peers exhausting all `MAX_LATENCY_INCREASES` (5 increases = 6 rounds * 10 blocks = 60 blocks)
    // issue short bans for both slow peers when backoff gives up.
    let (db_pair, chain_pair) = chain_headers_ahead_of_blocks(62);
    let genesis_hash_pair = db_pair.fetch_chain_header(0).unwrap().hash().to_vec();
    let tip_pair_claim = claim_for(chain_pair.last().unwrap());
    let (slow_a, _server_a) = connect_streaming_peer(
        &connectivity_mock,
        StreamingChainPeer {
            genesis_hash: genesis_hash_pair.clone(),
            chain: chain_pair.clone(),
            per_block_delay: Duration::from_millis(5),
        },
        tip_pair_claim.clone(),
    )
    .await;
    let (slow_b, _server_b) = connect_streaming_peer(
        &connectivity_mock,
        StreamingChainPeer {
            genesis_hash: genesis_hash_pair,
            chain: chain_pair,
            per_block_delay: Duration::from_millis(5),
        },
        tip_pair_claim,
    )
    .await;
    let slow_a_id = slow_a.node_id().clone();
    let slow_b_id = slow_b.node_id().clone();
    let mut pair_peers = vec![slow_a, slow_b];
    let mut synchronizer = BlockSynchronizer::new(
        config,
        db_pair.clone().into(),
        connectivity.clone(),
        &mut pair_peers,
        Arc::new(MockValidator::new(true)),
        &mut attempts_without_block,
    );
    let err = synchronizer.synchronize().await.unwrap_err();
    assert!(matches!(err, BlockSyncError::AllSyncPeersExceedLatency), "{err}");
    assert_eq!(db_pair.get_height().unwrap(), 60);
    assert!(pair_peers.is_empty());
    let banned = banned_peers(connectivity, &connectivity_mock).await;
    assert_eq!(banned.len(), 2, "{banned:?}");
    assert!(
        banned
            .iter()
            .any(|(id, dur, _)| *id == slow_a_id && *dur == short_ban_period)
    );
    assert!(
        banned
            .iter()
            .any(|(id, dur, _)| *id == slow_b_id && *dur == short_ban_period)
    );
}

#[tokio::test]
async fn duplicate_sync_peer_entries_are_deduplicated_and_removed_cleanly() {
    let (db, chain) = headers_ahead_of_blocks(block_specs!(["A->GB"]), "A");
    let block = chain.get("A").unwrap();
    let (connectivity, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock = connectivity_mock.spawn();
    let (peer, _server) =
        connect_mock_peer(&connectivity_mock, not_found_peer(&db), claim_with_another_tip(block)).await;
    let peer_id = peer.node_id().clone();

    let mut sync_peers = vec![peer.clone(), peer.clone(), peer];
    let mut attempts_without_block = HashMap::new();
    let mut synchronizer = BlockSynchronizer::new(
        BlockchainSyncConfig::default(),
        db.clone().into(),
        connectivity.clone(),
        &mut sync_peers,
        Arc::new(MockValidator::new(true)),
        &mut attempts_without_block,
    );
    let err = synchronizer.synchronize().await.unwrap_err();

    assert!(matches!(err, BlockSyncError::NoMoreSyncPeers(_)), "{err}");
    assert!(sync_peers.is_empty());
    assert_eq!(attempts_without_block.get(&peer_id).map(Vec::len), Some(1));
    assert!(banned_peers(connectivity, &connectivity_mock).await.is_empty());
}
