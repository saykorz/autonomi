// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::Marker;
use ant_networking::time::Instant;
#[cfg(feature = "open-metrics")]
use ant_networking::MetricsRegistries;
use ant_protocol::storage::DataTypes;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{
        counter::Counter,
        family::Family,
        gauge::Gauge,
        histogram::{exponential_buckets, Histogram},
        info::Info,
    },
};

#[derive(Clone)]
/// The shared recorders that are used to record metrics.
pub(crate) struct NodeMetricsRecorder {
    /// put record
    put_record_ok: Family<PutRecordOk, Counter>,
    put_record_err: Counter,

    /// replication
    replication_triggered: Counter,
    replication_keys_to_fetch: Histogram,

    // routing table
    peer_added_to_routing_table: Counter,
    peer_removed_from_routing_table: Counter,

    // wallet
    pub(crate) current_reward_wallet_balance: Gauge,
    pub(crate) _total_forwarded_rewards: Gauge,

    // to track the uptime of the node.
    pub(crate) started_instant: Instant,
    pub(crate) uptime: Gauge,
}

#[derive(EncodeLabelSet, Hash, Clone, Eq, PartialEq, Debug)]
struct PutRecordOk {
    record_type: DataTypes,
}

impl NodeMetricsRecorder {
    pub(crate) fn new(registries: &mut MetricsRegistries) -> Self {
        let node_metadata_sub_registry = registries.metadata.sub_registry_with_prefix("ant_node");
        node_metadata_sub_registry.register(
            "antnode_version",
            "The version of the safe node",
            Info::new(vec![(
                "antnode_version".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
            )]),
        );

        let sub_registry = registries
            .standard_metrics
            .sub_registry_with_prefix("ant_node");

        let put_record_ok = Family::default();
        sub_registry.register(
            "put_record_ok",
            "Number of successful record PUTs",
            put_record_ok.clone(),
        );
        let put_record_err = Counter::default();
        sub_registry.register(
            "put_record_err",
            "Number of errors during record PUTs",
            put_record_err.clone(),
        );

        let replication_triggered = Counter::default();
        sub_registry.register(
            "replication_triggered",
            "Number of time that replication has been triggered",
            replication_triggered.clone(),
        );

        // Currently MAX_PARALLEL_FETCH = 2*CLOSE_GROUP_SIZE
        let replication_keys_to_fetch = Histogram::new(exponential_buckets(1.0, 2.0, 4));
        sub_registry.register(
            "replication_keys_to_fetch",
            "Number of replication keys to fetch from the network",
            replication_keys_to_fetch.clone(),
        );

        let peer_added_to_routing_table = Counter::default();
        sub_registry.register(
            "peer_added_to_routing_table",
            "Number of peers that have been added to the Routing Table",
            peer_added_to_routing_table.clone(),
        );

        let peer_removed_from_routing_table = Counter::default();
        sub_registry.register(
            "peer_removed_from_routing_table",
            "Number of peers that have been removed from the Routing Table",
            peer_removed_from_routing_table.clone(),
        );

        let current_reward_wallet_balance = Gauge::default();
        sub_registry.register(
            "current_reward_wallet_balance",
            "The number of Nanos in the node reward wallet",
            current_reward_wallet_balance.clone(),
        );

        let total_forwarded_rewards = Gauge::default();
        sub_registry.register(
            "total_forwarded_rewards",
            "The cumulative number of Nanos forwarded by the node",
            total_forwarded_rewards.clone(),
        );

        let uptime = Gauge::default();
        sub_registry.register(
            "uptime",
            "The uptime of the node in seconds",
            uptime.clone(),
        );

        Self {
            put_record_ok,
            put_record_err,
            replication_triggered,
            replication_keys_to_fetch,
            peer_added_to_routing_table,
            peer_removed_from_routing_table,
            current_reward_wallet_balance,
            _total_forwarded_rewards: total_forwarded_rewards,
            started_instant: Instant::now(),
            uptime,
        }
    }

    // Records the metric
    pub(crate) fn record(&self, log_marker: Marker) {
        match log_marker {
            Marker::ValidChunkRecordPutFromNetwork(_) => {
                let _ = self
                    .put_record_ok
                    .get_or_create(&PutRecordOk {
                        record_type: DataTypes::Chunk,
                    })
                    .inc();
            }

            Marker::ValidGraphEntryRecordPutFromNetwork(_) => {
                let _ = self
                    .put_record_ok
                    .get_or_create(&PutRecordOk {
                        record_type: DataTypes::GraphEntry,
                    })
                    .inc();
            }

            Marker::RecordRejected(_, _) => {
                let _ = self.put_record_err.inc();
            }

            Marker::IntervalReplicationTriggered => {
                let _ = self.replication_triggered.inc();
            }

            Marker::FetchingKeysForReplication { fetching_keys_len } => self
                .replication_keys_to_fetch
                .observe(fetching_keys_len as f64),

            Marker::PeerAddedToRoutingTable(_) => {
                let _ = self.peer_added_to_routing_table.inc();
            }

            Marker::PeerRemovedFromRoutingTable(_) => {
                let _ = self.peer_removed_from_routing_table.inc();
            }

            _ => {}
        }
    }
}
