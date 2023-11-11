use lru::LruCache;
use std::net::{SocketAddr, ToSocketAddrs};
use std::num::NonZeroUsize;
use std::thread;
use std::time::Duration;

use crate::common::{Id, Node};
use crate::messages::{
    FindNodeRequestArguments, FindNodeResponseArguments, GetPeersResponseArguments, Message,
    MessageType, PingRequestArguments, PingResponseArguments, RequestSpecific, ResponseSpecific,
};

use crate::query::Query;
use crate::routing_table::RoutingTable;
use crate::socket::KrpcSocket;
use crate::Result;

const TICK_INTERVAL: Duration = Duration::from_millis(15);
const QUERIES_CACHE_SIZE: usize = 1000;
const DEFAULT_BOOTSTRAP_NODES: [&str; 8] = [
    "dht.transmissionbt.com:6881",
    "dht.libtorrent.org:25401", // @arvidn's
    "router.bittorrent.com:6881",
    "router.bittorrent.cloud:42069", // Seems to be read-only.
    "router.utorrent.com:6881",
    "dht.aelitis.com:6881",   // Vuze doesn't respond in home network.
    "router.silotis.us:6881", // IPv6
    "dht.anacrolix.link:42069",
];

#[derive(Debug)]
pub struct Rpc {
    socket: KrpcSocket,
    routing_table: RoutingTable,
    queries: LruCache<Id, Query>,

    // Options
    id: Id,
    interval: Duration,
    bootstrap: Vec<String>,
}

impl Rpc {
    pub fn new() -> Result<Self> {
        // TODO: One day I might implement BEP42.
        let id = Id::random();

        let socket = KrpcSocket::new()?;

        Ok(Rpc {
            id,
            bootstrap: DEFAULT_BOOTSTRAP_NODES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            interval: TICK_INTERVAL,

            socket,
            routing_table: RoutingTable::new().with_id(id),
            queries: LruCache::new(NonZeroUsize::new(QUERIES_CACHE_SIZE).unwrap()),
        })
    }

    // === Options ===

    pub fn with_id(mut self, id: Id) -> Self {
        self.id = id;
        self
    }

    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.socket.read_only = read_only;
        self
    }

    pub fn with_bootstrap(mut self, bootstrap: Vec<String>) -> Self {
        self.bootstrap = bootstrap;
        self
    }

    pub fn with_interval(mut self, interval: u64) -> Self {
        self.interval = Duration::from_millis(interval);
        self
    }

    /// Sets requests timeout in milliseconds
    pub fn with_request_timout(mut self, timeout: u64) -> Self {
        self.socket.request_timeout = Duration::from_millis(timeout);
        self
    }

    /// Returns the address the server is listening to.
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr()
    }

    // === Public Methods ===

    pub fn tick(&mut self) {
        // === Bootstrapping ===
        self.populate();

        if let Some((message, from)) = self.socket.recv_from() {
            self.add_node(&message, from);

            match &message.message_type {
                MessageType::Request(request_specific) => {
                    self.handle_request(from, message.transaction_id, request_specific);
                }
                MessageType::Response(response_specific) => {
                    self.handle_response(from, &message);
                }
                MessageType::Error(_) => {
                    // TODO: Handle error messages!
                }
            }
        };

        // === Refresh queries ===
        for (_, query) in self.queries.iter_mut() {
            query.tick(&mut self.socket);
        }

        thread::sleep(self.interval);
    }

    pub fn ping(&mut self, address: SocketAddr) -> u16 {
        self.socket.request(
            address,
            RequestSpecific::Ping(PingRequestArguments {
                requester_id: self.id,
            }),
        )
    }

    pub fn find_node(&mut self, address: SocketAddr, target: Id) -> u16 {
        self.socket.request(
            address,
            RequestSpecific::FindNode(FindNodeRequestArguments {
                target,
                requester_id: self.id,
            }),
        )
    }

    /// Send a message to closer and closer nodes until we can't find any more nodes.
    pub fn query(&mut self, target: Id, request: RequestSpecific) {
        // If query exists and it's set to done, restart it.
        if let Some(query) = self.queries.get_mut(&target) {
            if query.is_done() {
                query.start(&mut self.socket);
            }
            return;
        }

        let mut query = Query::new(target, request);

        let closest = self.routing_table.closest(&target);

        // If we don't have enough or any closest nodes, call the bootstraping nodes.
        if closest.is_empty() || closest.len() < self.bootstrap.len() {
            for bootstrapping_node in self.bootstrap.clone() {
                if let Ok(addresses) = bootstrapping_node.to_socket_addrs() {
                    for address in addresses {
                        query.visit(&mut self.socket, address);
                    }
                }
            }
        } else {
            // Seed this query with the closest nodes we know about.
            for node in closest {
                query.add(node)
            }

            // After adding the nodes, we need to start the query.
            query.start(&mut self.socket);
        }

        self.queries.put(target, query);
    }

    // === Private Methods ===

    /// Ping bootstrap nodes, add them to the routing table with closest query.
    fn populate(&mut self) {
        if !self.routing_table.is_empty() {
            // No need for populating. Already called our bootstrap nodes?
            return;
        }

        // Start or restart the query.
        self.query(
            self.id,
            RequestSpecific::FindNode(FindNodeRequestArguments {
                target: self.id,
                requester_id: self.id,
            }),
        );
    }

    /// Return a boolean indicating whether the bootstrapping query is done.
    fn is_ready(&mut self) -> bool {
        return if let Some(query) = self.queries.get(&self.id) {
            query.is_done()
        } else {
            false
        };
    }

    fn handle_request(&mut self, from: SocketAddr, transaction_id: u16, request: &RequestSpecific) {
        match request {
            // TODO: Handle bad requests (send an error message).
            RequestSpecific::Ping(PingRequestArguments { requester_id }) => {
                self.socket.response(
                    from,
                    transaction_id,
                    ResponseSpecific::Ping(PingResponseArguments {
                        responder_id: self.id,
                    }),
                );
            }
            RequestSpecific::FindNode(FindNodeRequestArguments {
                target,
                requester_id,
            }) => {
                self.socket.response(
                    from,
                    transaction_id,
                    ResponseSpecific::FindNode(FindNodeResponseArguments {
                        responder_id: self.id,
                        nodes: self.routing_table.closest(target),
                    }),
                );
            }
            _ => {
                // TODO: Handle queries (stuff with closer nodes in the response).
                // TODO: Send error message?
                // TODO: How to deal with unknown requests?
                // TODO: should we rsepond with FindNodeResponse anyways?
                todo!()
            }
        }
    }

    fn handle_response(&mut self, from: SocketAddr, message: &Message) {
        if (message.read_only) {
            return;
        }

        // Get corresponing query for message.transaction_id
        if let Some(query) = self.queries.iter_mut().find_map(|(_, query)| {
            if query.remove_inflight_request(message.transaction_id) {
                return Some(query);
            }
            None
        }) {
            if let Some(nodes) = message.get_closer_nodes() {
                query.add_candidates(nodes);
            }

            match &message.message_type {
                MessageType::Response(ResponseSpecific::GetPeers(GetPeersResponseArguments {
                    responder_id,
                    token,
                    values,
                    ..
                })) => {
                    if let Some(peers) = values {
                        println!(
                            "Got get peers response from: {:?}, values: {:?} version: {:?}\n",
                            from, values, message.version
                        )
                    };
                }
                // Ping response is already handled in add_node()
                // FindNode response is alreadh handled in query.add_candidates()
                _ => {}
            }
        }
    }

    fn add_node(&mut self, message: &Message, from: SocketAddr) {
        if message.read_only {
            return;
        }

        if let Some(id) = message.get_author_id() {
            self.routing_table.add(Node::new(id, from));
        }
    }
}

#[cfg(test)]
mod test {
    use crate::messages::GetPeersRequestArguments;

    use super::*;
    use std::{convert::TryInto, time::Instant};

    fn testnet(n: usize) -> Vec<String> {
        let mut bootstrap: Vec<String> = Vec::with_capacity(1);

        for i in 0..n {
            let mut rpc = Rpc::new().unwrap();

            if i > 0 {
                rpc = rpc.with_bootstrap(bootstrap.clone());
            } else {
                rpc = rpc.with_bootstrap(vec![]);
                let _ = &bootstrap.push(format!("0.0.0.0:{}", rpc.local_addr().port()));
            }

            thread::spawn(move || loop {
                rpc.tick();
            });
        }

        bootstrap
    }

    #[test]
    fn bootstrap() {
        let bootstrap = testnet(50);

        // Wait for nodes to connect to each other.
        thread::sleep(Duration::from_secs(2));

        let mut client = Rpc::new().unwrap().with_bootstrap(bootstrap);

        let client_thread = thread::spawn(move || loop {
            client.tick();

            if client.is_ready() {
                assert!(client.routing_table.closest(&client.id).len() >= 20);
                break;
            }
        });

        client_thread.join().unwrap();
    }

    // Live tests that shouldn't run in CI etc.

    // #[test]
    fn live_bootstrap() {
        let mut client = Rpc::new().unwrap();

        let client_thread = thread::spawn(move || loop {
            client.tick();

            if client.is_ready() {
                assert!(client.routing_table.closest(&client.id).len() >= 20);
                break;
            }
        });

        client_thread.join().unwrap();
    }

    // #[test]
    fn live_get_peers() {
        let mut client = Rpc::new().unwrap().with_read_only(true);

        let target: Id = "13cdea75c1fc002d24eec080f4ba93f2892a62f9"
            .try_into()
            .unwrap();

        let start = Instant::now();

        client.query(
            target,
            RequestSpecific::GetPeers(GetPeersRequestArguments {
                info_hash: target,
                requester_id: client.id,
            }),
        );

        let client_thread = thread::spawn(move || loop {
            client.tick();
            if let Some(query) = client.queries.get(&target) {
                if query.is_done() {
                    dbg!(query);

                    break;
                }
            }
        });

        client_thread.join().unwrap();
    }
}
