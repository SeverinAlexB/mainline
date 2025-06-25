//! UDP socket layer managing incoming/outgoing requests and responses.
use super::config::Config;
use crate::common::{ErrorSpecific, Message, MessageType, RequestSpecific, ResponseSpecific};
use std::cmp::Ordering;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};
use tracing::{debug, error, trace};

const VERSION: [u8; 4] = [82, 83, 0, 5]; // "RS" version 05
/// Maximum MTU size for a received UDP packet.
const MAX_MTU: usize = 2048;

pub const DEFAULT_PORT: u16 = 6881;
/// Default request timeout before abandoning an inflight request to a non-responding node.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_millis(2000); // 2 seconds
/// Socket read timeout that is used to avoid blocking the main thread.
pub const READ_TIMEOUT: Duration = Duration::from_millis(10);

/// Transaction ID is used to correlate requests and responses.
/// It is incremented by 1 for each request.
/// It is wrapped around to 0 when it reaches 65535.
pub type TransactionId = u16;

/// Helper struct to track inflight requests
/// to correlate requests and responses.
#[derive(Debug)]
struct InflightRequest {
    tid: TransactionId,
    to: SocketAddrV4,
    sent_at: Instant,
}

impl InflightRequest {
    fn new(tid: TransactionId, to: SocketAddrV4) -> Self {
        Self {
            tid,
            to,
            sent_at: Instant::now(),
        }
    }
}

/// A UdpSocket wrapper that formats and correlates DHT requests and responses.
#[derive(Debug)]
pub struct KrpcSocket {
    /// Counter for the transaction_id.
    /// This is used to generate a unique transaction_id for each request.
    /// It is incremented by 1 for each request.
    /// It is wrapped around to 0 when it reaches 65535.
    next_transaction_id: TransactionId,
    socket: UdpSocket,
    pub(crate) server_mode: bool,
    request_timeout: Duration,
    /// We don't need a HashMap, since we know the capacity is `65536` requests.
    /// Requests are also ordered by their transaction_id and thus sent_at, so lookup is fast.
    inflight_requests: Vec<InflightRequest>,
    local_addr: SocketAddrV4,
}

impl KrpcSocket {
    pub(crate) fn new(config: &Config) -> Result<Self, std::io::Error> {
        let request_timeout = config.request_timeout;

        let socket = if let Some(port) = config.port {
            UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port)))?
        } else {
            // Port not defined by user. Try default port first, if that fails, try any port.
            match UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT))) {
                Ok(socket) => Ok(socket),
                Err(_) => UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))),
            }?
        };

        let local_addr = match socket.local_addr()? {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => unimplemented!("KrpcSocket does not support Ipv6"),
        };

        socket.set_read_timeout(Some(READ_TIMEOUT))?;

        Ok(Self {
            socket,
            next_transaction_id: 0,
            server_mode: config.server_mode,
            request_timeout,
            inflight_requests: Vec::with_capacity(u16::MAX as usize),

            local_addr,
        })
    }

    #[cfg(test)]
    pub(crate) fn server() -> Result<Self, std::io::Error> {
        Self::new(&Config {
            server_mode: true,
            ..Default::default()
        })
    }

    #[cfg(test)]
    pub(crate) fn client() -> Result<Self, std::io::Error> {
        Self::new(&Config::default())
    }

    // === Getters ===

    /// Returns the address the server is listening to.
    #[inline]
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local_addr
    }

    // === Public Methods ===

    /// Returns true if this message's transaction_id is still inflight
    pub fn is_inflight(&self, transaction_id: &TransactionId) -> bool {
        self.inflight_requests
            .binary_search_by(|request| request.tid.cmp(transaction_id))
            .is_ok()
    }

    /// Send a request to the given address and return the transaction_id
    pub fn send_request(
        &mut self,
        address: SocketAddrV4,
        request: RequestSpecific,
    ) -> TransactionId {
        let message = self.build_request_message(request);
        trace!(context = "socket_message_sending", message = ?message);

        self.inflight_requests
            .push(InflightRequest::new(message.transaction_id, address));

        let tid = message.transaction_id;
        let _ = self.send_message(address, message);

        tid
    }

    /// Send a response to the given address.
    pub fn send_response(
        &mut self,
        address: SocketAddrV4,
        transaction_id: TransactionId,
        response: ResponseSpecific,
    ) {
        let message =
            self.build_response_message(MessageType::Response(response), address, transaction_id);
        let _ = self.send_message(address, message);
    }

    /// Send an error to the given address.
    pub fn send_error(
        &mut self,
        address: SocketAddrV4,
        transaction_id: TransactionId,
        error: ErrorSpecific,
    ) {
        let message =
            self.build_response_message(MessageType::Error(error), address, transaction_id);
        let _ = self.send_message(address, message);
    }

    /// Receives a single krpc message on the socket.
    /// On success, returns the dht message and the origin.
    pub fn try_receive(&mut self) -> Option<(Message, SocketAddrV4)> {
        self.cleanup_timed_out_requests();

        // Read a message from the socket.
        let mut buf = [0u8; MAX_MTU];
        let (num_bytes_read, from) = match self.socket.recv_from(&mut buf) {
            Ok(values) => values,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                // Timed out like we expected after READ_TIMEOUT, no message received.
                return None;
            }
            Err(e) => {
                trace!(context = "socket_error", ?e, "Error receiving message");
                return None;
            }
        };

        // IPv4 extraction and sanity checks.
        let from_ipv4 = match from {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => {
                trace!(context = "socket_error", message = "Received Ipv6 message");
                return None;
            }
        };
        if from_ipv4.port() == 0 {
            trace!(
                context = "socket_validation",
                message = "Response from port 0"
            );
            return None;
        }

        // Parse the message.
        let bytes = &buf[..num_bytes_read];
        let message = match Message::from_bytes(bytes) {
            Ok(message) => message,
            Err(e) => {
                trace!(context = "socket_error", ?e, ?from_ipv4, message = ?String::from_utf8_lossy(bytes), "Received invalid Bencode message.");
                return None;
            }
        };

        // Check if the message is either a request or an expected response. Otherwise drop it.
        let should_return = match message.message_type {
            MessageType::Request(_) => {
                trace!(
                    context = "socket_message_receiving",
                    ?message,
                    ?from_ipv4,
                    "Received request message"
                );

                true
            }
            MessageType::Response(_) => {
                trace!(
                    context = "socket_message_receiving",
                    ?message,
                    ?from_ipv4,
                    "Received response message"
                );

                self.is_expected_response(&message, &from_ipv4)
            }
            MessageType::Error(_) => {
                trace!(
                    context = "socket_message_receiving",
                    ?message,
                    ?from_ipv4,
                    "Received error message"
                );

                self.is_expected_response(&message, &from_ipv4)
            }
        };

        if should_return {
            Some((message, from_ipv4))
        } else {
            None
        }
    }

    // === Private Methods ===

    /// Cleanup timed-out transaction_ids.
    fn cleanup_timed_out_requests(&mut self) {
        // Find the first timed-out request, and delete all earlier requests.
        match self.inflight_requests.binary_search_by(|request| {
            if request.sent_at.elapsed() > self.request_timeout {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }) {
            Ok(index) => {
                
                self.inflight_requests.drain(..index);
            }
            Err(index) => {
                self.inflight_requests.drain(..index);
            }
        };
    }

    /// Check if the message is an expected response
    /// aka it matches with an inflight request.
    fn is_expected_response(&mut self, message: &Message, from: &SocketAddrV4) -> bool {
        // Positive or an error response or to an inflight request.
        let index = match self
            .inflight_requests
            .binary_search_by(|request| request.tid.cmp(&message.transaction_id))
        {
            Ok(index) => index,
            Err(_) => {
                trace!(
                    context = "socket_validation",
                    message = "Unexpected response id"
                );
                return false;
            }
        };

        let inflight_request = self
            .inflight_requests
            .get(index)
            .expect("should be infallible");

        if are_addr_equal(&inflight_request.to, from) {
            // Confirm that it is a response we actually sent.
            self.inflight_requests.remove(index);
            true
        } else {
            trace!(
                context = "socket_validation",
                message = "Response from wrong address"
            );
            false
        }
    }

    /// Increments self.next_tid and returns the previous value.
    fn get_next_transaction_id(&mut self) -> TransactionId {
        // We don't bother much with reusing freed transaction ids,
        // since the timeout is so short we are unlikely to run out
        // of 65535 ids in 2 seconds.
        let tid = self.next_transaction_id;
        self.next_transaction_id = self.next_transaction_id.wrapping_add(1);
        tid
    }

    /// Builds a request message
    /// Set transactin_id, version and read_only
    fn build_request_message(&mut self, message: RequestSpecific) -> Message {
        let transaction_id = self.get_next_transaction_id();

        Message {
            transaction_id,
            message_type: MessageType::Request(message),
            version: Some(VERSION),
            read_only: !self.server_mode,
            requester_ip: None,
        }
    }

    /// Same as build_request_message but with request transaction_id and the requester_ip.
    fn build_response_message(
        &mut self,
        message: MessageType,
        requester_ip: SocketAddrV4,
        request_tid: TransactionId,
    ) -> Message {
        Message {
            transaction_id: request_tid,
            message_type: message,
            version: Some(VERSION),
            read_only: !self.server_mode,
            // BEP_0042 Only relevant in responses.
            requester_ip: Some(requester_ip),
        }
    }

    /// Send a raw dht message
    fn send_message(
        &mut self,
        address: SocketAddrV4,
        message: Message,
    ) -> Result<(), SendMessageError> {
        let bytes = match message.to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                debug!(
                    context = "socket_error",
                    ?e,
                    "Error sending request message. Failed to parse message to bytes"
                );
                return Err(e.into());
            }
        };

        match self.socket.send_to(&bytes, address) {
            Ok(_) => {
                trace!(context = "socket_message_sending", ?message, ?address);
                Ok(())
            }
            Err(e) => {
                debug!(
                    context = "socket_error",
                    ?e,
                    "Error sending request message. Failed to send message to address"
                );
                Err(e.into())
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
/// Mainline crate error enum.
pub enum SendMessageError {
    /// Errors related to parsing DHT messages.
    #[error("Failed to parse packet bytes: {0}")]
    BencodeError(#[from] serde_bencode::Error),

    #[error(transparent)]
    /// Transparent [std::io::Error]
    IO(#[from] std::io::Error),
}

// Same as SocketAddr::eq but ignores the ip if it is unspecified for testing reasons.
fn are_addr_equal(a: &SocketAddrV4, b: &SocketAddrV4) -> bool {
    if a.port() != b.port() {
        return false;
    }

    if a.ip().is_unspecified() {
        return true;
    }

    a.ip() == b.ip()
}

#[cfg(test)]
mod test {
    use std::thread;

    use crate::common::{Id, PingResponseArguments, RequestTypeSpecific};

    use super::*;

    #[test]
    fn tid() {
        let mut socket = KrpcSocket::server().unwrap();

        assert_eq!(socket.get_next_transaction_id(), 0);
        assert_eq!(socket.get_next_transaction_id(), 1);
        assert_eq!(socket.get_next_transaction_id(), 2);

        socket.next_transaction_id = TransactionId::MAX;

        assert_eq!(socket.get_next_transaction_id(), 65535);
        assert_eq!(socket.get_next_transaction_id(), 0);
    }

    #[test]
    fn recv_request() {
        let mut server = KrpcSocket::server().unwrap();
        let server_address = server.local_addr();

        let mut client = KrpcSocket::client().unwrap();
        client.next_transaction_id = 120;

        let client_address = client.local_addr();
        let request = RequestSpecific {
            requester_id: Id::random(),
            request_type: RequestTypeSpecific::Ping,
        };

        let expected_request = request.clone();

        let server_thread = thread::spawn(move || loop {
            if let Some((message, from)) = server.try_receive() {
                assert_eq!(from.port(), client_address.port());
                assert_eq!(message.transaction_id, 120);
                assert!(message.read_only, "Read-only should be true");
                assert_eq!(message.version, Some(VERSION), "Version should be 'RS'");
                assert_eq!(message.message_type, MessageType::Request(expected_request));
                break;
            }
        });

        client.send_request(server_address, request);

        server_thread.join().unwrap();
    }

    #[test]
    fn recv_response() {
        let (tx, rx) = flume::bounded(1);

        let mut client = KrpcSocket::client().unwrap();
        let client_address = client.local_addr();

        let responder_id = Id::random();
        let response = ResponseSpecific::Ping(PingResponseArguments { responder_id });

        let server_thread = thread::spawn(move || {
            let mut server = KrpcSocket::client().unwrap();
            let server_address = server.local_addr();
            tx.send(server_address).unwrap();

            loop {
                server
                    .inflight_requests
                    .push(InflightRequest::new(8, client_address));

                if let Some((message, from)) = server.try_receive() {
                    assert_eq!(from.port(), client_address.port());
                    assert_eq!(message.transaction_id, 8);
                    assert!(message.read_only, "Read-only should be true");
                    assert_eq!(message.version, Some(VERSION), "Version should be 'RS'");
                    assert_eq!(
                        message.message_type,
                        MessageType::Response(ResponseSpecific::Ping(PingResponseArguments {
                            responder_id,
                        }))
                    );
                    break;
                }
            }
        });

        let server_address = rx.recv().unwrap();

        client.send_response(server_address, 8, response);

        server_thread.join().unwrap();
    }

    #[test]
    fn ignore_response_from_wrong_address() {
        let mut server = KrpcSocket::client().unwrap();
        let server_address = server.local_addr();

        let mut client = KrpcSocket::client().unwrap();

        let client_address = client.local_addr();

        server.inflight_requests.push(InflightRequest::new(
            8,
            SocketAddrV4::new([127, 0, 0, 1].into(), client_address.port() + 1),
        ));

        let response = ResponseSpecific::Ping(PingResponseArguments {
            responder_id: Id::random(),
        });

        let _ = response.clone();

        let server_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(5));
            assert!(
                server.try_receive().is_none(),
                "Should not receive a response from wrong address"
            );
        });

        client.send_response(server_address, 8, response);

        server_thread.join().unwrap();
    }
}
