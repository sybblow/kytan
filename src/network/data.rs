// Copyright 2016-2017 Chang Lan
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bincode::{deserialize, serialize};
use device;
use dns_lookup;
use mio;
use rand::{thread_rng, Rng};
use ring::{aead, digest, pbkdf2};
use snap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering, ATOMIC_BOOL_INIT};
use std::time::Duration;
use transient_hashmap::TransientHashMap;
use utils;
use utils::IdRange;

pub static INTERRUPTED: AtomicBool = ATOMIC_BOOL_INIT;
static CONNECTED: AtomicBool = ATOMIC_BOOL_INIT;
static LISTENING: AtomicBool = ATOMIC_BOOL_INIT;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const NONCE: &[u8; 12] = &[0; 12];

type Id = u8;
type Token = u64;
type ClientInfo = TransientHashMap<Id, (Token, SocketAddr)>;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum Message {
    Request,
    Response { id: Id, token: Token },
    Data { id: Id, token: Token, data: Vec<u8> },
    RequestWithID { id: Id },
}

const TUN: mio::Token = mio::Token(0);
const SOCK: mio::Token = mio::Token(1);

fn resolve(host: &str) -> Result<IpAddr, String> {
    let ip_list = try!(dns_lookup::lookup_host(host).map_err(|_| "dns_lookup::lookup_host"));
    Ok(ip_list.first().unwrap().clone())
}

fn create_tun_attempt() -> device::Tun {
    fn attempt(id: u8) -> device::Tun {
        match id {
            255 => panic!("Unable to create TUN device."),
            _ => match device::Tun::create(id) {
                Ok(tun) => tun,
                Err(_) => attempt(id + 1),
            },
        }
    }
    attempt(0)
}

fn derive_keys(password: &str) -> (aead::SealingKey, aead::OpeningKey) {
    let mut key = [0; KEY_LEN];
    let salt = vec![0; 64];
    pbkdf2::derive(&digest::SHA256, 1024, &salt, password.as_bytes(), &mut key);
    let sealing_key = aead::SealingKey::new(&aead::AES_256_GCM, &key).unwrap();
    let opening_key = aead::OpeningKey::new(&aead::AES_256_GCM, &key).unwrap();
    (sealing_key, opening_key)
}

fn initiate(socket: &UdpSocket, addr: &SocketAddr, secret: &str) -> Result<(Id, Token), String> {
    let resp_msg = handshake(socket, addr, secret, &Message::Request {})?;
    match resp_msg {
        Message::Response { id, token } => Ok((id, token)),
        _ => Err(format!("Invalid message {:?} from {}", resp_msg, addr)),
    }
}

fn initiate2(socket: &UdpSocket, addr: &SocketAddr, secret: &str, id: u8) -> Result<Token, String> {
    let resp_msg = handshake(socket, addr, secret, &Message::RequestWithID { id })?;
    match resp_msg {
        Message::Response { token, .. } => Ok(token),
        _ => Err(format!("Invalid message {:?} from {}", resp_msg, addr)),
    }
}

fn handshake(
    socket: &UdpSocket,
    addr: &SocketAddr,
    secret: &str,
    msg: &Message,
) -> Result<Message, String> {
    let (sealing_key, opening_key) = derive_keys(secret);
    let req_msg_buf = encap_msg(msg, &sealing_key);
    block_send_all(socket, req_msg_buf.data(), addr).map_err(|e| e.to_string())?;
    info!("Request sent to {}.", addr);

    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    let mut buf = [0u8; 1600];
    let (len, recv_addr) = socket.recv_from(&mut buf).map_err(|e| e.to_string())?;
    assert_eq!(&recv_addr, addr);
    info!("Response received from {}.", addr);
    let decrypted_buf = aead::open_in_place(&opening_key, NONCE, &[], 0, &mut buf[..len]).unwrap();

    deserialize(decrypted_buf).map_err(|e| e.to_string())
}

pub fn connect(host: &str, port: u16, default: bool, secret: &str, addr_id: Option<u8>) {
    info!("Working in client mode.");
    let remote_ip = resolve(host).unwrap();
    let remote_addr = SocketAddr::new(remote_ip, port);
    info!("Remote server: {}", remote_addr);

    let local_addr: SocketAddr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
    let socket = UdpSocket::bind(&local_addr).unwrap();

    let (sealing_key, opening_key) = derive_keys(secret);

    let (id, token) = if let Some(v) = addr_id {
        (v, initiate2(&socket, &remote_addr, &secret, v).unwrap())
    } else {
        initiate(&socket, &remote_addr, &secret).unwrap()
    };
    info!(
        "Session established with token {}. Assigned IP address: 10.10.10.{}.",
        token, id
    );

    info!("Bringing up TUN device.");
    let mut tun = create_tun_attempt();
    let tun_rawfd = tun.as_raw_fd();
    tun.up(id);
    let tunfd = mio::unix::EventedFd(&tun_rawfd);
    info!(
        "TUN device {} initialized. Internal IP: 10.10.10.{}/24.",
        tun.name(),
        id
    );

    let poll = mio::Poll::new().unwrap();
    info!("Setting up TUN device for polling.");
    poll.register(&tunfd, TUN, mio::Ready::readable(), mio::PollOpt::level())
        .unwrap();

    info!("Setting up socket for polling.");
    let sockfd = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(&sockfd, SOCK, mio::Ready::readable(), mio::PollOpt::level())
        .unwrap();

    let mut events = mio::Events::with_capacity(1024);
    let mut buf = [0u8; 1600];

    // RAII so ignore unused variable warning
    let _gw = if default {
        Some(utils::DefaultGateway::create(
            "10.10.10.1",
            &format!("{}", remote_addr.ip()),
        ))
    } else {
        None
    };

    let mut encoder = snap::Encoder::new();
    let mut decoder = snap::Decoder::new();

    CONNECTED.store(true, Ordering::Relaxed);
    info!("Ready for transmission.");

    loop {
        if INTERRUPTED.load(Ordering::Relaxed) {
            break;
        }
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                SOCK => {
                    let (len, addr) = sockfd.recv_from(&mut buf).unwrap();
                    let decrypted_buf =
                        aead::open_in_place(&opening_key, NONCE, &[], 0, &mut buf[..len]).unwrap();
                    let msg: Message = deserialize(&decrypted_buf).unwrap();
                    match msg {
                        Message::Data {
                            id: _,
                            token: server_token,
                            data,
                        } => {
                            if token == server_token {
                                let decompressed_data = decoder.decompress_vec(&data).unwrap();
                                write_all(&mut tun, &decompressed_data);
                            } else {
                                warn!(
                                    "Token mismatched. Received: {}. Expected: {}",
                                    server_token, token
                                );
                            }
                        }
                        _ => {
                            warn!("Invalid message {:?} from {}", msg, addr);
                        }
                    }
                }
                TUN => {
                    let len: usize = tun.read(&mut buf).unwrap();
                    let data = &buf[..len];
                    let msg = Message::Data {
                        id: id,
                        token: token,
                        data: encoder.compress_vec(data).unwrap(),
                    };
                    let msg_buf = encap_msg(&msg, &sealing_key);
                    send_all(&sockfd, msg_buf.data(), &remote_addr);
                }
                _ => unreachable!(),
            }
        }
    }
}

pub fn serve(port: u16, secret: &str, reserved_ids: Option<IdRange>) {
    info!("Working in server mode.");

    let public_ip = utils::get_public_ip().unwrap();
    info!("Public IP: {}", public_ip);

    info!("Enabling kernel's IPv4 forwarding.");
    utils::enable_ipv4_forwarding().unwrap();

    info!("Bringing up TUN device.");
    let mut tun = create_tun_attempt();
    tun.up(1);

    let tun_rawfd = tun.as_raw_fd();
    let tunfd = mio::unix::EventedFd(&tun_rawfd);
    info!(
        "TUN device {} initialized. Internal IP: 10.10.10.1/24.",
        tun.name()
    );

    let addr = format!("0.0.0.0:{}", port).parse().unwrap();
    let sockfd = mio::net::UdpSocket::bind(&addr).unwrap();
    info!("Listening on: 0.0.0.0:{}.", port);

    let poll = mio::Poll::new().unwrap();
    poll.register(&sockfd, SOCK, mio::Ready::readable(), mio::PollOpt::level())
        .unwrap();
    poll.register(&tunfd, TUN, mio::Ready::readable(), mio::PollOpt::level())
        .unwrap();

    let mut events = mio::Events::with_capacity(1024);

    let mut rng = thread_rng();
    let mut client_id_pool = ClientIdPool::new(reserved_ids);
    let mut client_info: TransientHashMap<Id, (Token, SocketAddr)> = TransientHashMap::new(60);

    let mut buf = [0u8; 1600];
    let mut encoder = snap::Encoder::new();
    let mut decoder = snap::Decoder::new();

    let (sealing_key, opening_key) = derive_keys(secret);

    LISTENING.store(true, Ordering::Relaxed);
    info!("Ready for transmission.");

    loop {
        if INTERRUPTED.load(Ordering::Relaxed) {
            break;
        }

        // Clear expired client info
        client_id_pool.put(&client_info.prune());
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                SOCK => {
                    let (len, addr) = sockfd.recv_from(&mut buf).unwrap();
                    let decrypted_buf =
                        aead::open_in_place(&opening_key, NONCE, &[], 0, &mut buf[..len]).unwrap();
                    let msg: Message = match deserialize(&decrypted_buf) {
                        Ok(msg) => msg,
                        Err(e) => {
                            warn!(
                                "Invalid raw message {:?} from {} deserialize failed: {:?}",
                                decrypted_buf, addr, e
                            );
                            continue;
                        }
                    };
                    match msg {
                        Message::Request => {
                            let client_id: Id = client_id_pool.get().unwrap();
                            common_handle_handshake(
                                &sockfd,
                                &sealing_key,
                                &mut client_info,
                                &mut rng,
                                addr,
                                client_id,
                            )
                        }
                        Message::RequestWithID { id } => common_handle_handshake(
                            &sockfd,
                            &sealing_key,
                            &mut client_info,
                            &mut rng,
                            addr,
                            id,
                        ),
                        Message::Response { id: _, token: _ } => {
                            warn!("Invalid message {:?} from {}", msg, addr)
                        }
                        Message::Data { id, token, data } => match client_info.get(&id) {
                            None => warn!("Unknown data with token {} from id {}.", token, id),
                            Some(&(t, _)) => {
                                if t != token {
                                    warn!(
                                        "Unknown data with mismatched token {} from id {}. \
                                         Expected: {}",
                                        token, id, t
                                    );
                                } else {
                                    let decompressed_data = decoder.decompress_vec(&data).unwrap();
                                    write_all(&mut tun, &decompressed_data);
                                }
                            }
                        },
                    }
                }
                TUN => {
                    let len: usize = tun.read(&mut buf).unwrap();
                    let data = &buf[..len];
                    let client_id: u8 = data[19];

                    match client_info.get(&client_id) {
                        None => warn!("Unknown IP packet from TUN for client {}.", client_id),
                        Some(&(token, addr)) => {
                            let msg = Message::Data {
                                id: client_id,
                                token: token,
                                data: encoder.compress_vec(data).unwrap(),
                            };
                            let msg_buf = encap_msg(&msg, &sealing_key);
                            send_all(&sockfd, msg_buf.data(), &addr);
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

fn common_handle_handshake(
    sockfd: &mio::net::UdpSocket,
    sealing_key: &aead::SealingKey,
    client_info: &mut ClientInfo,
    rng: &mut rand::ThreadRng,
    client_addr: SocketAddr,
    client_id: Id,
) {
    let client_token: Token = rng.gen::<Token>();

    client_info.insert(client_id, (client_token, client_addr));

    info!(
        "Got request from {}. Assigning IP address: 10.10.10.{}.",
        client_addr, client_id
    );

    let reply = Message::Response {
        id: client_id,
        token: client_token,
    };
    let reply_buf = encap_msg(&reply, &sealing_key);
    send_all(&sockfd, reply_buf.data(), &client_addr);
}

fn write_all(tun: &mut device::Tun, data: &[u8]) {
    let mut sent_len = 0;
    while sent_len < data.len() {
        match tun.write(&data[sent_len..]) {
            Ok(len) => {
                sent_len += len;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                panic!("{:?}", e);
            }
        }
    }
}

fn encap_msg(msg: &Message, sealing_key: &aead::SealingKey) -> Buf {
    let mut encoded_msg: Vec<u8> = serialize(msg).unwrap();
    let len = encoded_msg.len() + TAG_LEN;
    encoded_msg.resize(len, 0);
    let len = aead::seal_in_place(&sealing_key, NONCE, &[], &mut encoded_msg, TAG_LEN).unwrap();

    Buf::new(encoded_msg, len)
}

struct Buf {
    inner_data: Vec<u8>,
    pub len: usize,
}

impl Buf {
    fn new(inner_data: Vec<u8>, len: usize) -> Buf {
        Buf { inner_data, len }
    }

    fn data(&self) -> &[u8] {
        &self.inner_data[..self.len]
    }
}

fn send_all(sockfd: &mio::net::UdpSocket, data: &[u8], addr: &SocketAddr) {
    let mut sent_len = 0;
    while sent_len < data.len() {
        match sockfd.send_to(&data[sent_len..], &addr) {
            Ok(len) => {
                sent_len += len;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                panic!("{:?}", e);
            }
        }
    }
}

fn block_send_all(sockfd: &UdpSocket, data: &[u8], addr: &SocketAddr) -> io::Result<()> {
    let mut sent_len = 0;
    while sent_len < data.len() {
        sent_len += try!(sockfd.send_to(&data[sent_len..], &addr))
    }

    Ok(())
}

struct ClientIdPool {
    available_ids: Vec<Id>,
    reserved_ids: Option<IdRange>,
}

impl ClientIdPool {
    fn new(reserved_ids: Option<IdRange>) -> ClientIdPool {
        let reserved_ids = reserved_ids.filter(IdRange::is_valid);
        let available_ids: Vec<Id> = match reserved_ids {
            Some(ref r) => r.get_other_ids(),
            _ => (2..254).collect(),
        };
        ClientIdPool {
            available_ids,
            reserved_ids,
        }
    }

    fn get(&mut self) -> Option<Id> {
        self.available_ids.pop()
    }

    fn put(&mut self, old: &[Id]) {
        for &e in old {
            if let Some(ref r) = self.reserved_ids {
                if r.contains(e) {
                    continue;
                }
            }
            self.available_ids.push(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use network::*;
    use std::net::Ipv4Addr;

    #[cfg(target_os = "linux")]
    use std::thread;

    #[test]
    fn resolve_test() {
        assert_eq!(
            super::resolve("127.0.0.1").unwrap(),
            super::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn integration_test() {
        assert!(utils::is_root());
        let server = thread::spawn(move || serve(8964, "password"));

        thread::sleep_ms(1000);
        assert!(LISTENING.load(Ordering::Relaxed));

        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8964);
        let local_addr: SocketAddr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let local_socket = UdpSocket::bind(&local_addr).unwrap();

        let (id, token) = initiate(&local_socket, &remote_addr, "password").unwrap();
        assert_eq!(id, 253);

        let client = thread::spawn(move || connect("127.0.0.1", 8964, false, "password"));

        thread::sleep_ms(1000);
        assert!(CONNECTED.load(Ordering::Relaxed));

        INTERRUPTED.store(true, Ordering::Relaxed);
    }
}