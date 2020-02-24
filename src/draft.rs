struct Server<'a> {
    tunfd: mio::unix::EventedFd<'a>,
    sockfd: mio::net::UdpSocket,

    rng: rand::ThreadRng,
    client_id_pool: ClientIdPool,

    client_info: ClientInfo,

    buf: [u8; 1600],
    encoder: snap::Encoder,
    decoder: snap::Decoder,
    sealing_key: aead::SealingKey,
    opening_key: aead::OpeningKey,
}

impl Server {
    fn new(port: u16, secret: &str, reserved_ids: Option<IdRange>) -> Server {
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

        let rng = thread_rng();
        let client_id_pool = ClientIdPool::new(reserved_ids);
        let client_info: ClientInfo = TransientHashMap::new(60);

        let buf = [0u8; 1600];
        let encoder = snap::Encoder::new();
        let decoder = snap::Decoder::new();

        let (sealing_key, opening_key) = derive_keys(secret);

        Server {
            tunfd,
            sockfd,
            rng,
            client_id_pool,
            client_info,
            buf,
            encoder,
            decoder,
            sealing_key,
            opening_key,
        }
    }
}
