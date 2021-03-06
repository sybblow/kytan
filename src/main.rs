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

mod crypto;
mod device;
mod dns;
mod network;
mod packet;
mod proto;
mod utils;

use env_logger;
use getopts;
use std::sync::atomic::Ordering;

fn print_usage(program: &str, opts: getopts::Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn handle_signal() {
    network::INTERRUPTED.store(true, Ordering::Relaxed);
}

fn main() {
    env_logger::init();

    let mut opts = getopts::Options::new();
    opts.reqopt("m", "mode", "mode (server or client)", "[s|c]");
    opts.optopt("p", "port", "UDP port to listen/connect", "PORT");
    opts.optopt("h", "host", "remote host to connect (client mode)", "HOST");
    opts.optopt("s", "secret", "shared secret", "PASSWORD");
    opts.optopt("a", "address-id", "last part of network address", "ADDR_ID");
    opts.optopt(
        "x",
        "exclude-ids",
        "reserved network addresses",
        "EX_ADDR_IDS",
    );
    opts.optopt("g", "gateway", "use VPN as gateway", "true/false");

    let args: Vec<String> = std::env::args().collect();
    let program = args[0].clone();

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => {
            print_usage(&program, opts);
            return;
        }
    };

    if !utils::is_root() {
        panic!("Please run as root");
    }

    let mode = matches.opt_str("m").unwrap();
    let port: u16 = matches
        .opt_str("p")
        .unwrap_or(String::from("8964"))
        .parse()
        .unwrap();
    let secret = matches.opt_str("s").unwrap();

    ctrlc::set_handler(handle_signal);

    let addr_id = matches.opt_get::<u8>("a").unwrap();
    let reserved_ids = matches.opt_get::<utils::IdRange>("x").unwrap();
    let is_gateway = matches.opt_get::<bool>("g").unwrap().unwrap_or(true);

    match mode.as_ref() {
        "s" => network::serve(port, &secret, reserved_ids),
        "c" => {
            let host = matches.opt_str("h").unwrap();
            network::connect(&host, port, is_gateway, &secret, addr_id)
        }
        _ => unreachable!(),
    };

    println!("SIGINT/SIGTERM captured. Exit.");
}
