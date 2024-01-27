use std::{
  net::{SocketAddr, UdpSocket},
  time::{Duration, SystemTime},
};

use clap::Parser;
use morf::peer::MorfPeer;
use rand::Rng;
use x25519_dalek::{PublicKey, StaticSecret};

/// MoRF/MQTT bidirectional bridge test program
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
  /// UDP local address for publishing
  #[arg(long)]
  local: SocketAddr,

  /// UDP remote address for subscribing
  #[arg(long)]
  remote: SocketAddr,

  /// Path to X25519 secret key
  #[arg(long)]
  device_secret_key: String,

  /// Path to server X25519 public key
  #[arg(long)]
  server_public_key: String,
}

fn main() {
  let args = Args::parse();
  let socket = UdpSocket::bind(args.local).expect("couldn't bind to address");
  let device_secret_key = StaticSecret::from(
    <[u8; 32]>::try_from(
      std::fs::read(args.device_secret_key).expect("couldn't read device secret key"),
    )
    .expect("invalid device secret key"),
  );
  let device_public_key = PublicKey::from(&device_secret_key);
  let server_public_key = PublicKey::from(
    <[u8; 32]>::try_from(
      std::fs::read(args.server_public_key).expect("couldn't read server public key"),
    )
    .expect("invalid server public key"),
  );
  'outer: loop {
    eprintln!("initiating handshake");

    let (mut peer, output) = MorfPeer::client_initiate_handshake(
      rand::thread_rng().gen(),
      &server_public_key,
      &device_public_key,
    );

    socket.set_read_timeout(None).unwrap();
    socket.set_write_timeout(None).unwrap();
    socket
      .send_to(output.as_ref(), args.remote)
      .expect("couldn't send handshake");

    let mut buf = vec![0u8; 1500];
    let deadline = SystemTime::now() + Duration::from_secs(1);
    loop {
      let now = SystemTime::now();
      if now >= deadline {
        eprintln!("timeout reading handshake response");
        continue 'outer;
      }
      socket
        .set_read_timeout(Some(deadline.duration_since(now).unwrap()))
        .unwrap();
      let (n, _) = match socket.recv_from(&mut buf) {
        Ok(x) => x,
        Err(e) => {
          eprintln!("failed to read handshake response: {:?}", e);
          continue 'outer;
        }
      };
      let pkt = &buf[..n];
      if peer
        .client_finalize_handshake(&device_secret_key, pkt)
        .is_ok()
      {
        let (prefix, suffix) = peer.seal(&mut []).unwrap();
        socket
          .send_to(&[&prefix[..], &suffix[..]].concat(), args.remote)
          .unwrap();
        break;
      }
    }

    for _ in 0..10000 {
      std::thread::sleep(Duration::from_millis(1));
      let mut payload = Vec::from(format!(
        "test {} ",
        SystemTime::now()
          .duration_since(SystemTime::UNIX_EPOCH)
          .unwrap()
          .as_millis(),
      ));
      payload.reserve(1000);
      {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
          payload.push(rng.gen_range(b'a'..b'z'));
        }
      }
      let (prefix, suffix) = peer.seal(&mut payload).unwrap();
      socket
        .send_to(
          &[&prefix[..], &payload[..], &suffix[..]].concat(),
          args.remote,
        )
        .unwrap();
    }

    eprintln!("finished send loop");
  }
}
