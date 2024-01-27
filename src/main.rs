mod mqtt;
mod util;

use std::{
  cell::RefCell,
  collections::HashSet,
  net::SocketAddr,
  rc::Rc,
  sync::{Arc, Mutex},
  time::{Duration, Instant},
};

use anyhow::Context;
use base64::Engine;
use clap::Parser;
use futures::{FutureExt, StreamExt};
use linked_hash_map::LinkedHashMap;
use monoio::net::udp::UdpSocket;
use morf::peer::MorfPeer;
use rand::Rng;
use rusqlite::OptionalExtension;
use rusqlite_migration::{Migrations, M};
use tracing_subscriber::{fmt::SubscriberBuilder, EnvFilter};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
  mqtt::{start_mqtt, MqttConfig, MqttMessage, MqttTlsConfig},
  util::enforce_future_type,
};

static MIGRATIONS: &[M] = &[M::up(
  r#"
create table devices (
  public_key_hash_b64 text not null,
  public_key_b64 text not null,
  description text not null default '',
  created_at integer not null default (strftime('%s', 'now')),

  primary key (public_key_hash_b64)
);
create table device_publish_topics(
  public_key_hash_b64 text not null,
  topic text not null,
  created_at integer not null default (strftime('%s', 'now')),

  primary key (public_key_hash_b64)
);
create table device_subscribe_topics(
  public_key_hash_b64 text not null,
  topic text not null,
  created_at integer not null default (strftime('%s', 'now')),

  primary key (topic, public_key_hash_b64)
);
"#,
)];

/// MoRF/MQTT bidirectional bridge
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
  /// Path to SQLite database
  #[arg(long, env = "DB_PATH")]
  db: String,

  /// Path to X25519 secret key
  #[arg(long)]
  secret_key: String,

  /// UDP downlink local address
  #[arg(long, env = "DOWNLINK")]
  downlink: SocketAddr,

  /// UDP uplink local address
  #[arg(long, env = "UPLINK_LOCAL")]
  uplink_local: SocketAddr,

  /// UDP uplink remote address
  #[arg(long, env = "UPLINK_REMOTE")]
  uplink_remote: SocketAddr,

  /// MQTT client ID
  #[arg(long, env = "MQTT_CLIENT_ID")]
  mqtt_client_id: String,

  /// MQTT server
  #[arg(long, env = "MQTT_SERVER")]
  mqtt_server: String,

  /// Enable TLS for MQTT
  #[arg(long)]
  mqtt_tls: bool,

  /// MQTT TLS server name
  #[arg(long, env = "MQTT_TLS_SERVER_NAME")]
  mqtt_tls_server_name: Option<String>,

  /// MQTT username
  #[arg(long, env = "MQTT_USERNAME")]
  mqtt_username: Option<String>,

  /// MQTT password
  #[arg(long, env = "MQTT_PASSWORD")]
  mqtt_password: Option<String>,

  /// MQTT TX buffer size (in number of messages)
  #[arg(long, default_value = "128", env = "MQTT_TX_BUFFER_SIZE")]
  mqtt_tx_buffer_size: usize,

  /// MQTT RX buffer size (in number of messages)
  #[arg(long, default_value = "128", env = "MQTT_RX_BUFFER_SIZE")]
  mqtt_rx_buffer_size: usize,

  /// MQTT keep alive interval in seconds
  #[arg(long, default_value = "15", env = "MQTT_KEEP_ALIVE_SECS")]
  mqtt_keep_alive_secs: u16,
}

#[derive(Clone)]
struct DeviceState {
  public_key_hash: [u8; 16],
  peer: Rc<RefCell<MorfPeer>>,
  topic: Option<Rc<str>>,
  created_at: Instant,
}

fn main() -> anyhow::Result<()> {
  monoio::start::<monoio::time::TimeDriver<monoio::IoUringDriver>, _>(async_main())
}

async fn async_main() -> anyhow::Result<()> {
  if std::env::var("RUST_LOG").is_err() {
    std::env::set_var("RUST_LOG", "info");
  }

  SubscriberBuilder::default()
    .with_env_filter(EnvFilter::from_default_env())
    .pretty()
    .init();

  let args = Args::parse();
  let secret_key = std::fs::read(&args.secret_key).with_context(|| "failed to read secret key")?;
  let secret_key = StaticSecret::from(
    <[u8; 32]>::try_from(&secret_key[..])
      .with_context(|| format!("secret key must be 32 bytes long, got {}", secret_key.len()))?,
  );
  let public_key = x25519_dalek::PublicKey::from(&secret_key);

  let db = Arc::new(Mutex::new(
    rusqlite::Connection::open(&args.db).with_context(|| "failed to open database")?,
  ));
  let migrations = Migrations::new(MIGRATIONS.iter().cloned().collect());
  migrations
    .to_latest(&mut db.try_lock().unwrap())
    .with_context(|| "failed to apply db migrations")?;

  let (mut mqtt_tx, mut mqtt_rx) = start_mqtt(&MqttConfig {
    server: Rc::from(&*args.mqtt_server),
    client_id: &args.mqtt_client_id,
    username: args.mqtt_username.as_deref(),
    password: args.mqtt_password.as_deref().map(|x| x.as_bytes()),
    keep_alive: args.mqtt_keep_alive_secs,
    tx_buffer_size: args.mqtt_tx_buffer_size,
    rx_buffer_size: args.mqtt_rx_buffer_size,
    tls: if args.mqtt_tls {
      Some(MqttTlsConfig {
        server_name: rustls::ServerName::try_from(
          args
            .mqtt_tls_server_name
            .as_deref()
            .unwrap_or_else(|| args.mqtt_server.split(':').next().unwrap()),
        )
        .with_context(|| "invalid mqtt tls server name")?,
      })
    } else {
      None
    },
  })
  .await
  .with_context(|| "failed to start mqtt client")?;

  let mut pkt = vec![0u8; 1500];
  let half_established_sessions: RefCell<LinkedHashMap<(SocketAddr, [u8; 32]), DeviceState>> =
    RefCell::new(LinkedHashMap::new());
  let sessions: RefCell<LinkedHashMap<(SocketAddr, [u8; 32]), DeviceState>> =
    RefCell::new(LinkedHashMap::new());
  let downlink = UdpSocket::bind(args.downlink).with_context(|| "Failed to bind downlink")?;
  let uplink =
    Arc::new(UdpSocket::bind(args.uplink_local).with_context(|| "Failed to bind uplink")?);

  tracing::info!(
    addr = %args.downlink,
    public_key = base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes()),
    "listening for downlink packets"
  );

  let session_eviction_work = async {
    let mut interval = Duration::from_secs(1);
    loop {
      monoio::time::sleep(interval).await;
      let now = Instant::now();
      let mut num_evicted_half_established_sessions = 0usize;
      let mut num_evicted_sessions = 0usize;
      {
        let mut half_established_sessions = half_established_sessions.borrow_mut();
        while let Some(front) = half_established_sessions.front() {
          if front.1.created_at > now
            || now.duration_since(front.1.created_at) < Duration::from_secs(5)
          {
            break;
          }
          half_established_sessions.pop_front();
          num_evicted_half_established_sessions += 1;
        }
      }
      {
        let mut sessions = sessions.borrow_mut();
        while sessions.len() > 50 {
          sessions.pop_front();
          num_evicted_sessions += 1;
        }
      }
      let duration = now.elapsed();
      interval = std::cmp::max(duration * 100, Duration::from_millis(200));
      if num_evicted_half_established_sessions != 0 || num_evicted_sessions != 0 {
        tracing::info!(duration = ?duration, interval = ?interval, num_evicted_half_established_sessions, num_evicted_sessions, "session eviction");
      }
    }
  };

  let morf2mqtt_work = async {
    loop {
      let (res, ourpkt) = downlink.recv_from(pkt).await;
      pkt = ourpkt;
      let (n, remote_addr) = res.with_context(|| "Failed to receive")?;
      let pkt = &pkt[..n];

      if pkt.is_empty() {
        continue;
      }
      let ty = pkt[0];
      match ty {
        3 => {
          let start_time = Instant::now();

          let Ok((mut peer, handshake, output)) =
            MorfPeer::server_accept_handshake(rand::thread_rng().gen(), &secret_key, pkt)
          else {
            continue;
          };

          let device_static_public_key_hash_b64 = base64::engine::general_purpose::STANDARD
            .encode(handshake.device_static_public_key_hash);
          let public_key_hash = handshake.device_static_public_key_hash;

          // Query and decode device public key
          let db2 = db.clone();
          let device_static_public_key_hash_b64_2 = device_static_public_key_hash_b64.clone();
          let device_static_public_key = blocking::unblock(move || {
            let output = db2
              .lock()
              .unwrap()
              .prepare_cached("select public_key_b64 from devices where public_key_hash_b64 = ?")?
              .query_row([&device_static_public_key_hash_b64_2], |row| {
                row.get::<_, String>(0)
              })
              .optional();
            output
          })
          .await?;
          let Some(device_static_public_key) = device_static_public_key
            .and_then(|x| {
              base64::engine::general_purpose::STANDARD
                .decode(x.as_bytes())
                .ok()
            })
            .and_then(|x| <[u8; 32]>::try_from(&x[..]).ok())
            .map(PublicKey::from)
          else {
            continue;
          };

          let device_key = (
            remote_addr,
            *handshake.client_ephemeral_public_key.as_bytes(),
          );
          handshake.authenticate(&device_static_public_key, &mut peer);
          let db2 = db.clone();
          let device_static_public_key_hash_b64_2 = device_static_public_key_hash_b64.clone();
          let topic = blocking::unblock(move || {
            db2
              .lock()
              .unwrap()
              .prepare_cached(
                "select topic from device_publish_topics where public_key_hash_b64 = ?",
              )?
              .query_row([device_static_public_key_hash_b64_2], |row| {
                row.get::<_, String>(0)
              })
              .optional()
          })
          .await?;
          half_established_sessions.borrow_mut().insert(
            device_key,
            DeviceState {
              public_key_hash,
              peer: Rc::new(RefCell::new(peer)),
              topic: topic.as_deref().map(Rc::from),
              created_at: Instant::now(),
            },
          );

          tracing::info!(public_key_hash = device_static_public_key_hash_b64, duration = ?start_time.elapsed(), ?topic, "device session half-established");

          if let Err(error) = uplink
            .send_to(output.as_ref().to_vec(), remote_addr)
            .await
            .0
          {
            tracing::error!(
              public_key_hash = device_static_public_key_hash_b64,
              ?error,
              "failed to send to uplink"
            );
            continue;
          }
        }
        2 => {
          let mut output: Option<(Vec<u8>, [u8; 16], Option<Rc<str>>)> = None;

          {
            let mut sessions = sessions.borrow_mut();
            let mut key_to_refresh = None;
            for entry in sessions.iter() {
              if entry.0 .0 != remote_addr {
                continue;
              }
              let mut pkt = pkt.to_vec();
              let res = entry.1.peer.borrow_mut().unseal(&mut pkt);
              if let Ok(res) = res {
                let key = entry.0;
                output = Some((res.to_vec(), entry.1.public_key_hash, entry.1.topic.clone()));
                key_to_refresh = Some(*key);
                break;
              }
            }
            if let Some(key) = key_to_refresh {
              sessions.get_refresh(&key);
            }
          }

          if output.is_none() {
            let mut half_established_sessions = half_established_sessions.borrow_mut();
            for entry in half_established_sessions.iter() {
              if entry.0 .0 != remote_addr {
                continue;
              }
              let mut pkt = pkt.to_vec();
              let res = entry.1.peer.borrow_mut().unseal(&mut pkt);
              if let Ok(res) = res {
                output = Some((res.to_vec(), entry.1.public_key_hash, entry.1.topic.clone()));
                let key = *entry.0;
                let st = entry.1.clone();
                let public_key_hash_b64 =
                  base64::engine::general_purpose::STANDARD.encode(entry.1.public_key_hash);
                tracing::info!(
                  public_key_hash = public_key_hash_b64,
                  "device session established"
                );
                half_established_sessions.remove(&key);
                sessions.borrow_mut().insert(key, st);
                break;
              }
            }
          }

          let Some((message, public_key, Some(topic))) = output else {
            continue;
          };

          // keep-alive?
          if message.is_empty() {
            continue;
          }

          let ok = mqtt_tx
            .try_send(MqttMessage {
              data: message.into(),
              topic: topic.clone(),
            })
            .is_ok();

          if ok {
            tracing::debug!(topic = %topic, ?public_key, "mqtt message sent");
          }
        }
        _ => {}
      }
    }
  };

  let mqtt2morf_work = async {
    loop {
      let Some(msg) = mqtt_rx.next().await else {
        break;
      };
      let db2 = db.clone();
      let topic = msg.topic.to_string();
      let public_key_hashes = blocking::unblock(move || {
        db2
          .lock()
          .unwrap()
          .prepare_cached(
            "select public_key_hash_b64 from device_subscribe_topics where topic = ?",
          )?
          .query_map([topic], |row| {
            row.get::<_, String>(0).map(|x| {
              // b64 decode into [u8; 16]
              base64::engine::general_purpose::STANDARD
                .decode(x.as_bytes())
                .ok()
                .and_then(|x| <[u8; 16]>::try_from(&x[..]).ok())
            })
          })?
          .filter_map(|x| x.transpose())
          .collect::<Result<HashSet<_>, _>>()
      })
      .await?;
      let mut target_devices: Vec<(SocketAddr, Rc<RefCell<MorfPeer>>)> = vec![];
      for entry in sessions.borrow().iter() {
        if public_key_hashes.contains(&entry.1.public_key_hash) {
          target_devices.push((entry.0 .0, entry.1.peer.clone()));
        }
      }

      for (addr, peer) in &target_devices {
        let mut packet = [&[0u8; 3], &msg.data[..], &[0u8; 16]].concat();
        let Ok(res) = peer.borrow_mut().seal(&mut packet[3..3 + msg.data.len()]) else {
          continue;
        };
        let (prefix, suffix): ([u8; 3], [u8; 16]) = res;
        packet[..3].copy_from_slice(&prefix);
        packet[3 + msg.data.len()..].copy_from_slice(&suffix);

        let _ = uplink.send_to(packet, *addr).await;
      }
    }
    Ok::<_, anyhow::Error>(())
  };

  futures::select_biased! {
    _ = session_eviction_work.fuse() => unreachable!(),
    e = enforce_future_type(morf2mqtt_work).fuse() => {
      e.with_context(|| "morf2mqtt failed")?;
    }
    e = enforce_future_type(mqtt2morf_work).fuse() => {
      e.with_context(|| "mqtt2morf failed")?;
    }
  }

  Ok(())
}
