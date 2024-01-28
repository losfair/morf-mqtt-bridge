use std::{cell::Cell, rc::Rc, time::Duration};

use anyhow::Context;
use bytes::Bytes;
use futures::{
  channel::mpsc::{channel, Receiver, Sender},
  future::Either,
  FutureExt, StreamExt,
};
use monoio::{
  io::{
    AsyncBufRead, AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt, BufReader,
    Splitable,
  },
  net::TcpStream,
  time::MissedTickBehavior,
};
use mqttrs::SubscribeTopic;
use rand::Rng;
use rustls::RootCertStore;

use crate::util::{enforce_future_type, OffsetIoBufMut};

pub enum MqttMessage {
  Publish { topic: Rc<str>, data: Bytes },
  Subscribe { topic: String },
  Unsubscribe { topic: String },
}

pub struct MqttConfig<'a> {
  pub server: Rc<str>,
  pub client_id: &'a str,
  pub username: Option<&'a str>,
  pub password: Option<&'a [u8]>,
  pub keep_alive: u16,
  pub tx_buffer_size: usize,
  pub rx_buffer_size: usize,
  pub tls: Option<MqttTlsConfig>,
}

#[derive(Clone)]
pub struct MqttTlsConfig {
  pub server_name: rustls::ServerName,
}

pub async fn start_mqtt(
  config: &MqttConfig<'_>,
) -> anyhow::Result<(Sender<MqttMessage>, Receiver<MqttMessage>)> {
  let (tx_p, tx_c) = channel(config.tx_buffer_size);
  let (rx_p, rx_c) = channel(config.rx_buffer_size);
  if config.keep_alive == 0 {
    anyhow::bail!("keep_alive must be at least 1 second");
  }

  let mut connect_packet = vec![0u8; 1024];
  let n = mqttrs::encode_slice(
    &mqttrs::Packet::Connect(mqttrs::Connect {
      protocol: mqttrs::Protocol::MQTT311,
      keep_alive: config.keep_alive,
      client_id: config.client_id,
      clean_session: true,
      last_will: None,
      username: config.username,
      password: config.password,
    }),
    &mut connect_packet,
  )?;
  connect_packet.truncate(n);

  monoio::spawn(worker(
    tx_c,
    rx_p,
    config.server.clone(),
    connect_packet,
    Duration::from_secs(config.keep_alive as u64),
    config.tls.clone(),
  ));

  Ok((tx_p, rx_c))
}

async fn worker(
  mut tx_c: Receiver<MqttMessage>,
  mut rx_p: Sender<MqttMessage>,
  server: Rc<str>,
  mut connect_packet: Vec<u8>,
  keep_alive: Duration,
  tls: Option<MqttTlsConfig>,
) {
  loop {
    match worker_once(
      &mut tx_c,
      &mut rx_p,
      &*server,
      &mut connect_packet,
      keep_alive,
      tls.as_ref(),
    )
    .await
    {
      Ok(()) => break,
      Err(error) => {
        tracing::error!(?error, "mqtt worker error, restarting");
        let dur = Duration::from_secs(3)
          + rand::thread_rng().gen_range(Duration::from_secs(0)..Duration::from_secs(2));
        monoio::time::sleep(dur).await;
      }
    }
  }
}

async fn worker_once(
  tx_c: &mut Receiver<MqttMessage>,
  rx_p: &mut Sender<MqttMessage>,
  server: &str,
  connect_packet: &mut Vec<u8>,
  keep_alive: Duration,
  tls: Option<&MqttTlsConfig>,
) -> anyhow::Result<()> {
  let tls_connector = if tls.is_some() {
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
      rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
        ta.subject.as_ref(),
        ta.subject_public_key_info.as_ref(),
        ta.name_constraints.as_ref().map(|x| x.as_ref()),
      )
    }));
    Some(monoio_rustls::TlsConnector::from(
      rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth(),
    ))
  } else {
    None
  };

  loop {
    let stream = TcpStream::connect(server).await?;
    if let Some(tls) = tls {
      let stream = tls_connector
        .as_ref()
        .unwrap()
        .connect(tls.server_name.clone(), stream)
        .await
        .with_context(|| "failed to establish tls connection")?;
      worker_once_on_stream(tx_c, rx_p, connect_packet, keep_alive, stream).await?;
    } else {
      worker_once_on_stream(tx_c, rx_p, connect_packet, keep_alive, stream).await?;
    }
  }
}

async fn worker_once_on_stream(
  tx_c: &mut Receiver<MqttMessage>,
  rx_p: &mut Sender<MqttMessage>,
  connect_packet: &mut Vec<u8>,
  keep_alive: Duration,
  stream: impl AsyncReadRent + AsyncWriteRent + monoio::io::Split,
) -> anyhow::Result<()> {
  let (rh, mut wh) = stream.into_split();
  let mut decoder = MqttDecoder::new(BufReader::new(rh), 1048576);

  // handshake
  let (res, ourpkt) = wh.write_all(std::mem::take(connect_packet)).await;
  *connect_packet = ourpkt;
  res?;

  {
    let ack = decoder.next().await?;
    let mqttrs::Packet::Connack(ack) = ack else {
      anyhow::bail!("did not get ack");
    };
    if ack.code != mqttrs::ConnectReturnCode::Accepted {
      anyhow::bail!("mqtt connect failed: {:?}", ack.code);
    }
  }

  tracing::info!("mqtt session established");

  let tx_task = async {
    let mut ping_interval = monoio::time::interval(keep_alive);
    ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut ping_buf = vec![0u8; 32];
    let n = mqttrs::encode_slice(&mqttrs::Packet::Pingreq, &mut ping_buf)?;
    ping_buf.truncate(n);

    loop {
      let input = futures::select_biased! {
        _ = ping_interval.tick().fuse() => {
          let (res, ourpkt) = wh.write_all(ping_buf).await;
          ping_buf = ourpkt;
          res?;
          continue;
        }
        input = tx_c.next().fuse() => input,
      };
      let Some(input) = input else {
        return Ok::<_, anyhow::Error>(());
      };

      match input {
        MqttMessage::Publish { topic, data } => {
          let mut output_buf = vec![0u8; 32 + topic.as_bytes().len() + data.len()];
          let n = mqttrs::encode_slice(
            &mqttrs::Packet::Publish(mqttrs::Publish {
              dup: false,
              qospid: mqttrs::QosPid::AtMostOnce,
              retain: false,
              topic_name: &*topic,
              payload: data.as_ref(),
            }),
            &mut output_buf,
          )?;
          output_buf.truncate(n);
          wh.write_all(output_buf).await.0?;
        }
        MqttMessage::Subscribe { topic } => {
          let mut output_buf = vec![0u8; 32 + topic.as_bytes().len()];
          let n = mqttrs::encode_slice(
            &mqttrs::Packet::Subscribe(mqttrs::Subscribe {
              pid: mqttrs::Pid::new(),
              topics: vec![SubscribeTopic {
                topic_path: topic,
                qos: mqttrs::QoS::AtMostOnce,
              }],
            }),
            &mut output_buf,
          )?;
          output_buf.truncate(n);
          wh.write_all(output_buf).await.0?;
        }
        MqttMessage::Unsubscribe { topic } => {
          let mut output_buf = vec![0u8; 32 + topic.as_bytes().len()];
          let n = mqttrs::encode_slice(
            &mqttrs::Packet::Unsubscribe(mqttrs::Unsubscribe {
              pid: mqttrs::Pid::new(),
              topics: vec![topic],
            }),
            &mut output_buf,
          )?;
          output_buf.truncate(n);
          wh.write_all(output_buf).await.0?;
        }
      }
    }
  };

  let num_missing_pongs: Cell<usize> = Cell::new(0);

  let liveness_check_task = async {
    let mut ping_interval = monoio::time::interval(keep_alive);
    ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
      ping_interval.tick().await;
      if num_missing_pongs.get() >= 3 {
        anyhow::bail!("did not receive ping responses from server, disconnecting");
      }
      num_missing_pongs.set(num_missing_pongs.get() + 1);
    }
  };

  let rx_task = async {
    loop {
      let pkt = decoder.next().await;

      let pkt = match pkt {
        Ok(x) => x,
        Err(e) => {
          return if matches!(
            e.downcast_ref::<std::io::Error>(),
            Some(x) if x.kind() == std::io::ErrorKind::UnexpectedEof,
          ) {
            Ok(())
          } else {
            Err(anyhow::Error::from(e))
          };
        }
      };

      match pkt {
        mqttrs::Packet::Pingresp => {
          num_missing_pongs.set(0);
          tracing::info!("received ping response");
        }
        mqttrs::Packet::Publish(x) => {
          match rx_p.try_send(MqttMessage::Publish {
            topic: Rc::from(x.topic_name),
            data: Bytes::copy_from_slice(x.payload),
          }) {
            Ok(()) => {}
            Err(e) => {
              // If the channel is disconnected, exit the loop
              // otherwise, the channel is full. Silently drop the message.
              if e.is_disconnected() {
                return Ok(());
              }
            }
          }
        }
        pkt => {
          tracing::info!(?pkt, "received mqtt packet");
        }
      }
    }
  };

  futures::future::try_select(
    futures::future::try_select(std::pin::pin!(tx_task), std::pin::pin!(rx_task)),
    enforce_future_type(std::pin::pin!(liveness_check_task)),
  )
  .await
  .map_err(|e| match e {
    Either::Left((Either::Left((e, _)), _)) => e.context("tx_task error"),
    Either::Left((Either::Right((e, _)), _)) => e.context("rx_task error"),
    Either::Right((e, _)) => e.context("liveness_check_task error"),
  })?;
  Ok(())
}

struct MqttDecoder<T> {
  rh: T,
  buf: Vec<u8>,
  max_packet_size: usize,
}

impl<T: AsyncBufRead> MqttDecoder<T> {
  fn new(rh: T, max_packet_size: usize) -> Self {
    Self {
      rh,
      buf: vec![],
      max_packet_size,
    }
  }

  async fn next<'a>(&'a mut self) -> anyhow::Result<mqttrs::Packet<'a>> {
    self.buf = read_mqtt_packet(&mut self.rh, self.max_packet_size).await?;

    let Some(pkt) = mqttrs::decode_slice(&self.buf)? else {
      anyhow::bail!("mqtt protocol violation");
    };

    Ok(pkt)
  }
}

// https://docs.rs/mqttrs/latest/src/mqttrs/decoder.rs.html
async fn read_mqtt_packet<'a>(
  buf: &mut impl AsyncReadRent,
  max_packet_size: usize,
) -> anyhow::Result<Vec<u8>> {
  let mut header_buf = [0u8; 8];
  // control byte
  header_buf[0] = buf.read_u8().await?;

  let mut len: usize = 0;
  for pos in 0..=3 {
    let byte = buf.read_u8().await?;
    header_buf[pos + 1] = byte;

    len += (byte as usize & 0x7F) << (pos * 7);

    if (byte & 0x80) == 0 {
      // Continuation bit == 0, length is parsed
      let output_size = pos
        .checked_add(2)
        .and_then(|x| x.checked_add(len))
        .unwrap_or(0);
      if output_size == 0 || output_size > max_packet_size {
        anyhow::bail!("packet too large");
      }

      let mut output = Vec::with_capacity(output_size);
      output.extend_from_slice(&header_buf[..pos + 2]);
      let (res, output) = buf.read_exact(OffsetIoBufMut::new(output, pos + 2)).await;
      res?;
      return Ok(output.into_inner());
    }
  }
  // Continuation byte == 1 four times, that's illegal.
  anyhow::bail!("invalid header");
}
