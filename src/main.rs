use clap::Parser as _;
use futures::StreamExt as _;
use gpiocdev::line::EdgeDetection;
use gpiocdev::line::EdgeKind;
use gpiocdev::line::Value;
use homie5::Homie5DeviceProtocol;
use homie5::HomieDeviceStatus;
use homie5::HomieID;
use homie5::client::Publish as HomiePublish;
use homie5::client::Subscription;
use homie5::device_description::HomieDeviceDescription;
use homie5::device_description::NodeDescriptionBuilder;
use homie5::device_description::PropertyDescriptionBuilder;
use rumqttc::Outgoing;
use rumqttc::v5::mqttbytes::v5::{LastWill, Packet, Publish as MqttPublish};
use rumqttc::v5::{AsyncClient, Event as MqttEvent, MqttOptions};
use std::cell::RefCell;
use std::error::Error as StdError;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

const NODE_ID: HomieID = HomieID::new_const("gate");
const STATUS_ID: HomieID = HomieID::new_const("status");
const CMD_OPEN_ID: HomieID = HomieID::new_const("open");
const CMD_CLOSE_ID: HomieID = HomieID::new_const("close");
const CMD_OPEN_HALF_ID: HomieID = HomieID::new_const("open-half");
const CMD_STEPSTEP_ID: HomieID = HomieID::new_const("step");

/// Read the value stored in the specified register.
#[derive(clap::Parser)]
struct Args {
    /// How to connect to the MQTT broker.
    ///
    /// The value is expected to be provided as an URL, such as:
    /// `mqtt://location:1883?client_id=hostname` for plain text connection or
    /// `mqtts://location:1883?client_id=hostname` for TLS protected connection.
    #[clap(short = 'm', long)]
    mqtt_broker: String,

    /// To be provided together with `--mqtt-password` to use password based authentication
    /// with the broker.
    #[clap(short = 'u', long, requires = "mqtt_password")]
    mqtt_user: Option<String>,

    /// To be provided together with `--mqtt-user` to use password based authentication with
    /// the broker.
    #[clap(short = 'p', long, requires = "mqtt_user")]
    mqtt_password: Option<String>,

    #[clap(long, default_value = "uzparine")]
    device_name: String,

    /// Specify GPIO pin that indicates whether the gate is not closed.
    ///
    /// Value should be the `{name of the pin}={value when gate is not closed}`
    #[clap(long)]
    status_not_closed_gpio: Option<String>,

    /// Specify GPIO pin that needs to be toggled in order to send the Open Gate command.
    ///
    /// Value should be the `{name of the pin}={pin value when activating the command}`
    #[clap(long)]
    command_open_gpio: Option<String>,

    /// Specify GPIO pin that needs to be toggled in order to send the Close Gate command.
    ///
    /// Value should be the `{name of the pin}={pin value when activating the command}`
    #[clap(long)]
    command_close_gpio: Option<String>,

    /// Specify GPIO pin that needs to be toggled in order to send the StepStep command.
    ///
    /// Value should be the `{name of the pin}={pin value when activating the command}`
    #[clap(long)]
    command_step_step_gpio: Option<String>,

    /// Specify GPIO pin that needs to be toggled in order to send the Pedestrian command.
    ///
    /// Value should be the `{name of the pin}={pin value when activating the command}`
    #[clap(long)]
    command_pedestrian_gpio: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("could not parse the `--mqtt-broker` argument")]
    ParseMqttBroker(#[source] rumqttc::v5::OptionError),
    #[error("could not publish init value to the state topic")]
    PublishInitState(#[source] rumqttc::v5::ClientError),
    #[error("could not construct device description message")]
    GenerateDescription(#[source] homie5::Homie5ProtocolError),
    #[error("could not publish the device description")]
    PublishDescription(#[source] rumqttc::v5::ClientError),
    #[error("could not publish ready value to the state topic")]
    PublishReadyState(#[source] rumqttc::v5::ClientError),
    #[error("could not publish a value")]
    PublishValue(#[source] rumqttc::v5::ClientError),
    #[error("could not construct the message to subscribe")]
    GenerateSubscribtions(#[source] homie5::Homie5ProtocolError),
    #[error("could not subscribe to the homie setters")]
    Subscribe(#[source] rumqttc::v5::ClientError),
    #[error("{0} is an invalid gpio pin description, should be `{{pin}}={{value}}`")]
    InvalidArgument(String),
    #[error("invalid value in gpio pin description")]
    PinValue(#[source] std::num::ParseIntError),
    #[error("could not request the GPIO line")]
    GpioLineRequest(#[source] gpiocdev::Error),
    #[error("when handling gpio {0} found an already handled use-case??")]
    MultipleGpioMatch(String),
    #[error("gpio line for {0} not found!")]
    RequestedLineNotFound(String),
    #[error("gpio value for current state could not be read")]
    GetGpioValue(#[source] gpiocdev::Error),
    #[error("could not iterate GPIO lines")]
    GpioLines(#[source] gpiocdev::Error),
    #[error("error occurred while waiting for GPIO edge events")]
    AwaitGpioEvent(#[source] gpiocdev::Error),
    #[error("mqtt connection error")]
    MqttConnection(#[source] rumqttc::v5::ConnectionError),
    #[error("could not activate the command gpio for {1}")]
    ActivateGpio(#[source] gpiocdev::Error, &'static str),
    #[error("could not deactivate the command gpio {1}")]
    DeactivateGpio(#[source] gpiocdev::Error, &'static str),
    #[error("could not parse the specified device-id")]
    ParseDeviceId(#[source] homie5::InvalidHomieIDError),
}

fn main() {
    let filter_description = std::env::var("UZPARINE_LOG");
    let filter_description = filter_description.as_deref().unwrap_or("info");
    let filter = filter_description.parse::<tracing_subscriber::filter::targets::Targets>();
    match &filter {
        Ok(f) => tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(f.clone())
            .init(),
        Err(e) => end(Err(e)),
    }
    tracing::debug!(filter = filter_description, message = "logging initiated");
    let args = Args::parse();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let localset = tokio::task::LocalSet::new();
    end(localset.block_on(&runtime, run(&args)));
}

async fn run(args: &Args) -> Result<(), Error> {
    let mut mqtt_options =
        MqttOptions::parse_url(&args.mqtt_broker).map_err(Error::ParseMqttBroker)?;
    if let Some((u, p)) = args
        .mqtt_user
        .as_ref()
        .and_then(|u| Some((u, args.mqtt_password.as_ref()?)))
    {
        mqtt_options.set_credentials(u, p);
    }

    let (protocol, last_will) = homie5::Homie5DeviceProtocol::new(
        args.device_name.clone().try_into().map_err(Error::ParseDeviceId)?,
        homie5::HomieDomain::Default,
    );
    mqtt_options.set_last_will(LastWill::new(
        last_will.topic,
        last_will.message,
        convert_qos(last_will.qos),
        last_will.retain,
        None,
    ));
    let (client, mut client_loop) = AsyncClient::new(mqtt_options, 100);
    let device = HomieDevice::new(client, protocol, &args)?;
    loop {
        let result = client_loop.poll().await;
        match result.map_err(Error::MqttConnection)? {
            MqttEvent::Incoming(Packet::ConnAck(_)) => {
                tracing::info!("connected to mqtt");
                let () = device.publish_device().await?;
                if let Some(gpio_monitor) = device.monitor_status() {
                    tokio::task::spawn_local(gpio_monitor);
                }
            }
            MqttEvent::Incoming(Packet::Publish(publish)) => {
                let () = device.handle_incoming_publish(publish).await?;
            }
            MqttEvent::Outgoing(Outgoing::Disconnect) => {
                error!("disconnected from mqtt, wrapping up");
                break;
            }
            MqttEvent::Incoming(_) | MqttEvent::Outgoing(_) => continue,
        };
    }

    Ok(())
}

pub fn convert_qos(homie: homie5::client::QoS) -> rumqttc::v5::mqttbytes::QoS {
    use homie5::client::QoS::*;
    match homie {
        AtMostOnce => rumqttc::v5::mqttbytes::QoS::AtMostOnce,
        AtLeastOnce => rumqttc::v5::mqttbytes::QoS::AtLeastOnce,
        ExactlyOnce => rumqttc::v5::mqttbytes::QoS::ExactlyOnce,
    }
}

fn end<E: std::error::Error>(r: Result<(), E>) {
    std::process::exit(match r {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            let mut cause = e.source();
            while let Some(e) = cause {
                eprintln!("  because: {e}");
                cause = e.source();
            }
            1
        }
    });
}

struct HomieDevice {
    mqtt: AsyncClient,
    protocol: Homie5DeviceProtocol,
    description: HomieDeviceDescription,
    status_gpio: RefCell<Option<gpiocdev::Request>>,
    open_gpio: Option<gpiocdev::Request>,
    close_gpio: Option<gpiocdev::Request>,
    pedestrian_gpio: Option<gpiocdev::Request>,
    stepstep_gpio: Option<gpiocdev::Request>,
}

impl HomieDevice {
    pub fn new(
        mqtt: AsyncClient,
        protocol: Homie5DeviceProtocol,
        args: &Args,
    ) -> Result<Self, Error> {
        let mut status_gpio = None;
        let (mut open_gpio, mut close_gpio) = (None, None);
        let (mut pedestrian_gpio, mut stepstep_gpio) = (None, None);
        for line in gpiocdev::lines().map_err(Error::GpioLines)? {
            tracing::debug!(
                chip = ?line.chip,
                offset = line.info.offset,
                name = line.info.name,
                consumer = line.info.consumer,
                is_used = line.info.used,
                message = "discovered a gpio line"
            );
            let check_line = |name_to_match: &Option<String>| {
                let Some(name_to_match) = name_to_match else {
                    return Ok(None);
                };
                let Some((name, value)) = name_to_match.split_once('=') else {
                    return Err(Error::InvalidArgument(name_to_match.clone()));
                };
                let default_value = value.parse::<u8>().map_err(Error::PinValue)?;
                Ok((line.info.name == name).then_some(default_value))
            };
            let output = |default_value: u8| {
                let mut builder = gpiocdev::Request::builder();
                builder.with_found_line(&line);
                builder.as_output(gpiocdev::line::Value::Inactive);
                match default_value {
                    0 => builder.as_active_low(),
                    _ => builder.as_active_high(),
                };
                builder.request().map_err(Error::GpioLineRequest)
            };
            if let Some(_) = check_line(&args.status_not_closed_gpio)? {
                let io = gpiocdev::Request::builder()
                    .with_found_line(&line)
                    .with_edge_detection(EdgeDetection::BothEdges)
                    .with_debounce_period(std::time::Duration::from_millis(1))
                    .request()
                    .map_err(Error::GpioLineRequest)?;
                if let Some(_) = status_gpio.replace(io) {
                    let n = args.status_not_closed_gpio.as_deref().unwrap_or("");
                    return Err(Error::MultipleGpioMatch(n.to_string()));
                }
            }
            if let Some(default_value) = check_line(&args.command_open_gpio)? {
                let io = output(default_value)?;
                if let Some(_) = open_gpio.replace(io) {
                    let n = args.command_open_gpio.as_deref().unwrap_or("");
                    return Err(Error::MultipleGpioMatch(n.to_string()));
                }
            }
            if let Some(default_value) = check_line(&args.command_close_gpio)? {
                let io = output(default_value)?;
                if let Some(_) = close_gpio.replace(io) {
                    let n = args.command_close_gpio.as_deref().unwrap_or("");
                    return Err(Error::MultipleGpioMatch(n.to_string()));
                }
            }
            if let Some(default_value) = check_line(&args.command_pedestrian_gpio)? {
                let io = output(default_value)?;
                if let Some(_) = pedestrian_gpio.replace(io) {
                    let n = args.command_pedestrian_gpio.as_deref().unwrap_or("");
                    return Err(Error::MultipleGpioMatch(n.to_string()));
                }
            }
            if let Some(default_value) = check_line(&args.command_step_step_gpio)? {
                let io = output(default_value)?;
                if let Some(_) = stepstep_gpio.replace(io) {
                    let n = args.command_step_step_gpio.as_deref().unwrap_or("");
                    return Err(Error::MultipleGpioMatch(n.to_string()));
                }
            }
        }
        let verify_found_if_requested = |lh: bool, arg: &Option<String>, name: &str| {
            if arg.is_some() && !lh {
                return Err(Error::RequestedLineNotFound(name.to_string()));
            }
            Ok(())
        };
        verify_found_if_requested(
            status_gpio.is_some(),
            &args.status_not_closed_gpio,
            "status-not-closed-gpio",
        )?;
        verify_found_if_requested(
            open_gpio.is_some(),
            &args.command_open_gpio,
            "command-open-gpio",
        )?;
        verify_found_if_requested(
            close_gpio.is_some(),
            &args.command_close_gpio,
            "command-close-gpio",
        )?;
        verify_found_if_requested(
            pedestrian_gpio.is_some(),
            &args.command_pedestrian_gpio,
            "command-pedestrian-gpio",
        )?;
        verify_found_if_requested(
            stepstep_gpio.is_some(),
            &args.command_step_step_gpio,
            "command-step-step-gpio",
        )?;

        let cmd_prop = PropertyDescriptionBuilder::new(homie5::HomieDataType::Boolean)
            .retained(false)
            .settable(true)
            .build();
        let mut node = NodeDescriptionBuilder::new().name("gate");
        if status_gpio.is_some() {
            node = node.add_property(
                STATUS_ID,
                PropertyDescriptionBuilder::new(homie5::HomieDataType::Boolean)
                    .retained(true)
                    .build(),
            );
        }
        if open_gpio.is_some() {
            node = node.add_property(CMD_OPEN_ID, cmd_prop.clone());
        }
        if close_gpio.is_some() {
            node = node.add_property(CMD_CLOSE_ID, cmd_prop.clone());
        }
        if stepstep_gpio.is_some() || true {
            node = node.add_property(CMD_STEPSTEP_ID, cmd_prop.clone());
        }
        if pedestrian_gpio.is_some() {
            node = node.add_property(CMD_OPEN_HALF_ID, cmd_prop.clone());
        }
        let description = homie5::device_description::DeviceDescriptionBuilder::new()
            .name("uzparine")
            .add_node(NODE_ID, node.build())
            .build();
        Ok(Self {
            mqtt,
            protocol,
            description,
            status_gpio: status_gpio.into(),
            open_gpio,
            close_gpio,
            pedestrian_gpio,
            stepstep_gpio,
        })
    }

    pub async fn publish_device(&self) -> Result<(), Error> {
        for step in homie5::homie_device_publish_steps() {
            match step {
                homie5::DevicePublishStep::DeviceStateInit => {
                    let p = self.protocol.publish_state(HomieDeviceStatus::Init);
                    self.mqtt
                        .homie_publish(p)
                        .await
                        .map_err(Error::PublishInitState)?;
                }
                homie5::DevicePublishStep::DeviceDescription => {
                    let p = self
                        .protocol
                        .publish_description(&self.description)
                        .map_err(Error::GenerateDescription)?;
                    self.mqtt
                        .homie_publish(p)
                        .await
                        .map_err(Error::PublishDescription)?;
                }
                homie5::DevicePublishStep::PropertyValues => {
                    if let Some(status_gpio) = &*self.status_gpio.borrow() {
                        let value = match status_gpio.lone_value().map_err(Error::GetGpioValue)? {
                            gpiocdev::line::Value::Inactive => "false",
                            gpiocdev::line::Value::Active => "true",
                        };
                        let p = self
                            .protocol
                            .publish_value(&NODE_ID, &STATUS_ID, value, true);
                        self.mqtt
                            .homie_publish(p)
                            .await
                            .map_err(Error::PublishValue)?;
                    }
                }
                homie5::DevicePublishStep::SubscribeProperties => {
                    let p = self
                        .protocol
                        .subscribe_props(&self.description)
                        .map_err(Error::GenerateSubscribtions)?;
                    self.mqtt
                        .homie_subscribe(p)
                        .await
                        .map_err(Error::Subscribe)?;
                }
                homie5::DevicePublishStep::DeviceStateReady => {
                    let p = self.protocol.publish_state(HomieDeviceStatus::Ready);
                    self.mqtt
                        .homie_publish(p)
                        .await
                        .map_err(Error::PublishReadyState)?;
                }
            }
        }
        Ok(())
    }

    pub fn monitor_status(&self) -> Option<impl 'static + Future<Output = Result<(), Error>>> {
        if let Some(status_gpio) = self.status_gpio.borrow_mut().take() {
            let client = self.mqtt.clone();
            let protocol = self.protocol.clone();
            Some(async move {
                let gpio = gpiocdev::tokio::AsyncRequest::new(status_gpio);
                loop {
                    let Some(result) = gpio.edge_events().next().await else {
                        return Ok(());
                    };
                    let value = match result.map_err(Error::AwaitGpioEvent)?.kind {
                        EdgeKind::Rising => "true",
                        EdgeKind::Falling => "false",
                    };
                    let p = protocol.publish_value(&NODE_ID, &STATUS_ID, value, true);
                    client.homie_publish(p).await.map_err(Error::PublishValue)?;
                }
            })
        } else {
            None
        }
    }

    pub async fn handle_incoming_publish(&self, msg: MqttPublish) -> Result<(), Error> {
        let Ok(topic) = std::str::from_utf8(&msg.topic) else {
            warn!("received mqtt message with topic that isn't utf8, ignoring");
            return Ok(());
        };
        match homie5::parse_mqtt_message(topic, &msg.payload) {
            Ok(homie5::Homie5Message::PropertySet {
                property,
                set_value,
            }) => {
                let node = property.node_id().clone();
                if node != NODE_ID {
                    warn!(?node, "received mqtt message for node we don't handle");
                    return Ok(());
                }
                let property = property.prop_id().clone();
                info!(?property, ?set_value, "received a command");
                let act_on = async |gpio_ty: &'static str, gpio: &Option<gpiocdev::Request>| {
                    if let Some(gpio) = gpio {
                        gpio.set_lone_value(Value::Active)
                            .map_err(|e| Error::ActivateGpio(e, gpio_ty))?;
                        sleep(Duration::from_millis(100)).await;
                        gpio.set_lone_value(Value::Inactive)
                            .map_err(|e| Error::DeactivateGpio(e, gpio_ty))?;
                    } else {
                        warn!(?node, gpio_ty, "gpio is not configured, ignoring");
                    }
                    Ok::<_, Error>(())
                };
                if property == CMD_STEPSTEP_ID {
                    act_on("step-step", &self.stepstep_gpio).await?;
                } else if property == CMD_OPEN_HALF_ID {
                    act_on("open-half", &self.pedestrian_gpio).await?;
                } else if property == CMD_CLOSE_ID {
                    act_on("close", &self.close_gpio).await?;
                } else if property == CMD_OPEN_ID {
                    act_on("open", &self.open_gpio).await?;
                } else {
                    warn!(?node, ?property, "command for an unknown property");
                }
            }
            Ok(msg) => debug!(?msg, "received a message we don't handle"),
            Err(e) => error!(
                error = &e as &dyn StdError,
                ?msg.topic, ?msg.payload, "received invalid mqtt message"
            ),
        }
        Ok(())
    }
}

trait MqttClientExt {
    type PublishError;
    type SubscribeError;
    async fn homie_publish(&self, p: HomiePublish) -> Result<(), Self::PublishError>;
    async fn homie_subscribe(
        &self,
        subs: impl Iterator<Item = Subscription> + Send,
    ) -> Result<(), Self::SubscribeError>;
}

impl MqttClientExt for rumqttc::v5::AsyncClient {
    type PublishError = rumqttc::v5::ClientError;
    type SubscribeError = rumqttc::v5::ClientError;
    async fn homie_publish(&self, p: HomiePublish) -> Result<(), Self::PublishError> {
        self.publish(p.topic, convert_qos(p.qos), p.retain, p.payload)
            .await
    }

    async fn homie_subscribe(
        &self,
        subs: impl Iterator<Item = Subscription> + Send,
    ) -> Result<(), Self::SubscribeError> {
        let subs = subs
            .map(|sub| rumqttc::v5::mqttbytes::v5::Filter::new(sub.topic, convert_qos(sub.qos)))
            .collect::<Vec<_>>();
        if subs.is_empty() {
            return Ok(());
        }
        self.subscribe_many(subs).await
    }
}
