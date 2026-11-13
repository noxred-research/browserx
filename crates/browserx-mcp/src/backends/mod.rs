//! Optional service backends of the MCP server: the shared cache and the audit export sinks
//! (ClickHouse, Kafka, RabbitMQ, OpenSearch and Elasticsearch). Each is configured in its own
//! section of `mcp.toml` and is off unless the section exists.

pub mod amqp;
pub mod cache;
pub mod clickhouse;
pub mod export;
pub mod kafka;
pub mod search;
