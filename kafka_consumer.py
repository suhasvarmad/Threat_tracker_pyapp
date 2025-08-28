# In kafka_consumer.py
import yaml
import logging
import json
from confluent_kafka import Consumer
from processor.main import process_log
from elasticsearch import Elasticsearch

def load_config():
    """Loads the application configuration from config.yaml."""
    with open('config.yaml', 'r') as f:
        return yaml.safe_load(f)

def main():
    """Connects to Kafka, consumes messages, processes them, and saves to Elasticsearch."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler("consumer.log"), logging.StreamHandler()]
    )

    config = load_config()
    kafka_settings = config.get('kafka', {})
    es_settings = config.get('elasticsearch', {})

    # --- Kafka Configuration ---
    KAFKA_CONFIG = {
        'bootstrap.servers': kafka_settings.get('bootstrap_servers'),
        'group.id': kafka_settings.get('group_id'),
        'auto.offset.reset': 'earliest'
    }
    KAFKA_TOPIC = kafka_settings.get('topic')

    # --- Elasticsearch Client Setup ---
    ES_HOST = es_settings.get('hosts')
    ES_INDEX = es_settings.get('index_name')
    try:
        es_client = Elasticsearch(ES_HOST)
        logging.info(f"Successfully connected to Elasticsearch at {ES_HOST}")
    except Exception as e:
        logging.error(f"Could not connect to Elasticsearch: {e}")
        return

    consumer = Consumer(KAFKA_CONFIG)
    consumer.subscribe([KAFKA_TOPIC])
    logging.info(f"Subscribed to topic '{KAFKA_TOPIC}'. Waiting for messages...")

    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None: continue
            if msg.error():
                logging.error(f"Consumer error: {msg.error()}"); continue

            raw_log_str = msg.value().decode('utf-8')
            logging.info("--- Received Raw Log from Kafka ---")

            # --- Parse the outer message (Vector may wrap the real JSON in "message") ---
            try:
                outer = json.loads(raw_log_str)
            except json.JSONDecodeError:
                logging.error("Could not parse JSON from Kafka message (outer). Skipping.")
                continue

            # Try to unwrap inner JSON if present (Vector file source usually puts the line in 'message')
            inner_payload = None

            # Common Vector shapes:
            # 1) {"file": "...", "host": "...", "message": "{\"vendor\":\"...\", ...}", "timestamp": "..."}
            # 2) {"event": {"fullLog": "{\"vendor\":\"...\", ...}"}, ...}
            # 3) Manual ingestion: already the vendor JSON (no wrapping)

            # Candidate 1: outer["message"] is JSON string
            msg_field = outer.get("message")
            if isinstance(msg_field, str):
                try:
                    # strip CR/LF noise that can break JSON parsing
                    inner_payload = json.loads(msg_field.strip())
                except json.JSONDecodeError:
                    inner_payload = None

            # Candidate 2: outer["event"]["fullLog"] is JSON string
            if inner_payload is None:
                full_log = (outer.get("event") or {}).get("fullLog")
                if isinstance(full_log, str):
                    try:
                        inner_payload = json.loads(full_log.strip())
                    except json.JSONDecodeError:
                        inner_payload = None

            # Choose effective payload:
            # - If we found a valid inner JSON -> use it (Vector case)
            # - Else -> use the outer object (manual ingestion case)
            effective = inner_payload if inner_payload is not None else outer

            # --- Smart Vendor Detection on the *effective* payload ---
            vendor = 'unknown'
            try:
                if isinstance(effective, dict):
                    # Wazuh-in-Elastic style
                    if '_source' in effective and 'rule' in effective['_source']:
                        vendor = 'elastic'
                    # SentinelOne style
                    elif 'dataSource' in effective and isinstance(effective['dataSource'], dict) and \
                         'vendor' in effective['dataSource']:
                        vendor = effective['dataSource']['vendor']
                else:
                    # edge case: effective is not a dict (shouldn't happen after json loads)
                    pass
            except Exception as e:
                logging.warning(f"Vendor detection error (non-fatal): {e}")

            # --- Hand off to your existing mapper exactly as before, but with unwrapped payload ---
            try:
                unified_log = process_log(json.dumps(effective), vendor=vendor.lower())
            except Exception as e:
                logging.error(f"process_log failed: {e}")
                continue

            if unified_log:
                logging.info("--- Successfully Unified Log ---")
                try:
                    log_document = json.loads(unified_log)
                    response = es_client.index(index=ES_INDEX, document=log_document)
                    logging.info(f"Successfully indexed document to Elasticsearch with ID: {response.get('_id')}")
                except Exception as e:
                    logging.error(f"Failed to index document to Elasticsearch: {e}")

    except KeyboardInterrupt:
        logging.info("Stopping consumer.")
    finally:
        consumer.close()
        logging.info("Consumer closed.")

if __name__ == '__main__':
    main()