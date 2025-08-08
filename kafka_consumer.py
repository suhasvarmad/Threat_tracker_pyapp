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

            # --- NEW: Smart Vendor Detection ---
            vendor = 'unknown'
            try:
                # First, try to parse the string as JSON
                log_data = json.loads(raw_log_str)

                # Look for the vendor in common locations
                if '_source' in log_data and 'rule' in log_data['_source']:
                    vendor = 'elastic' # It's a Wazuh-in-Elastic log
                elif 'dataSource' in log_data and 'vendor' in log_data['dataSource']:
                    vendor = log_data['dataSource']['vendor']

            except json.JSONDecodeError:
                logging.error("Could not parse JSON from Kafka message.")
                continue # Skip this message

            # --- Use the detected vendor ---
            unified_log = process_log(raw_log_str, vendor=vendor.lower())

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