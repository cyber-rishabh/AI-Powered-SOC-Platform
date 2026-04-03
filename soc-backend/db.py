"""
db.py — Elasticsearch async client
"""

import os
from elasticsearch import AsyncElasticsearch
from dotenv import load_dotenv

load_dotenv()

ES_URL      = os.getenv("ES_URL",    "http://localhost:9200")
ES_USER     = os.getenv("ES_USER",   "")
ES_PASSWORD = os.getenv("ES_PASS",   "")
LOG_INDEX   = os.getenv("LOG_INDEX", "soc-logs")

es: AsyncElasticsearch = None

LOG_MAPPING = {
    "mappings": {
        "properties": {
            "id":          {"type": "keyword"},
            "timestamp":   {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
            "ingested_at": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
            "event_type":  {"type": "keyword"},
            "source":      {"type": "keyword"},
            "user":        {"type": "keyword"},
            "host":        {"type": "keyword"},
            "tags":        {"type": "keyword"},
            "parent_proc": {"type": "keyword"},
            "process": {
                "type": "text",
                "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}
            },
            "process_id": {"type": "integer"},
            "port_dst":   {"type": "integer"},
            "ip_src":     {"type": "ip"},
            "ip_dst":     {"type": "ip"},
            "raw":        {"type": "object", "enabled": False},
        },
        # dynamic: false  →  unknown fields (NXLog sends many: Keywords,
        # SeverityValue, OpcodeValue, RecordNumber, etc.) are silently IGNORED
        # instead of rejected. They still appear in _source but aren't indexed.
        # Never use "strict" with real-world NXLog data.
        "dynamic": False,
    },
    "settings": {
        "number_of_shards":   1,
        "number_of_replicas": 0,
        "refresh_interval":   "1s",
    },
}


async def connect_db():
    global es
    kwargs = {"hosts": [ES_URL]}
    if ES_USER and ES_PASSWORD:
        kwargs["basic_auth"] = (ES_USER, ES_PASSWORD)

    es = AsyncElasticsearch(**kwargs)

    exists = await es.indices.exists(index=LOG_INDEX)
    if not exists:
        await es.indices.create(index=LOG_INDEX, body=LOG_MAPPING)
        print(f"[ES] Created index '{LOG_INDEX}' with dynamic:false mapping")
    else:
        print(f"[ES] Index '{LOG_INDEX}' already exists")

    info = await es.info()
    print(f"[ES] Connected — Elasticsearch {info['version']['number']} @ {ES_URL}")


async def close_db():
    global es
    if es:
        await es.close()
        print("[ES] Connection closed")


async def reset_index():
    """
    Delete and recreate the index with the correct mapping.
    Call this once after fixing the mapping.
    WARNING: deletes all existing data.
    """
    if await es.indices.exists(index=LOG_INDEX):
        await es.indices.delete(index=LOG_INDEX)
        print(f"[ES] Deleted old index '{LOG_INDEX}'")
    await es.indices.create(index=LOG_INDEX, body=LOG_MAPPING)
    print(f"[ES] Recreated '{LOG_INDEX}' with correct mapping")


def get_es() -> AsyncElasticsearch:
    return es


def get_index() -> str:
    return LOG_INDEX
