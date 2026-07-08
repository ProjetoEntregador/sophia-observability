import json
import os
import time
import uuid
from datetime import datetime, timezone

import pika
import psycopg2
from dateutil import parser
from psycopg2.extras import Json


RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.getenv("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "admin")
RABBITMQ_PASSWORD = os.getenv("RABBITMQ_PASSWORD", "admin")
RABBITMQ_QUEUE = os.getenv("RABBITMQ_QUEUE", "audit.events")

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "audit-db")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_USER = os.getenv("POSTGRES_USER", "audit_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "audit_password")
POSTGRES_DB = os.getenv("POSTGRES_DB", "audit_db")


REQUIRED_FIELDS = [
    "service",
    "entity",
    "operation",
    "occurredAt",
]


def get_postgres_connection():
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
        dbname=POSTGRES_DB,
    )


def parse_timestamp(value):
    if not value:
        return datetime.now(timezone.utc)

    parsed = parser.isoparse(value)

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def normalize_operation(operation):
    return str(operation).strip().upper()


def validate_event(event):
    if not isinstance(event, dict):
        raise ValueError("Event must be a JSON object.")

    missing_fields = [
        field for field in REQUIRED_FIELDS
        if not event.get(field)
    ]

    if missing_fields:
        raise ValueError(
            f"Missing required fields: {', '.join(missing_fields)}"
        )

    if not isinstance(event.get("service"), str):
        raise ValueError("service must be a string.")

    if not isinstance(event.get("entity"), str):
        raise ValueError("entity must be a string.")

    if not isinstance(event.get("operation"), str):
        raise ValueError("operation must be a string.")

    parse_timestamp(event["occurredAt"])


def save_audit_event(event):
    validate_event(event)

    occurredAt = parse_timestamp(event["occurredAt"])

    with get_postgres_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_events (
                    service,
                    entity,
                    old_data,
                    new_data,
                    operation,
                    changed_by,
                    occurred_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s);
                """,
                (
                    event["service"],
                    event["entity"],
                    Json(event.get("oldData")),
                    Json(event.get("newData")),
                    normalize_operation(event["operation"]),
                    event.get("changedBy"),
                    occurredAt,
                ),
            )


def create_security_alert_if_needed(event):
    operation = normalize_operation(event.get("operation"))
    service = event.get("service", "unknown-service")

    alert_operations = {
        "DELETE": "warning",
        "ACCESS_DENIED": "critical",
        "EXPORT": "warning",
    }

    if operation not in alert_operations:
        return

    severity = alert_operations[operation]

    message = f"{operation} event detected in {service}"

    details = {
        "service": event.get("service"),
        "entity": event.get("entity"),
        "operation": operation,
        "changedBy": event.get("changedBy"),
        "oldData": event.get("oldData"),
        "newData": event.get("newData"),
        "occurredAt": event.get("occurredAt"),
    }

    with get_postgres_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO security_alerts (
                    service,
                    severity,
                    alert_type,
                    message,
                    details
                )
                VALUES (%s, %s, %s, %s, %s);
                """,
                (
                    service,
                    severity,
                    f"audit_{operation.lower()}",
                    message,
                    Json(details),
                ),
            )


def process_message(channel, method, properties, body):
    try:
        event = json.loads(body.decode("utf-8"))

        save_audit_event(event)
        create_security_alert_if_needed(event)

        channel.basic_ack(delivery_tag=method.delivery_tag)

        print(
            "[AUDIT] Event processed:",
            event.get("service"),
            event.get("entity"),
            normalize_operation(event.get("operation")),
            flush=True,
        )

    except json.JSONDecodeError as exc:
        print("[AUDIT] Invalid JSON:", str(exc), flush=True)

        channel.basic_nack(
            delivery_tag=method.delivery_tag,
            requeue=False,
        )

    except ValueError as exc:
        print("[AUDIT] Invalid audit event:", str(exc), flush=True)

        channel.basic_nack(
            delivery_tag=method.delivery_tag,
            requeue=False,
        )

    except Exception as exc:
        print("[AUDIT] Failed to process message:", str(exc), flush=True)

        channel.basic_nack(
            delivery_tag=method.delivery_tag,
            requeue=True,
        )


def connect_rabbitmq():
    credentials = pika.PlainCredentials(
        RABBITMQ_USER,
        RABBITMQ_PASSWORD,
    )

    parameters = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        credentials=credentials,
        heartbeat=60,
        blocked_connection_timeout=30,
    )

    return pika.BlockingConnection(parameters)


def main():
    while True:
        try:
            print("[AUDIT] Connecting to RabbitMQ...", flush=True)

            connection = connect_rabbitmq()
            channel = connection.channel()

            channel.queue_declare(
                queue=RABBITMQ_QUEUE,
                durable=True,
            )

            channel.basic_qos(prefetch_count=10)

            channel.basic_consume(
                queue=RABBITMQ_QUEUE,
                on_message_callback=process_message,
            )

            print(
                f"[AUDIT] Waiting for messages from queue: {RABBITMQ_QUEUE}",
                flush=True,
            )

            channel.start_consuming()

        except Exception as exc:
            print("[AUDIT] Consumer connection error:", str(exc), flush=True)
            print("[AUDIT] Retrying in 5 seconds...", flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main()