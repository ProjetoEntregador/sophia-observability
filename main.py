import json
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import pika
import psycopg2
from dateutil import parser
from psycopg2.extras import Json


RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.getenv("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "admin")
RABBITMQ_PASSWORD = os.getenv("RABBITMQ_PASSWORD", "admin")
RABBITMQ_QUEUE = os.getenv("RABBITMQ_QUEUE", "audit.queue")

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "audit-db")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_USER = os.getenv("POSTGRES_USER", "audit_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "audit_password")
POSTGRES_DB = os.getenv("POSTGRES_DB", "audit_db")

PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")

ALERT_CHECK_INTERVAL_SECONDS = 30

ALERT_COOLDOWN_MINUTES = 2

MAX_CONNECTIONS = 15
MAX_CHANGES_2M = 50
MAX_DELETES_2M = 20
MAX_QUERY_SECONDS = 30
MAX_LOCK_SECONDS = 15
MAX_MEAN_QUERY_TIME_MS = 2000

REQUIRED_FIELDS = [
    "service",
    "entity",
    "operation",
    "occurredAt",
]

DEFAULT_MONITORED_TARGETS = """
[
  {
    "metrics_service": "pharmacy",
    "database": "pharmacy_db",
    "audit_service": "pharmacy"
  },
  {
    "metrics_service": "medication",
    "database": "medication_db",
    "audit_service": "medication"
  },
  {
    "metrics_service": "notification",
    "database": "notification_db",
    "audit_service": "notification"
  }
]
"""

MONITORED_TARGETS = json.loads(
    os.getenv("MONITORED_TARGETS_JSON", DEFAULT_MONITORED_TARGETS)
)

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()

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

    if isinstance(value, (int, float)):
        if value > 10_000_000_000:
            value = value / 1000

        return datetime.fromtimestamp(value, tz=timezone.utc)

    if not isinstance(value, str):
        raise ValueError(
            "occurredAt must be an ISO datetime string or Unix timestamp."
        )

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

    if not isinstance(event.get("occurredAt"), (str, int, float)):
        raise ValueError("occurredAt must be a string, int or float.")

    parse_timestamp(event["occurredAt"])

def query_prometheus(promql):
    encoded_query = urllib.parse.quote(promql)

    url = f"{PROMETHEUS_URL}/api/v1/query?query={encoded_query}"

    with urllib.request.urlopen(url, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))

    if payload.get("status") != "success":
        raise RuntimeError(f"Prometheus query failed: {payload}")

    return payload["data"]["result"]

def get_prometheus_single_value(promql):
    result = query_prometheus(promql)

    if not result:
        return 0.0

    value = result[0]["value"][1]

    if value in ("NaN", "+Inf", "-Inf"):
        return 0.0

    return float(value)

def create_security_alert(
    cursor,
    service,
    severity,
    alert_type,
    message,
    details=None,
    cooldown_minutes=ALERT_COOLDOWN_MINUTES,
):
    details = details or {}

    cursor.execute(
        """
        SELECT 1
        FROM security_alerts
        WHERE service = %s
          AND alert_type = %s
          AND created_at >= NOW() - (%s * INTERVAL '2 minutes')
        LIMIT 1;
        """,
        (
            service,
            alert_type,
            cooldown_minutes,
        ),
    )

    already_exists = cursor.fetchone()

    if already_exists:
        print(
            f"[ALERT] Skipped by cooldown: {service} / {alert_type}",
            flush=True,
        )
        return

    cursor.execute(
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
            alert_type,
            message,
            Json(details),
        ),
    )

    print(
        f"[ALERT] Created: {service} / {alert_type} ({severity})",
        flush=True,
    )

def save_audit_event(cursor, event):
    occurred_at = parse_timestamp(event["occurredAt"])

    cursor.execute(
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
            occurred_at,
        ),
    )

def process_audit_event(event):
    validate_event(event)

    connection = get_postgres_connection()
    connection.autocommit = False

    try:
        with connection.cursor() as cursor:
            save_audit_event(cursor, event)

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

def process_message(channel, method, properties, body):
    try:
        event = json.loads(body.decode("utf-8"))

        process_audit_event(event)

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

    except (ValueError, TypeError) as exc:
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

def check_many_changes(cursor, target):
    audit_service = target["audit_service"]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM audit_events
        WHERE service = %s
          AND operation IN ('CREATE', 'INSERT', 'UPDATE')
          AND occurred_at >= NOW() - INTERVAL '2 minutes';
        """,
        (audit_service,),
    )

    changes = int(cursor.fetchone()[0] or 0)

    if changes > MAX_CHANGES_2M:
        create_security_alert(
            cursor=cursor,
            service=audit_service,
            severity="warning",
            alert_type="many_change_operations",
            message="High number of change operations detected.",
            details={
                "source": "audit_events",
                "service": audit_service,
                "operations": ["CREATE", "INSERT", "UPDATE"],
                "count": changes,
                "threshold": MAX_CHANGES_2M,
                "window": "2 minutes",
                "checkedAt": utc_now_iso(),
            },
        )

def check_many_deletes(cursor, target):
    audit_service = target["audit_service"]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM audit_events
        WHERE service = %s
          AND operation = 'DELETE'
          AND occurred_at >= NOW() - INTERVAL '2 minutes';
        """,
        (audit_service,),
    )

    deletes = int(cursor.fetchone()[0] or 0)

    if deletes > MAX_DELETES_2M:
        create_security_alert(
            cursor=cursor,
            service=audit_service,
            severity="critical",
            alert_type="many_delete_operations",
            message="High number of DELETE operations detected.",
            details={
                "source": "audit_events",
                "service": audit_service,
                "operation": "DELETE",
                "count": deletes,
                "threshold": MAX_DELETES_2M,
                "window": "2 minutes",
                "checkedAt": utc_now_iso(),
            },
        )

def check_many_connections(cursor, target):
    metrics_service = target["metrics_service"]
    database = target["database"]
    audit_service = target["audit_service"]

    promql = (
        "max("
        "pg_stat_activity_connections_by_state_count"
        f'{{service="{metrics_service}", datname="{database}"}}'
        ")"
    )

    connections = get_prometheus_single_value(promql)

    if connections > MAX_CONNECTIONS:
        create_security_alert(
            cursor=cursor,
            service=audit_service,
            severity="warning",
            alert_type="many_database_connections",
            message="High number of database connections detected.",
            details={
                "source": "prometheus",
                "promql": promql,
                "metricsService": metrics_service,
                "database": database,
                "connections": connections,
                "threshold": MAX_CONNECTIONS,
                "checkedAt": utc_now_iso(),
            },
        )

def check_long_queries(cursor, target):
    metrics_service = target["metrics_service"]
    database = target["database"]
    audit_service = target["audit_service"]

    promql = (
        "max("
        "pg_stat_activity_max_query_duration_duration_seconds"
        f'{{service="{metrics_service}", datname="{database}"}}'
        ")"
    )

    max_duration_seconds = get_prometheus_single_value(promql)

    if max_duration_seconds > MAX_QUERY_SECONDS:
        create_security_alert(
            cursor=cursor,
            service=audit_service,
            severity="warning",
            alert_type="long_running_query",
            message="Long running query detected.",
            details={
                "source": "prometheus",
                "promql": promql,
                "metricsService": metrics_service,
                "database": database,
                "maxDurationSeconds": max_duration_seconds,
                "thresholdSeconds": MAX_QUERY_SECONDS,
                "checkedAt": utc_now_iso(),
            },
        )

def check_long_locks(cursor, target):
    metrics_service = target["metrics_service"]
    database = target["database"]
    audit_service = target["audit_service"]

    promql = (
        "max("
        "pg_locks_count"
        f'{{service="{metrics_service}", datname="{database}"}}'
        ")"
    )

    max_lock_wait_seconds = get_prometheus_single_value(promql)

    if max_lock_wait_seconds > MAX_LOCK_SECONDS:
        create_security_alert(
            cursor=cursor,
            service=audit_service,
            severity="critical",
            alert_type="long_lock_wait",
            message="Long lock wait detected.",
            details={
                "source": "prometheus",
                "promql": promql,
                "metricsService": metrics_service,
                "database": database,
                "maxLockWaitSeconds": max_lock_wait_seconds,
                "thresholdSeconds": MAX_LOCK_SECONDS,
                "checkedAt": utc_now_iso(),
            },
        )

def check_slow_average_queries(cursor, target):
    metrics_service = target["metrics_service"]
    database = target["database"]
    audit_service = target["audit_service"]

    promql = (
        "max("
        "pg_stat_statements_top_mean_time_mean_exec_time"
        f'{{service="{metrics_service}", datname="{database}"}}'
        ")"
    )

    max_mean_exec_time_ms = get_prometheus_single_value(promql)

    if max_mean_exec_time_ms > MAX_MEAN_QUERY_TIME_MS:
        create_security_alert(
            cursor=cursor,
            service=audit_service,
            severity="warning",
            alert_type="slow_average_query",
            message="Slow average query detected.",
            details={
                "source": "prometheus",
                "promql": promql,
                "metricsService": metrics_service,
                "database": database,
                "maxMeanExecutionTimeMs": max_mean_exec_time_ms,
                "thresholdMs": MAX_MEAN_QUERY_TIME_MS,
                "checkedAt": utc_now_iso(),
            },
        )

def run_alert_checks():
    connection = get_postgres_connection()
    connection.autocommit = False

    try:
        with connection.cursor() as cursor:
            for target in MONITORED_TARGETS:
                print(
                    "[ALERT] Checking target:",
                    target["audit_service"],
                    target["metrics_service"],
                    target["database"],
                    flush=True,
                )

                check_many_changes(cursor, target)
                check_many_deletes(cursor, target)
                check_many_connections(cursor, target)
                check_long_queries(cursor, target)
                check_long_locks(cursor, target)
                check_slow_average_queries(cursor, target)

        connection.commit()

        print("[ALERT] Checks finished.", flush=True)

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

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

def create_rabbitmq_channel():
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
        auto_ack=False,
    )

    return connection, channel

def main():
    print("[APP] Starting audit observability service...", flush=True)
    print(f"[APP] RabbitMQ: {RABBITMQ_HOST}:{RABBITMQ_PORT}", flush=True)
    print(f"[APP] Queue: {RABBITMQ_QUEUE}", flush=True)
    print(f"[APP] Prometheus URL: {PROMETHEUS_URL}", flush=True)
    print(f"[APP] Alert interval: {ALERT_CHECK_INTERVAL_SECONDS}s", flush=True)

    print("[APP] Monitored targets:", flush=True)
    for target in MONITORED_TARGETS:
        print(
            f"  - audit_service={target['audit_service']} "
            f"metrics_service={target['metrics_service']} "
            f"database={target['database']}",
            flush=True,
        )

    rabbitmq_connection = None
    last_alert_check_at = 0

    while True:
        try:
            if rabbitmq_connection is None or rabbitmq_connection.is_closed:
                print("[APP] Connecting to RabbitMQ...", flush=True)
                rabbitmq_connection, _ = create_rabbitmq_channel()
                print("[APP] Connected to RabbitMQ.", flush=True)

            rabbitmq_connection.process_data_events(time_limit=1)

            now = time.time()

            if now - last_alert_check_at >= ALERT_CHECK_INTERVAL_SECONDS:
                print("[ALERT] Running checks...", flush=True)
                run_alert_checks()
                last_alert_check_at = now

        except pika.exceptions.AMQPError as exc:
            print("[APP] RabbitMQ error:", str(exc), flush=True)

            try:
                if rabbitmq_connection and not rabbitmq_connection.is_closed:
                    rabbitmq_connection.close()
            except Exception:
                pass

            rabbitmq_connection = None

            print("[APP] Retrying RabbitMQ in 5 seconds...", flush=True)
            time.sleep(5)

        except Exception as exc:
            print("[APP] Unexpected error:", str(exc), flush=True)
            print("[APP] Retrying in 5 seconds...", flush=True)
            time.sleep(5)

if __name__ == "__main__":
    main()