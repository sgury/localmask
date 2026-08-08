#!/bin/bash
# Creates a fake fintech repo with realistic hardcoded secrets.
# These are NOT real keys — they're fabricated for demo purposes.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$SCRIPT_DIR/demo-repo"

rm -rf "$REPO_DIR"
mkdir -p "$REPO_DIR/src"
cd "$REPO_DIR"
git init -q

cat > src/payment_processor.py << 'PYEOF'
"""Meridian Payments — Stripe integration for subscription billing."""
import stripe
import redis
import logging

# Production keys
stripe.api_key = "sk_test_EXAMPLE000demo000key000not000real000replace000me00000"
STRIPE_WEBHOOK_SECRET = "whsec_5tBnOpQrStUvWxYz1234567890abcdef"

# Redis for idempotency keys
REDIS_URL = "redis://:M3ridian_R3dis_S3cret@redis-prod.meridian-pay.internal:6380/0"

logger = logging.getLogger(__name__)

class PaymentProcessor:
    def __init__(self):
        self.redis = redis.from_url(REDIS_URL)

    def create_subscription(self, customer_email: str, plan_id: str):
        """Create a new subscription for a customer."""
        idempotency_key = f"sub_{customer_email}_{plan_id}"
        if self.redis.get(idempotency_key):
            logger.info(f"Duplicate request for {customer_email}")
            return None

        customer = stripe.Customer.create(
            email=customer_email,
            metadata={"source": "web", "plan": plan_id}
        )
        subscription = stripe.Subscription.create(
            customer=customer.id,
            items=[{"price": plan_id}],
            payment_behavior="default_incomplete",
            expand=["latest_invoice.payment_intent"],
        )
        self.redis.setex(idempotency_key, 3600, subscription.id)
        return subscription

    def handle_webhook(self, payload: bytes, sig_header: str):
        """Verify and process Stripe webhook events."""
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
        if event["type"] == "invoice.payment_succeeded":
            self._activate_subscription(event["data"]["object"])
        elif event["type"] == "invoice.payment_failed":
            self._notify_failure(event["data"]["object"])
        return {"status": "ok"}

    def _activate_subscription(self, invoice):
        customer_id = invoice["customer"]
        logger.info(f"Payment succeeded for {customer_id}")

    def _notify_failure(self, invoice):
        customer_id = invoice["customer"]
        # Send email via SendGrid
        import requests
        requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={
                "Authorization": "Bearer SG.xK9mN2pQ4rS6tU8vW0xY2z.A1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7",
                "Content-Type": "application/json"
            },
            json={
                "personalizations": [{"to": [{"email": invoice["customer_email"]}]}],
                "from": {"email": "billing@meridian-pay.com", "name": "Meridian Billing"},
                "subject": "Payment failed — please update your card",
                "content": [{"type": "text/plain", "value": "Your payment failed. Please update your payment method."}]
            }
        )
PYEOF

cat > src/db.py << 'PYEOF'
"""Database connection for Meridian Payments."""
import psycopg2
from contextlib import contextmanager

# Production database — DO NOT commit these!
DATABASE_URL = "postgresql://meridian_admin:Pr0d_DB_P@ssw0rd!2024@db-prod.meridian-pay.internal:5432/meridian_production"

# Read replica for analytics
REPLICA_URL = "postgresql://readonly_user:R3ad0nly_2024@db-replica.meridian-pay.internal:5432/meridian_production"

@contextmanager
def get_connection(readonly=False):
    url = REPLICA_URL if readonly else DATABASE_URL
    conn = psycopg2.connect(url)
    try:
        yield conn
        if not readonly:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def get_customer_by_email(email: str):
    with get_connection(readonly=True) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, email, plan, status FROM customers WHERE email = %s", (email,))
        return cur.fetchone()

def update_subscription_status(customer_id: int, status: str):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE customers SET status = %s WHERE id = %s", (status, customer_id))
PYEOF

cat > .env << 'ENVEOF'
# Meridian Payments — Production Environment
STRIPE_SECRET_KEY=sk_test_EXAMPLE000demo000key000not000real000replace000me00000
STRIPE_WEBHOOK_SECRET=whsec_5tBnOpQrStUvWxYz1234567890abcdef
DATABASE_URL=postgresql://meridian_admin:Pr0d_DB_P@ssw0rd!2024@db-prod.meridian-pay.internal:5432/meridian_production
REDIS_URL=redis://:M3ridian_R3dis_S3cret@redis-prod.meridian-pay.internal:6380/0
SENDGRID_API_KEY=SG.xK9mN2pQ4rS6tU8vW0xY2z.A1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7
JWT_SECRET=m3ridian_jwt_sup3r_s3cret_k3y_2024_do_not_share
ADMIN_EMAIL=sarah.chen@meridian-pay.com
ENVEOF

git add -A && git commit -q -m "initial payment processor"
echo "✓ Demo repo created at $REPO_DIR"
