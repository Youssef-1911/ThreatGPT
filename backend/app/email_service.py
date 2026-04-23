from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from typing import Any


class EmailService:
    def __init__(self) -> None:
        self.enabled = os.getenv("EMAIL_NOTIFICATIONS_ENABLED", "false").strip().lower() in {"1", "true", "yes"}
        self.smtp_host = os.getenv("SMTP_HOST", "").strip()
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = os.getenv("SMTP_USERNAME", "").strip()
        self.smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
        self.smtp_from = os.getenv("SMTP_FROM", "").strip()
        self.use_tls = os.getenv("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes"}

    def send_notification(self, *, to_email: str, subject: str, body: str) -> dict[str, Any]:
        if not self.enabled:
            return {"status": "disabled", "message": "Email notifications are disabled"}
        if not self.smtp_host or not self.smtp_from:
            return {"status": "disabled", "message": "SMTP settings are not fully configured"}
        if not to_email:
            return {"status": "disabled", "message": "Recipient email is missing"}

        message = EmailMessage()
        message["From"] = self.smtp_from
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content(body)

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as smtp:
                if self.use_tls:
                    smtp.starttls()
                if self.smtp_username:
                    smtp.login(self.smtp_username, self.smtp_password)
                smtp.send_message(message)
        except Exception as exc:
            return {"status": "failed", "message": str(exc)}

        return {"status": "sent", "message": "Email notification sent"}

