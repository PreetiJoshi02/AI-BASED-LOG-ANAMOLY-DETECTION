import os
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import config

# Global subscriber registry (persisted in RAM and MongoDB if available)
_subscribers = {
    "email": "",
    "sender_email": "",
    "sender_password": "",
    "smtp_server": config.DEFAULT_SMTP_SERVER,
    "smtp_port": config.DEFAULT_SMTP_PORT,
    "desktop_enabled": True
}


def update_alert_config(email="", sender_email="", sender_password="", desktop_enabled=True):
    """Updates global notification subscriber settings."""
    global _subscribers
    if email:
        _subscribers["email"] = email.strip()
    if sender_email:
        _subscribers["sender_email"] = sender_email.strip()
    if sender_password:
        _subscribers["sender_password"] = sender_password.strip()
    _subscribers["desktop_enabled"] = bool(desktop_enabled)
    print(f"🔔 Alert configuration updated: Email='{_subscribers['email']}', Desktop={_subscribers['desktop_enabled']}")
    return _subscribers


def get_alert_config():
    """Returns current alert configuration."""
    return _subscribers


def send_desktop_notification(title, message):
    """
    Triggers native Windows Desktop Notification using Plyer or PowerShell fallback.
    """
    if not _subscribers.get("desktop_enabled", True):
        return False

    # Attempt 1: Try plyer library
    try:
        from plyer import notification
        notification.notify(
            title=title,
            message=message,
            app_name="AI Log Anomaly System",
            timeout=5
        )
        print(f"🖥️ Desktop notification sent via Plyer: {title}")
        return True
    except Exception as e:
        print(f"ℹ️ Plyer notification fallback to PowerShell: {e}")

    # Attempt 2: Native PowerShell NotifyIcon Toast Fallback
    try:
        ps_script = f"""
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        $objNotifyIcon = New-Object System.Windows.Forms.NotifyIcon
        $objNotifyIcon.Icon = [System.Drawing.SystemIcons]::Warning
        $objNotifyIcon.BalloonTipIcon = "Warning"
        $objNotifyIcon.BalloonTipText = "{message.replace('"', "'")}"
        $objNotifyIcon.BalloonTipTitle = "{title.replace('"', "'")}"
        $objNotifyIcon.Visible = $True
        $objNotifyIcon.ShowBalloonTip(5000)
        Start-Sleep -Seconds 2
        $objNotifyIcon.Dispose()
        """
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script]
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"🖥️ Desktop notification sent via PowerShell: {title}")
        return True
    except Exception as ex:
        print(f"❌ Failed to trigger desktop notification: {ex}")
        return False


def send_email_alert(subject, body_html, recipient=None):
    """
    Dispatches HTML security alert email via SMTP if credentials are supplied.
    """
    target_email = recipient or _subscribers.get("email")
    if not target_email:
        print("⚠️ Skipping email alert: No recipient email subscribed.")
        return False, "No recipient email subscribed."

    sender = _subscribers.get("sender_email") or target_email
    password = _subscribers.get("sender_password")
    smtp_server = _subscribers.get("smtp_server", config.DEFAULT_SMTP_SERVER)
    smtp_port = int(_subscribers.get("smtp_port", config.DEFAULT_SMTP_PORT))

    if not password:
        msg = "Email address registered, but SMTP Sender App Password is missing in Alert Settings."
        print(f"ℹ️ {msg}")
        return False, msg

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"AI Log Anomaly System <{sender}>"
        msg["To"] = target_email

        html_part = MIMEText(body_html, "html")
        msg.attach(html_part)

        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, target_email, msg.as_string())
        server.quit()

        print(f"📧 Security Email Alert successfully sent to {target_email}")
        return True, f"Email alert sent successfully to {target_email}!"
    except Exception as e:
        error_msg = str(e)
        print(f"❌ SMTP Email Sending Failed: {error_msg}")
        return False, f"SMTP Error: {error_msg}"


def dispatch_anomaly_alert(log_doc):
    """
    Dispatches simultaneous Desktop Toast and Email Alert when an anomaly is detected.
    """
    event_id = log_doc.get("event_id", "Unknown")
    source = log_doc.get("source", "Unknown")
    channel = log_doc.get("log_type", "System")
    score = log_doc.get("anomaly_score", 0.0)
    timestamp = str(log_doc.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    title = f"🚨 ANOMALY DETECTED: Event ID {event_id}"
    message = f"Channel: {channel} | Source: {source} | Score: {score}"

    # 1. Desktop Notification
    desktop_ok = send_desktop_notification(title, message)

    # 2. Email Alert
    email_html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; background-color: #0b0f19; color: #f3f4f6; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #111827; border: 1px solid #f43f5e; border-radius: 12px; padding: 24px;">
          <h2 style="color: #f43f5e; margin-top: 0;">🚨 AI Security Anomaly Alert</h2>
          <p style="color: #9ca3af;">The Isolation Forest ML engine flagged an outlier in your Windows Event Logs.</p>
          <table style="width: 100%; text-align: left; border-collapse: collapse; margin-top: 15px;">
            <tr style="border-bottom: 1px solid #1f2937;"><th style="padding: 8px; color: #9ca3af;">Timestamp</th><td style="padding: 8px; color: #ffffff;">{timestamp}</td></tr>
            <tr style="border-bottom: 1px solid #1f2937;"><th style="padding: 8px; color: #9ca3af;">Event ID</th><td style="padding: 8px; color: #6366f1; font-weight: bold;">{event_id}</td></tr>
            <tr style="border-bottom: 1px solid #1f2937;"><th style="padding: 8px; color: #9ca3af;">Channel</th><td style="padding: 8px; color: #ffffff;">{channel}</td></tr>
            <tr style="border-bottom: 1px solid #1f2937;"><th style="padding: 8px; color: #9ca3af;">Source</th><td style="padding: 8px; color: #ffffff;">{source}</td></tr>
            <tr><th style="padding: 8px; color: #9ca3af;">Anomaly Score</th><td style="padding: 8px; color: #f43f5e; font-weight: bold;">{score}</td></tr>
          </table>
          <p style="margin-top: 20px; font-size: 12px; color: #6b7280;">Log Anomaly Detection System • Powered by Isolation Forest ML Pipeline</p>
        </div>
      </body>
    </html>
    """
    email_ok, email_msg = send_email_alert(f"[ALERT] Windows Log Anomaly - Event ID {event_id}", email_html)

    return {
        "desktop_sent": desktop_ok,
        "email_sent": email_ok,
        "email_status": email_msg
    }
