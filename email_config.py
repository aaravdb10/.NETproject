import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def _env(name: str, default: str = '') -> str:
    """Read and normalize environment variable values."""
    return (os.getenv(name, default) or '').strip()


# Email configuration — set values in .env (never hardcode credentials)
SMTP_SERVER = _env('SMTP_SERVER', 'smtp.gmail.com')
try:
    SMTP_PORT = int(_env('SMTP_PORT', '587'))
except ValueError:
    SMTP_PORT = 587
SMTP_USER = _env('SMTP_USER', '')
SMTP_PASSWORD = _env('SMTP_PASSWORD', '').replace(' ', '')

# Function to send OTP email
def send_otp_email(recipient_email: str, code: str) -> None:
    """
    Send an OTP code to the specified email address.
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        raise RuntimeError('SMTP credentials are not configured. Set SMTP_USER and SMTP_PASSWORD in .env')

    try:
        subject = "Your Verification Code - AccessRakshak"
        body = f"""
Hello,

Your verification code for AccessRakshak registration is: {code}

This code will expire in 5 minutes.

If you did not request this code, please ignore this email.

Best regards,
AccessRakshak Team
"""
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SMTP_USER
        msg['To'] = recipient_email

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"OTP email sent successfully to {recipient_email}")
    except Exception as e:
        raise RuntimeError(f'Failed to send OTP email: {e}') from e
