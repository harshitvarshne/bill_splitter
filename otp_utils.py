import smtplib
from email.message import EmailMessage
import random

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(to_email, otp):
    EMAIL = "harshitwebotpforlogin@gmail.com"
    PASSWORD = "efrrovswcvftpalw"

    msg = EmailMessage()
    msg['Subject'] = "Your OTP Verification Code"
    msg['From'] = EMAIL
    msg['To'] = to_email
    msg.set_content(f"Your OTP is: {otp}")

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL, PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print("Email error:", e)
        return False
