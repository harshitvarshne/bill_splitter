import sys
print("🔍 Using Python:", sys.executable)

from fastapi import FastAPI, Form, Request, UploadFile, File, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from database import Base, engine, SessionLocal
from otp_utils import send_otp_email, generate_otp
from passlib.hash import bcrypt
import re
from typing import Optional, Union
from starlette.middleware.sessions import SessionMiddleware
from fastapi.exceptions import HTTPException as FastAPIHTTPException
from fastapi.exception_handlers import http_exception_handler
from models import User, Group, GroupMember, PaymentSettlement, Trip, TripExpense, TripExpenseShare, Expense
import os, shutil, uuid, subprocess
from PIL import Image
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
from datetime import date
from fastapi.responses import StreamingResponse
import pandas as pd
from io import BytesIO
from typing import List
import io
import httpx
from fastapi import UploadFile, File, Depends, HTTPException
# Base.metadata.drop_all(bind=engine)
# Base.metadata.create_all(bind=engine)

app = FastAPI()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
Base.metadata.create_all(bind=engine)
app.add_middleware(SessionMiddleware, secret_key="1234")
otp_store = {}
user_temp_data = {}
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

def require_login(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not logged in")
    return user_id

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
def get_current_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        # Force redirect to login page if user not logged in
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user_id
def render_error_message(request: Request, message: str):
    return templates.TemplateResponse("error_message.html", {
        "request": request,
        "message": message
    })
def calculate_settlements_for_all_expenses(expenses, members):
    from collections import defaultdict

    net_balance = defaultdict(float)

    for expense in expenses:
        total_amount = expense.total_amount
        paid_by = expense.paid_by  # {user_id: amount}
        split_type = expense.split_type
        split_detail = expense.split_detail  # {user_id: share/percent/amount}

        # 1. Track payments
        for uid, amt in paid_by.items():
            net_balance[uid] += amt

        # 2. Track shares owed
        if split_type == "equal":
            per_head = total_amount / len(members)
            for uid in members:
                net_balance[uid] -= per_head

        elif split_type == "percentage":
            for uid, pct in split_detail.items():
                net_balance[uid] -= (pct / 100) * total_amount

        elif split_type == "share":
            total_shares = sum(split_detail.values())
            for uid, share in split_detail.items():
                net_balance[uid] -= (share / total_shares) * total_amount

        elif split_type == "custom":
            for uid, amt in split_detail.items():
                net_balance[uid] -= amt

    # Calculate who owes whom using greedy method
    owes = []
    creditors = sorted([(uid, amt) for uid, amt in net_balance.items() if amt > 0], key=lambda x: -x[1])
    debtors = sorted([(uid, -amt) for uid, amt in net_balance.items() if amt < 0], key=lambda x: -x[1])

    i = j = 0
    while i < len(debtors) and j < len(creditors):
        d_uid, d_amt = debtors[i]
        c_uid, c_amt = creditors[j]
        paid = min(d_amt, c_amt)

        owes.append({
            "from": d_uid,
            "to": c_uid,
            "amount": round(paid, 2)
        })

        debtors[i] = (d_uid, d_amt - paid)
        creditors[j] = (c_uid, c_amt - paid)

        if debtors[i][1] == 0:
            i += 1
        if creditors[j][1] == 0:
            j += 1

    return owes

@app.exception_handler(FastAPIHTTPException)
async def custom_http_exception_handler(request: Request, exc: FastAPIHTTPException):
    if exc.status_code == 303 and exc.headers.get("Location") == "/login":
        return RedirectResponse("/login", status_code=303)
    return await http_exception_handler(request, exc)

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})
@app.get("/signup", response_class=HTMLResponse)
def show_signup(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.post("/send-otp")
def send_otp(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)  # Required to query existing users
):
    if password != confirm_password:
        return HTMLResponse("<script>alert('❌ Passwords do not match'); window.history.back();</script>", status_code=400)

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return HTMLResponse("<script>alert('❌ Invalid email format'); window.history.back();</script>", status_code=400)

    # Check if user already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        # Redirect to login page with alert
        return HTMLResponse("""
            <script>
                alert("User already exists! Please login.");
                window.location.href = "/login";
            </script>
        """, status_code=303)

    # Continue normal OTP flow
    otp = generate_otp()
    if send_otp_email(email, otp):
        otp_store[email] = otp
        user_temp_data[email] = {
            "name": name,
            "password": bcrypt.hash(password)
        }
        return RedirectResponse(f"/verify?email={email}", status_code=303)
    else:
        return HTMLResponse("<script>alert('❌ Failed to send OTP'); window.history.back();</script>", status_code=500)

@app.get("/verify", response_class=HTMLResponse)
def verify_form(request: Request, email: str, error: int = 0):
    return templates.TemplateResponse("verify.html", {
        "request": request,
        "email": email,
        "error": error
    })
@app.post("/verify-otp")
def verify_otp(
    request: Request,
    email: str = Form(...),
    otp: str = Form(...),
    db: Session = Depends(get_db)
):
    if otp_store.get(email) == otp:
        data = user_temp_data.get(email)
        if data:
            user = User(name=data["name"], email=email, hashed_password=data["password"])
            db.add(user)
            db.commit()
            del otp_store[email]
            del user_temp_data[email]
            return templates.TemplateResponse("signup_success.html", {"request": request})
    return RedirectResponse(f"/verify?email={email}&error=1", status_code=303)
@app.get("/login", response_class=HTMLResponse)
def show_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})
@app.post("/login")
def login(request: Request, email: str = Form(...), method: str = Form(...), password: str = Form(None),
          db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return HTMLResponse("❌ User not found", status_code=404)
    if method == "password":
        if not password or not bcrypt.verify(password, user.hashed_password):
            return HTMLResponse("❌ Invalid credentials", status_code=401)
        request.session["email"] = user.email
        request.session["name"] = user.name
        request.session["user_id"] = user.id
        return RedirectResponse("/dashboard", status_code=303)
    elif method == "otp":
        otp = generate_otp()
        if send_otp_email(email, otp):
            otp_store[email] = otp
            return RedirectResponse(f"/verify-login-otp?email={email}", status_code=303)
        else:
            return HTMLResponse("❌ Failed to send OTP", status_code=500)

    return HTMLResponse("❌ Invalid method", status_code=400)
@app.get("/verify-login-otp", response_class=HTMLResponse)
def show_otp_login(request: Request, email: str, error: int = 0):
    return templates.TemplateResponse("verify_login_otp.html", {
        "request": request,
        "email": email,
        "error": error
    })
@app.post("/verify-login-otp")
def verify_login_otp(
    request: Request,
    email: str = Form(...),
    otp: str = Form(...),
    db: Session = Depends(get_db)
):
    if otp_store.get(email) == otp:
        user = db.query(User).filter(User.email == email).first()
        if user:
            request.session["email"] = user.email
            request.session["name"] = user.name
            request.session["user_id"] = user.id
            del otp_store[email]
            return RedirectResponse("/dashboard", status_code=303)
    return RedirectResponse(f"/verify-login-otp?email={email}&error=1", status_code=303)
@app.get("/post-login", response_class=HTMLResponse)
def post_login(request: Request):
    return templates.TemplateResponse("post_login.html", {"request": request})

@app.get("/create-group", response_class=HTMLResponse)
def create_group_page(request: Request):
    return templates.TemplateResponse("create_group.html", {"request": request})
@app.post("/create-group")
def create_group(
    request: Request,
    group_name: str = Form(...),
    user_id: int = Form(...),
    db: Session = Depends(get_db),
):
    group = Group(name=group_name, creator_id=user_id)
    db.add(group)
    db.commit()

    html_content = """
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="3;url=/dashboard" />
    <title>Group Created</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(to right, #141e30, #243b55);
            color: #f0f0f0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }

        .message-box {
            text-align: center;
            background-color: #2d2b42;
            padding: 2rem 3rem;
            border-radius: 12px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        h2 {
            font-size: 1.8rem;
            margin-bottom: 1rem;
        }

        p {
            font-size: 1rem;
            color: #cbd5e1;
        }
    </style>
</head>
<body>
    <div class="message-box">
        <h2>✅ Group Created Successfully!</h2>
        <p>You will be redirected to your dashboard in 3 seconds...</p>
    </div>
</body>
</html>
    """
    return HTMLResponse(content=html_content, status_code=200)
@app.get("/my-groups", response_class=HTMLResponse)
def my_groups(request: Request, user_id: int = Depends(require_login), db: Session = Depends(get_db)):
    groups = db.query(Group).filter(Group.creator_id == user_id).all()
    return templates.TemplateResponse("my_groups.html", {"request": request, "groups": groups})


@app.get("/group-details", response_class=HTMLResponse)
def view_group_details(request: Request, group_id: Optional[int], user_id: int = Depends(require_login),
                       db: Session = Depends(get_db)):
    group = db.query(Group).filter_by(g_id=group_id, creator_id=user_id).first()
    if not group:
        return RedirectResponse("/dashboard", status_code=302)

    members = db.query(GroupMember).filter_by(group_id=group_id).all()
    return templates.TemplateResponse("group_members.html", {
        "request": request,
        "group": group,
        "members": members
    })

@app.get("/request-delete-otp")
def request_delete_otp(request: Request, email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return HTMLResponse("<script>alert('❌ User not found'); window.location.href='/';</script>")
    otp = generate_otp()
    otp_store[email] = otp
    if send_otp_email(email, otp):
        return RedirectResponse(f"/confirm-delete?email={email}", status_code=303)
    else:
        return HTMLResponse("<script>alert('❌ Failed to send OTP'); window.location.href='/';</script>")
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user_id: int = Depends(require_login), db: Session = Depends(get_db)):
    groups = db.query(Group).filter(Group.creator_id == user_id).all()
    return templates.TemplateResponse("dashboard_main.html", {
        "request": request,
        "groups": groups
    })
@app.get("/delete-account", response_class=HTMLResponse)
def show_delete_account_page(request: Request):
    if "email" not in request.session:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("delete_account.html", {"request": request})
@app.post("/send-delete-otp")
def send_delete_otp(request: Request):
    email = request.session.get("email")
    if not email:
        return RedirectResponse("/login", status_code=303)
    otp = generate_otp()
    if send_otp_email(email, otp):
        otp_store[email] = otp
        return RedirectResponse("/confirm-delete", status_code=303)
    else:
        return HTMLResponse("❌ Failed to send OTP", status_code=500)
@app.get("/confirm-delete", response_class=HTMLResponse)
def confirm_delete_page(request: Request):
    if "email" not in request.session:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("confirm_delete.html", {"request": request})
@app.post("/confirm-delete")
def confirm_delete_account(request: Request, otp: str = Form(...), db: Session = Depends(get_db)):
    email = request.session.get("email")
    if not email:
        return RedirectResponse("/login", status_code=303)
    if otp_store.get(email) == otp:
        user = db.query(User).filter(User.email == email).first()
        if user:
            db.delete(user)
            db.commit()
            del otp_store[email]
            request.session.clear()
            return HTMLResponse("✅ Your account has been deleted.", status_code=200)
        return HTMLResponse("❌ User not found", status_code=404)
    return HTMLResponse("❌ Invalid OTP", status_code=400)
@app.get("/settings", response_class=HTMLResponse)
def user_settings(request: Request,  user_id: int = Depends(require_login)):
    return templates.TemplateResponse("user_settings.html", {"request": request})
@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)
@app.get("/delete-user")
def delete_user(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if user:
        db.delete(user)
        db.commit()
        html_content = """
        <html>
            <head>
                <meta http-equiv="refresh" content="3;url=/" />
            </head>
            <body>
                <h2>✅ Account deleted successfully.</h2>
                <p>Redirecting to Home Page in 3 seconds...</p>
            </body>
        </html>
        """
        return HTMLResponse(content=html_content, status_code=200)
    return HTMLResponse("❌ User not found", status_code=404)
@app.get("/group/{group_id}", response_class=HTMLResponse)
def view_group(request: Request, group_id: int, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    group = db.query(Group).filter(Group.g_id == group_id).first()

    if not group or group.creator_id != user_id:
        return RedirectResponse("/dashboard", status_code=303)

    members = db.query(GroupMember).filter(GroupMember.group_id == group_id).all()
    return templates.TemplateResponse("group_members.html", {
        "request": request,
        "group": group,
        "members": members
    })
@app.get("/group/{group_id}/add-member", response_class=HTMLResponse)
def add_member_form(request: Request, group_id: int, user_id: int = Depends(require_login), db: Session = Depends(get_db)):
    group = db.query(Group).filter_by(g_id=group_id, creator_id=user_id).first()
    if not group:
        return RedirectResponse("/dashboard", status_code=302)

    return templates.TemplateResponse("add_member.html", {
        "request": request,
        "group": group
    })
@app.post("/group/{group_id}/add-member")
def add_member_to_group(
    request: Request,
    group_id: int,
    member_name: str = Form(...),  # 👈 this matches the HTML input name
    user_id: int = Depends(require_login),
    db: Session = Depends(get_db)
):
    new_user = User(name=member_name)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    new_member = GroupMember(
        group_id=group_id,
        user_id=new_user.id,
        name=member_name
    )
    db.add(new_member)
    db.commit()

    return RedirectResponse(f"/group/{group_id}/add-member", status_code=303)
@app.post("/group/{group_id}/delete")
def delete_group(request: Request, group_id: int, user_id: int = Depends(require_login), db: Session = Depends(get_db)):
    group = db.query(Group).filter_by(g_id=group_id, creator_id=user_id).first()
    if not group:
        return RedirectResponse("/dashboard", status_code=302)

    db.delete(group)
    db.commit()
    return RedirectResponse("/my-groups", status_code=302)
@app.get("/group/{group_id}/members", response_class=HTMLResponse)
def view_group_members(
    request: Request,
    group_id: int,
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group = db.query(Group).filter(Group.g_id == group_id).first()
    if not group or group.creator_id != user_id:
        return HTMLResponse("Unauthorized access", status_code=403)
    members = db.query(User).join(GroupMember).filter(GroupMember.group_id == group_id).all()
    return templates.TemplateResponse("group_members.html", {
        "request": request,
        "group": group,
        "members": members
    })
@app.get("/group/{group_id}/split", response_class=HTMLResponse)
def show_split_form(
    request: Request,
    group_id: int,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user)
):
    group = db.query(Group).filter(Group.g_id == group_id).first()
    if not group or group.creator_id != user_id:
        return HTMLResponse("Unauthorized", status_code=403)
    return templates.TemplateResponse("split_form.html", {"request": request, "group": group})
@app.post("/group/{group_id}/split", response_class=HTMLResponse)
def perform_split(request: Request, group_id: int, amount: float = Form(...), db: Session = Depends(get_db), user_id: int = Depends(get_current_user)):
    group = db.query(Group).filter(Group.g_id == group_id).first()
    if not group or group.creator_id != user_id:
        return HTMLResponse("Unauthorized", status_code=403)

    members = db.query(GroupMember).filter(GroupMember.group_id == group_id).all()
    if not members:
        return HTMLResponse("No members to split with.", status_code=400)

    per_person = round(amount / len(members), 2)
    result = {m.name: per_person for m in members}
    return templates.TemplateResponse("split_result.html", {"request": request, "group": group, "result": result})
@app.get("/group-split")
def redirect_to_split(request: Request, group_id: int):
    return RedirectResponse(f"/group/{group_id}/split", status_code=303)
@app.get("/split", response_class=HTMLResponse)
def split_select(request: Request, group_id: int = None, db: Session = Depends(get_db), user_id: int = Depends(require_login)):
    groups = db.query(Group).filter_by(creator_id=user_id).all()
    selected_group = None
    members = []

    if group_id:
        selected_group = db.query(Group).filter_by(g_id=group_id, creator_id=user_id).first()
        if selected_group:
            members = db.query(GroupMember).filter_by(group_id=group_id).all()

    return templates.TemplateResponse("split_select.html", {
        "request": request,
        "groups": groups,
        "selected_group": selected_group,
        "members": members
    })
@app.post("/split", response_class=HTMLResponse)
def perform_split(
    request: Request,
    group_id: Optional[int] = Form(None),
    amount: Optional[float] = Form(None),
    db: Session = Depends(get_db),
    user_id: int = Depends(require_login)
):
    group = db.query(Group).filter_by(g_id=group_id, creator_id=user_id).first()
    if not group:
        return RedirectResponse("/dashboard", status_code=302)

    members = db.query(GroupMember).filter_by(group_id=group_id).all()
    if not members:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "message": "No members found to split the bill."
        })

    per_person = round(amount / len(members), 2)
    result = {member.name: per_person for member in members}

    return templates.TemplateResponse("split_result.html", {
        "request": request,
        "group": group,
        "result": result
    })
@app.get("/manual-split", response_class=HTMLResponse)
def show_manual_split_form(
    request: Request,
    group_id: Optional[int] = None,
    db: Session = Depends(get_db),
    user_id: int = Depends(require_login)
):
    groups = db.query(Group).filter_by(creator_id=user_id).all()
    selected_group = None
    members = []

    if group_id:
        selected_group = db.query(Group).filter_by(g_id=group_id, creator_id=user_id).first()
        if selected_group:
            members = db.query(GroupMember).filter_by(group_id=group_id).all()

    return templates.TemplateResponse("manual_split_form.html", {
        "request": request,
        "groups": groups,
        "selected_group": selected_group,
        "members": members
    })
from fastapi import Form

@app.post("/manual-split", response_class=HTMLResponse)
async def calculate_manual_split(
    request: Request,
    group_id: int = Form(...),
    db: Session = Depends(get_db),
    user_id: int = Depends(require_login)
):
    form_data = await request.form()
    paid_amounts = {}
    for key, value in form_data.items():
        if key.startswith("paid_"):
            name = key.replace("paid_", "")
            paid_amounts[name] = float(value)

    total_amount = sum(paid_amounts.values())
    fair_share = round(total_amount / len(paid_amounts), 0)

    balances = {person: paid - fair_share for person, paid in paid_amounts.items()}
    creditors = {p: amt for p, amt in balances.items() if amt > 0}
    debtors = {p: -amt for p, amt in balances.items() if amt < 0}
    settlements = []

    for debtor, debt_amt in debtors.items():
        for creditor in list(creditors.keys()):
            credit_amt = creditors.get(creditor, 0)
            if debt_amt <= 0 or credit_amt <= 0:
                continue

            pay_amt = min(debt_amt, credit_amt)
            settlements.append(f"{debtor} pays ₹{pay_amt:.2f} to {creditor}")

            # ✅ Save to DB
            db.add(PaymentSettlement(
                group_id=group_id,
                payer_name=debtor,
                receiver_name=creditor,
                amount=pay_amt,
                is_settled=False
            ))

            debt_amt -= pay_amt
            creditors[creditor] = credit_amt - pay_amt

            if creditors[creditor] <= 0:
                creditors.pop(creditor)

    db.commit()

    group = db.query(Group).filter_by(g_id=group_id).first()

    return templates.TemplateResponse("manual_split_result.html", {
        "request": request,
        "paid_amounts": paid_amounts,
        "total_amount": total_amount,
        "fair_share": fair_share,
        "settlements": settlements,
        "selected_group": group,
        "group": group
    })
from sqlalchemy import and_

@app.post("/settle-payment")
def settle_payment(
    group_id: int = Form(...),
    payer: str = Form(...),
    receiver: str = Form(...),
    amount: float = Form(...),
    db: Session = Depends(get_db),
    user_id: int = Depends(require_login)
):
    # Find possible matches by group, payer, receiver, unsettled
    settlements = db.query(PaymentSettlement).filter(
        and_(
            PaymentSettlement.group_id == group_id,
            PaymentSettlement.payer_name == payer,
            PaymentSettlement.receiver_name == receiver,
            PaymentSettlement.is_settled == False
        )
    ).all()

    # Match approximate amount (float-safe)
    settlement = next((s for s in settlements if abs(s.amount - amount) < 0.01), None)

    if settlement:
        settlement.is_settled = True
        db.commit()

    return RedirectResponse(f"/my-settlements?", status_code=303)
@app.get("/manual-split-result", response_class=HTMLResponse)
def show_manual_split_result(
    request: Request,
    group_id: int,
    db: Session = Depends(get_db),
    user_id: int = Depends(require_login)
):
    group = db.query(Group).filter_by(g_id=group_id, creator_id=user_id).first()
    if not group:
        return RedirectResponse("/dashboard", status_code=302)

    # Fetch settlements for this group
    # settlements = db.query(PaymentSettlement).filter_by(group_id=group_id).all()
    settlements = db.query(PaymentSettlement).filter_by(group_id=group_id, is_settled=False).all()

    return templates.TemplateResponse("manual_split_result.html", {
        "request": request,
        "group": group,
        "settlements": settlements
    })
@app.get("/create-trip", response_class=HTMLResponse)
def show_create_trip_form(request: Request, user_id: int = Depends(require_login), db: Session = Depends(get_db)):
    groups = db.query(Group).filter_by(creator_id=user_id).all()
    return templates.TemplateResponse("create_trip.html", {"request": request, "groups": groups})


@app.post("/create-trip")
def create_trip(
    request: Request,
    trip_name: str = Form(...),
    group_id: int = Form(...),
    user_id: int = Depends(require_login),
    db: Session = Depends(get_db)
):
    trip = Trip(name=trip_name, group_id=group_id, created_by=user_id)
    db.add(trip)
    db.commit()
    return RedirectResponse(f"/trip/{trip.id}/add-expense", status_code=303)
@app.get("/trip/{trip_id}/add-expense", response_class=HTMLResponse)
def add_expense_form(request: Request, trip_id: int, user_id: int = Depends(require_login), db: Session = Depends(get_db)):
    trip = db.query(Trip).filter_by(id=trip_id, created_by=user_id).first()
    members = db.query(GroupMember).filter_by(group_id=trip.group_id).all()
    trip = db.query(Trip).filter_by(id=trip_id).first()
    if trip.is_closed:
        return render_error_message(request, "Trip is closed. Changes are not allowed.")
    return templates.TemplateResponse("trip_expense_form.html", {"request": request, "trip": trip, "members": members})


# @app.post("/trip/{trip_id}/add-expense")
# def add_expense(
#     request: Request,
#     trip_id: int,
#     category: str = Form(...),
#     description: str = Form(...),
#     total_amount: float = Form(...),
#     paid_by: str = Form(...),
#     user_id: int = Depends(require_login),
#     db: Session = Depends(get_db)
# ):
#     expense = TripExpense(
#         trip_id=trip_id,
#         category=category,
#         description=description,
#         total_amount=total_amount,
#         paid_by=paid_by
#     )
#     db.add(expense)
#     db.commit()
#     trip = db.query(Trip).filter_by(id=trip_id).first()
#     if trip.is_closed:
#         return render_error_message(request, "Trip is closed. Changes are not allowed.")
#     return RedirectResponse(f"/trip/{trip_id}/add-expense", status_code=303)
@app.post("/trip/{trip_id}/add-expense")
async def add_expense(
    request: Request,
    trip_id: int,
    category: str = Form(...),
    description: str = Form(...),
    total_amount: float = Form(...),
    paid_by: str = Form(...),
    split_method: str = Form(...),
    member_names: List[str] = Form(...),
    percentages: Optional[List[float]] = Form(None),
    shares: Optional[List[int]] = Form(None),
    amounts: Optional[List[float]] = Form(None),
    db: Session = Depends(get_db),
):
    trip = db.query(Trip).filter(Trip.id == trip_id).first()
    if not trip:
        raise HTTPException(status_code=404, detail="Trip not found.")
    if trip.is_closed:
        return templates.TemplateResponse("error_trip_closed.html", {
            "request": request,
            "message": "Trip is closed. Changes are not allowed.",
            "redirect_url": "/dashboard"
        })

    # Backend validation
    if split_method == "percentages":
        if not percentages or len(percentages) != len(member_names):
            raise HTTPException(status_code=400, detail="Invalid percentages input.")
        total_percent = round(sum(percentages), 2)
        if total_percent != 100.0:
            raise HTTPException(
                status_code=400,
                detail=f"Percentage must sum to 100. Got {total_percent}%"
            )

    elif split_method == "amounts":
        if not amounts or len(amounts) != len(member_names):
            raise HTTPException(status_code=400, detail="Invalid amounts input.")
        total_entered = round(sum(amounts), 2)
        expected = round(total_amount, 2)
        if total_entered != expected:
            raise HTTPException(
                status_code=400,
                detail=f"Amounts must sum to {expected}. Got {total_entered}"
            )
    elif split_method == "shares":
        if not shares or len(shares) != len(member_names):
            raise HTTPException(status_code=400, detail="Invalid shares input.")
        total_shares = sum(shares)
        if total_shares <= 0:
            raise HTTPException(status_code=400, detail="Total shares must be greater than zero.")

    # Save the TripExpense
    expense = TripExpense(
        trip_id=trip_id,
        category=category,
        description=description,
        total_amount=total_amount,
        paid_by=paid_by,
        split_type=split_method
    )
    db.add(expense)
    db.commit()
    db.refresh(expense)

    # Save the shares
    if split_method == "equally":
        per_person = round(total_amount / len(member_names), 2)
        for member in member_names:
            db.add(TripExpenseShare(
                expense_id=expense.id,
                member_name=member,
                amount=per_person
            ))

    elif split_method == "percentages":
        for member, percent in zip(member_names, percentages):
            amount = round(total_amount * (percent / 100), 2)
            db.add(TripExpenseShare(
                expense_id=expense.id,
                member_name=member,
                amount=amount
            ))

    elif split_method == "shares":
        for member, share_count in zip(member_names, shares):
            share_amount = round((share_count / total_shares) * total_amount, 2)
            db.add(TripExpenseShare(
                expense_id=expense.id,
                member_name=member,
                amount=share_amount
            ))

    elif split_method == "amounts":
        for member, amt in zip(member_names, amounts):
            db.add(TripExpenseShare(
                expense_id=expense.id,
                member_name=member,
                amount=amt
            ))

    db.commit()
    return RedirectResponse(url=f"/trip/{trip_id}/add-expense", status_code=303)
@app.get("/trip/{trip_id}/end", response_class=HTMLResponse)
def end_trip(
    request: Request,
    trip_id: int,
    user_id: int = Depends(require_login),
    db: Session = Depends(get_db)
):
    trip = db.query(Trip).filter_by(id=trip_id, created_by=user_id).first()
    if not trip:
        return RedirectResponse("/dashboard", status_code=302)

    expenses = db.query(TripExpense).filter_by(trip_id=trip_id).all()
    members = db.query(GroupMember).filter_by(group_id=trip.group_id).all()

    paid_map = {m.name: 0.0 for m in members}
    owed_map = {m.name: 0.0 for m in members}

    # 1. Calculate paid and owed from all expenses
    for e in expenses:
        paid_map[e.paid_by] += e.total_amount
        for s in e.shares:
            owed_map[s.member_name] += s.amount

    # 2. Net balance
    balances = {name: round(paid_map[name] - owed_map[name], 2) for name in paid_map}

    # 3. Settle using greedy algorithm
    creditors = {p: amt for p, amt in balances.items() if amt > 0}
    debtors = {p: -amt for p, amt in balances.items() if amt < 0}
    settlements = []

    for debtor, owed in debtors.items():
        for creditor in list(creditors.keys()):
            credit_amt = creditors.get(creditor, 0)
            if owed <= 0 or credit_amt <= 0:
                continue

            pay_amt = min(owed, credit_amt)
            settlements.append({
                "from": debtor,
                "to": creditor,
                "amount": round(pay_amt, 2)
            })
            owed -= pay_amt
            creditors[creditor] -= pay_amt

            if creditors[creditor] <= 0:
                del creditors[creditor]

            if owed <= 0:
                break

    total = sum(e.total_amount for e in expenses)
    per_person = round(total / len(members), 2)

    # Save settlements to DB (optional step)
    for s in settlements:
        db.add(PaymentSettlement(
            group_id=trip.group_id,
            payer_name=s["from"],
            receiver_name=s["to"],
            amount=s["amount"],
            is_settled=False
        ))
    db.commit()

    return templates.TemplateResponse("trip_result.html", {
        "request": request,
        "trip": trip,
        "total": total,
        "per_person": per_person,
        "settlements": settlements,
        "expenses": expenses
    })
@app.get("/trip-closed", response_class=HTMLResponse)
def trip_closed(request: Request):
    return templates.TemplateResponse("trip_closed.html", {
        "request": request
    })
@app.get("/trip/{trip_id}/export")
def export_trip_to_excel(trip_id: int, user_id: int = Depends(require_login), db: Session = Depends(get_db)):
    trip = db.query(Trip).filter_by(id=trip_id, created_by=user_id).first()
    if not trip:
        return HTMLResponse("❌ Trip not found", status_code=404)

    expenses = db.query(TripExpense).filter_by(trip_id=trip_id).all()
    members = db.query(GroupMember).filter_by(group_id=trip.group_id).all()

    # Expense Table
    data = [{
        "Date": e.created_at.strftime("%Y-%m-%d"),
        "Category": e.category,
        "Description": e.description,
        "Amount": e.total_amount,
        "Paid By": e.paid_by
    } for e in expenses]
    df_expenses = pd.DataFrame(data)

    # Settlement Calculation
    paid_map = {m.name: 0.0 for m in members}
    total = 0.0
    for e in expenses:
        paid_map[e.paid_by] += e.total_amount
        total += e.total_amount

    per_head = round(total / len(members), 2)
    balances = {name: round(paid - per_head, 2) for name, paid in paid_map.items()}
    creditors = {p: amt for p, amt in balances.items() if amt > 0}
    debtors = {p: -amt for p, amt in balances.items() if amt < 0}
    settlements = []

    for debtor, owed in debtors.items():
        for creditor in list(creditors):
            if owed <= 0 or creditors[creditor] <= 0:
                continue
            pay = min(owed, creditors[creditor])
            settlements.append({
                "Debtor": debtor,
                "Creditor": creditor,
                "Amount": f"₹{pay:.2f}"
            })
            creditors[creditor] -= pay
            owed -= pay
            if creditors[creditor] <= 0:
                del creditors[creditor]
            if owed <= 0:
                break

    df_settlements = pd.DataFrame(settlements)

    # Write both to Excel
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df_expenses.to_excel(writer, sheet_name='Expenses', index=False)
        df_settlements.to_excel(writer, sheet_name='Settlements', index=False)
    output.seek(0)

    filename = f"{trip.name.replace(' ', '_')}_trip.xlsx"
    return StreamingResponse(output, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                             headers={"Content-Disposition": f"attachment; filename={filename}"})

@app.get("/trip-history", response_class=HTMLResponse)
def trip_history(request: Request, user_id: int = Depends(require_login), db: Session = Depends(get_db)):
    trips = db.query(Trip).filter_by(created_by=user_id).all()
    return templates.TemplateResponse("trip_history.html", {"request": request, "trips": trips})
@app.get("/trip/{trip_id}/expenses", response_class=HTMLResponse)
def view_trip_expenses(
    request: Request,
    trip_id: int,
    user_id: int = Depends(require_login),
    db: Session = Depends(get_db)
):
    trip = db.query(Trip).filter_by(id=trip_id, created_by=user_id).first()
    if not trip:
        return HTMLResponse("❌ Trip not found or unauthorized", status_code=403)
    trip = db.query(Trip).filter_by(id=trip_id).first()
    if trip.is_closed:
        return render_error_message(request, "Trip is closed. Changes are not allowed.")
    expenses = db.query(TripExpense).filter_by(trip_id=trip_id).all()
    return templates.TemplateResponse("trip_expense_list.html", {
        "request": request,
        "trip": trip,
        "expenses": expenses
    })
@app.post("/expense/{expense_id}/delete")
def delete_expense(
    expense_id: int,
    user_id: int = Depends(require_login),
    db: Session = Depends(get_db)
):
    expense = db.query(TripExpense).get(expense_id)
    trip_id = expense.trip_id
    trip = db.query(Trip).filter_by(id=trip_id).first()
    if trip.is_closed:
        return render_error_message(request,"Trip is closed. Changes are not allowed.")
    trip = db.query(Trip).filter_by(id=expense.trip_id, created_by=user_id).first()

    if not trip or not expense:
        return HTMLResponse("❌ Unauthorized or not found", status_code=403)

    db.delete(expense)
    db.commit()
    return RedirectResponse(f"/trip/{trip.id}/expenses", status_code=303)
@app.post("/trip/{trip_id}/delete")
def delete_trip(trip_id: int, db: Session = Depends(get_db)):
    trip = db.query(Trip).filter_by(id=trip_id).first()

    if not trip:
        raise HTTPException(status_code=404, detail="Trip not found")

    db.delete(trip)  # Automatically deletes related TripExpense if cascade is set
    db.commit()

    return RedirectResponse(url="/trip-history", status_code=303)
@app.post("/trip/{trip_id}/close")
def close_trip(trip_id: int, db: Session = Depends(get_db)):
    trip = db.query(Trip).filter_by(id=trip_id).first()

    if not trip:
        raise HTTPException(status_code=404, detail="Trip not found")

    trip.is_closed = True
    db.commit()
    return RedirectResponse(url="/trip-history", status_code=303)
# @app.get("/trip/{trip_id}/settlement", response_class=HTMLResponse)
# def trip_settlement(
#     request: Request,
#     trip_id: int,
#     user_id: int = Depends(require_login),
#     db: Session = Depends(get_db)
# ):
#     trip = db.query(Trip).filter_by(id=trip_id, created_by=user_id).first()
#     if not trip:
#         return RedirectResponse("/dashboard", status_code=302)
#
#     expenses = db.query(TripExpense).filter_by(trip_id=trip_id).all()
#     members = db.query(GroupMember).filter_by(group_id=trip.group_id).all()
#
#     paid_map = {m.name: 0.0 for m in members}
#     owed_map = {m.name: 0.0 for m in members}
#
#     # 1. Calculate paid and owed
#     for e in expenses:
#         paid_map[e.paid_by] += e.total_amount
#         for s in e.shares:
#             owed_map[s.member_name] += s.amount
#
#     # 2. Net balance
#     balances = {name: round(paid_map[name] - owed_map[name], 2) for name in paid_map}
#
#     # 3. Settle using greedy algo
#     creditors = {p: amt for p, amt in balances.items() if amt > 0}
#     debtors = {p: -amt for p, amt in balances.items() if amt < 0}
#     settlements = []
#
#     for debtor, owed in debtors.items():
#         for creditor in list(creditors.keys()):
#             credit_amt = creditors.get(creditor, 0)
#             if owed <= 0 or credit_amt <= 0:
#                 continue
#
#             pay_amt = min(owed, credit_amt)
#             settlements.append({
#                 "from": debtor,
#                 "to": creditor,
#                 "amount": round(pay_amt, 2)
#             })
#             owed -= pay_amt
#             creditors[creditor] -= pay_amt
#
#             if creditors[creditor] <= 0:
#                 del creditors[creditor]
#
#             if owed <= 0:
#                 break
#
#     return templates.TemplateResponse("settlement.html", {
#         "request": request,
#         "trip": trip,
#         "expenses": expenses,
#         "settlements": settlements
#     })
# @app.post("/trip/{trip_id}/upload-bill")
# async def upload_bill(
#     trip_id: int,
#     file: UploadFile = File(...),
#     db: Session = Depends(get_db),
#     user_id: int = Depends(require_login),
# ):
#     trip = db.query(Trip).filter(Trip.id == trip_id, Trip.created_by == user_id).first()
#     if not trip:
#         raise HTTPException(status_code=404, detail="Trip not found")
#
#     # Save image locally
#     ext = file.filename.split(".")[-1]
#     filename = f"{uuid.uuid4()}.{ext}"
#     file_path = f"uploads/{filename}"
#     os.makedirs("uploads", exist_ok=True)
#     with open(file_path, "wb") as f:
#         shutil.copyfileobj(file.file, f)
#
#     # OCR extraction
#     img = Image.open(file_path)
#     text = pytesseract.image_to_string(img)
#
#     prompt = f"""
# You are an AI assistant that extracts expense data from OCR receipt text.
# The receipt is below. Extract:
# - Total amount (only the final total)
# - List of items (name and price)
# - Paid by (if any name is mentioned)
#
# Return JSON like:
# {{
#   "total_amount": ...,
#   "items": [{{"name": "...", "price": ...}}, ...],
#   "paid_by": "..."  # optional
# }}
#
# OCR TEXT:
# {text}
# """
#
#     try:
#         result = subprocess.check_output(
#             ["ollama", "run", "llama3", prompt],
#             stderr=subprocess.STDOUT,
#             timeout=120
#         ).decode()
#     except subprocess.TimeoutExpired:
#         raise HTTPException(status_code=500, detail="Ollama timed out. Try again.")
#     except subprocess.CalledProcessError as e:
#         raise HTTPException(status_code=500, detail=f"Ollama error: {e.output.decode()}")
#
#     return {
#         "ocr_text": text,
#         "ollama_response": result
#     }
# @app.post("/trip/{trip_id}/upload-receipt")
# async def upload_receipt(
#     trip_id: int,
#     receipt_img: UploadFile = File(...),
#     user_id: int = Depends(require_login),
#     db: Session = Depends(get_db)
# ):
#     trip = db.query(Trip).filter_by(id=trip_id, created_by=user_id).first()
#     if not trip:
#         raise HTTPException(status_code=404, detail="Trip not found")
#
#     # OCR image handling
#     image_bytes = await receipt_img.read()
#     image = Image.open(io.BytesIO(image_bytes))
#     ocr_text = pytesseract.image_to_string(image)
#
#     # Llama3 prompt
#     prompt = f"""
#     Example:
# OCR:
# TANDOORI ROTI 6 24 144
# CHHAWAL KI ROTI 3 24 72
# Total: 810
#
# Return:
# {{
#   "total_amount": 810,
#   "items": [
#     {{"name": "TANDOORI ROTI", "qty": 6, "price": 24}},
#     {{"name": "CHHAWAL KI ROTI", "qty": 3, "price": 24}}
#   ]
# }}
#
#     ONLY return valid JSON. Do not include explanations, notes, or markdown code blocks.
#
#     OCR RECEIPT:
#     {ocr_text}
#     """
#
#     try:
#         response = httpx.post("http://localhost:11434/api/generate", json={
#             "model": "llama3",
#             "prompt": prompt,
#             "stream": False
#         }, timeout=180)
#
#         if response.status_code != 200:
#             raise HTTPException(status_code=500, detail="Ollama failed to respond")
#
#         ai_response = response.json()["response"]
#
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Ollama error: {str(e)}")
#
#     return HTMLResponse(f"""
#         <h2>🧾 OCR Extracted Text</h2>
#         <pre style="background:#eee; color:#333; padding:1rem;">{ocr_text}</pre>
#         <h2>🤖 AI (llama3) Parsed Output</h2>
#         <pre style="background:#eee; color:#333; padding:1rem;">{ai_response}</pre>
#         <a href="/trip/{trip_id}/add-expense"><button>⬅️ Back to Add Expense</button></a>
#     """)
@app.get("/my-settlements", response_class=HTMLResponse)
def view_my_settlements(
        request: Request,
        db: Session = Depends(get_db),
        user_id: int = Depends(require_login),
        member_name: Optional[str] = Query(None),
        show_all: bool = Query(False)
):
    groups = db.query(Group).filter_by(creator_id=user_id).all()
    group_ids = [g.g_id for g in groups]

    query = db.query(PaymentSettlement).filter(PaymentSettlement.group_id.in_(group_ids))
    if not show_all:
        query = query.filter(PaymentSettlement.is_settled == False)

    settlements = query.all()

    members = db.query(GroupMember).filter(GroupMember.group_id.in_(group_ids)).all()
    member_names = sorted(set(m.name for m in members))

    if member_name:
        settlements = [s for s in settlements if s.payer_name == member_name]

    return templates.TemplateResponse("my_settlements.html", {
        "request": request,
        "settlements": settlements,
        "member_names": member_names,
        "selected_member": member_name,
        "show_all": show_all
    })
@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_form(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})


import uuid

# Temporary token store: email → token
reset_tokens = {}


@app.post("/forgot-password")
def handle_forgot_password(
        request: Request,
        email: str = Form(...),
        db: Session = Depends(get_db)
):
    user = db.query(User).filter_by(email=email).first()
    if user:
        token = str(uuid.uuid4())
        reset_tokens[email] = token
        reset_link = f"http://localhost:8000/reset-password?email={email}&token={token}"

        # Send reset link (you could send via email; here, just print)
        send_otp_email(email, f"Click the link to reset your password:\n\n{reset_link}")

    # Show this message whether user exists or not (for security)
    return templates.TemplateResponse("reset_link_sent.html", {
        "request": request,
        "email": email
    })
@app.get("/reset-password", response_class=HTMLResponse)
def show_reset_password_form(
    request: Request,
    email: str,
    token: str
):
    # Validate token
    if reset_tokens.get(email) != token:
        return HTMLResponse("❌ Invalid or expired token", status_code=400)

    return templates.TemplateResponse("reset_password.html", {
        "request": request,
        "email": email,
        "token": token
    })
@app.post("/reset-password")
def reset_password(
    request: Request,
    email: str = Form(...),
    token: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    if new_password != confirm_password:
        return HTMLResponse("❌ Passwords do not match", status_code=400)

    if reset_tokens.get(email) != token:
        return HTMLResponse("❌ Invalid or expired token", status_code=400)

    user = db.query(User).filter_by(email=email).first()
    if not user:
        return HTMLResponse("❌ User not found", status_code=404)

    # Compare new password with old one
    if bcrypt.verify(new_password, user.hashed_password):
        html_content="""
        <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Password Reset Error</title>
  <meta http-equiv="refresh" content="3;url=javascript:history.back()">
  <style>
    body {
      margin: 0;
      height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      background: linear-gradient(to right, #141e30, #243b55);
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      color: #f8d7da;
    }

    .message-box {
      background-color: #2d2b42;
      padding: 2rem 2.5rem;
      border-radius: 12px;
      text-align: center;
      border: 1px solid #f44336;
      box-shadow: 0 0 10px rgba(244, 67, 54, 0.4);
    }

    h2 {
      margin-bottom: 1rem;
    }

    p {
      font-size: 0.95rem;
      color: #ffaaaa;
    }
  </style>
</head>
<body>
  <div class="message-box">
    <h2>❌ New password must be different from the current password.</h2>
    <p>Redirecting back in 3 seconds...</p>
  </div>
</body>
</html>
"""
        return HTMLResponse(content=html_content, status_code=400)

    user.hashed_password = bcrypt.hash(new_password)
    db.commit()

    del reset_tokens[email]

    return HTMLResponse("""
        <script>
        alert("✅ Password reset successfully. Please login.");
        window.location.href = "/login";
        </script>
    """)

