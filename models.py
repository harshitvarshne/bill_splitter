from xmlrpc.client import boolean

from sqlalchemy import Column, Integer, String, ForeignKey, Float, Boolean, DateTime, JSON
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100))
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String(200))
    bill_group = relationship("Group", back_populates="creator")
    group_memberships = relationship("GroupMember", back_populates="user")

class Group(Base):
    __tablename__ = "bill_group"
    g_id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    creator_id = Column(Integer, ForeignKey("users.id"))

    creator = relationship("User", back_populates="bill_group")
    members = relationship("GroupMember", back_populates="group")


class GroupMember(Base):
    __tablename__ = 'group_members'
    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey('bill_group.g_id'))
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    name = Column(String(100))

    group = relationship("Group", back_populates="members")
    user = relationship("User", back_populates="group_memberships")

class PaymentSettlement(Base):
    __tablename__ = "payment_settlements"

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey("bill_group.g_id"))
    payer_name = Column(String(100))
    receiver_name = Column(String(100))
    amount = Column(Float)
    is_settled = Column(Boolean, default=False)
class Trip(Base):
    __tablename__ = "trips"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    group_id = Column(Integer, ForeignKey("bill_group.g_id"))
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    is_closed = Column(Boolean, default=False)

    group = relationship("Group")
    expenses = relationship("TripExpense", back_populates="trip")


class TripExpense(Base):
    __tablename__ = "trip_expenses"
    id = Column(Integer, primary_key=True)
    trip_id = Column(Integer, ForeignKey("trips.id"))
    category = Column(String(100), nullable=False)
    description = Column(String(255), nullable=False)
    total_amount = Column(Float, nullable=False)
    paid_by = Column(String(100), nullable=False)
    split_type = Column(String(20), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    trip = relationship("Trip", back_populates="expenses")
    shares = relationship("TripExpenseShare", back_populates="expense", cascade="all, delete-orphan")

class TripExpenseShare(Base):
    __tablename__ = "trip_expense_shares"
    id = Column(Integer, primary_key=True)
    expense_id = Column(Integer, ForeignKey("trip_expenses.id"))
    member_name = Column(String(100), nullable=False)
    amount = Column(Float, nullable=False)
    expense = relationship("TripExpense", back_populates="shares")

class Expense(Base):
    __tablename__ = 'expenses'

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("bill_group.g_id"))
    title = Column(String(255))
    total_amount = Column(Float)
    paid_by = Column(JSON)  # {user_id: amount}
    split_type = Column(String(20))  # 'equal', 'percentage', 'share', 'custom'
    split_detail = Column(JSON)  # {user_id: value based on split_type}

