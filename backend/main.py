from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials  # ✅ Fixed
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import timedelta

import models
import crud
import schemas
from database import engine, SessionLocal
from auth import create_access_token, decode_token, ACCESS_TOKEN_EXPIRE_MINUTES

# Create database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Support CRM API", version="2.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://customer-support-ticketing-crm-syst.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()


# ==================== DEPENDENCIES ====================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),  # ✅ Fixed
    db: Session = Depends(get_db)
):
    """Extract and validate current user from JWT token."""
    token = credentials.credentials
    token_data = decode_token(token)
    user = crud.get_user_by_id(db, token_data["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_admin(current_user: models.User = Depends(get_current_user)):
    """Ensure user is an admin."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def require_customer(current_user: models.User = Depends(get_current_user)):
    """Ensure user is a customer."""
    if current_user.role != "customer":
        raise HTTPException(status_code=403, detail="Customer access required")
    return current_user


# ==================== HEALTH CHECK ====================

@app.get("/")
def home():
    return {"message": "Support CRM API Running", "version": "2.0.0"}


# ==================== AUTH ENDPOINTS ====================

@app.post("/api/auth/register", response_model=schemas.UserResponse, status_code=201)
def register(user: schemas.UserRegister, db: Session = Depends(get_db)):
    """Register a new user."""

    if crud.get_user_by_username(db, user.username):
        raise HTTPException(status_code=400, detail="Username already registered")

    if crud.get_user_by_email(db, user.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    # Assign role
    role = "customer"

    if user.email == "superadmin@gmail.com":
        role = "admin"

    # Create user
    new_user = models.User(
        username=user.username,
        email=user.email,
        password=user.password,
        role=role
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@app.post("/api/auth/login", response_model=schemas.TokenResponse)
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    """Login user and return JWT token."""
    db_user = crud.authenticate_user(db, user.username, user.password)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.id, "role": db_user.role},
        expires_delta=access_token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": db_user.id,
        "username": db_user.username,
        "role": db_user.role,
    }


@app.get("/api/auth/me", response_model=schemas.UserResponse)
def get_current_user_info(current_user: models.User = Depends(get_current_user)):
    """Get current logged-in user info."""
    return current_user


# ==================== CUSTOMER TICKET ENDPOINTS ====================

@app.post("/api/tickets", response_model=schemas.TicketResponse, status_code=201)
def create_ticket(
    ticket: schemas.TicketCreate,
    current_user: models.User = Depends(require_customer),
    db: Session = Depends(get_db)
):
    """Create a new support ticket (customer only)."""
    db_ticket = crud.create_ticket(db, ticket, current_user.id)
    if not db_ticket:
        raise HTTPException(status_code=400, detail="Could not create ticket")
    return db_ticket


@app.get("/api/tickets/my-tickets", response_model=List[schemas.TicketResponse])
def get_my_tickets(
    status: Optional[str] = None,
    search: Optional[str] = None,
    current_user: models.User = Depends(require_customer),
    db: Session = Depends(get_db),
):
    """Get tickets for the current customer."""
    return crud.get_user_tickets(db, current_user.id, status, search)


# ✅ FIXED: /my-tickets MUST come BEFORE /{ticket_id}
@app.get("/api/tickets/my-tickets", response_model=List[schemas.TicketResponse])
def get_my_tickets(
    status: Optional[str] = None,
    search: Optional[str] = None,
    current_user: models.User = Depends(require_customer),
    db: Session = Depends(get_db),
):
    """Get tickets for the current customer."""
    return crud.get_user_tickets(db, current_user.id, status, search)


@app.get("/api/tickets/{ticket_id}", response_model=schemas.TicketResponse)
def get_ticket(
    ticket_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get ticket details. Customer can only see their own, admin can see all."""
    ticket = crud.get_ticket(db, ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    if current_user.role == "customer" and ticket.customer_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    return ticket


# ==================== ADMIN TICKET ENDPOINTS ====================

@app.get("/api/admin/tickets", response_model=List[schemas.TicketResponse])
def get_all_tickets(
    status: Optional[str] = None,
    search: Optional[str] = None,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Get all tickets (admin only)."""
    return crud.get_all_tickets(db, status, search)


@app.put("/api/admin/tickets/{ticket_id}", response_model=schemas.TicketResponse)
def update_ticket(
    ticket_id: str,
    ticket: schemas.TicketUpdate,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Update ticket status and notes (admin only)."""
    updated = crud.update_ticket(db, ticket_id, ticket)
    if not updated:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return updated


@app.delete("/api/admin/tickets/{ticket_id}")
def delete_ticket(
    ticket_id: str,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete a ticket (admin only)."""
    deleted = crud.delete_ticket(db, ticket_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return {"message": "Ticket deleted successfully"}


@app.get("/api/admin/stats")
def get_stats(
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics (admin only)."""
    return crud.get_stats(db)
