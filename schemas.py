"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogs" collection
"""

from pydantic import BaseModel, Field
from typing import Optional

# Example schemas (retain for reference/other features)

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user" (lowercase of class name)
    """
    name: str = Field(..., description="Full name")
    email: str = Field(..., description="Email address")
    address: str = Field(..., description="Address")
    age: Optional[int] = Field(None, ge=0, le=120, description="Age in years")
    is_active: bool = Field(True, description="Whether user is active")

class Product(BaseModel):
    """
    Products collection schema
    Collection name: "product" (lowercase of class name)
    """
    title: str = Field(..., description="Product title")
    description: Optional[str] = Field(None, description="Product description")
    price: float = Field(..., ge=0, description="Price in dollars")
    category: str = Field(..., description="Product category")
    in_stock: bool = Field(True, description="Whether product is in stock")

# Authentication-related schemas used by the app

class AuthUser(BaseModel):
    """
    Auth users for application login
    Collection name: "authuser"
    """
    email: str = Field(..., description="Unique email")
    name: Optional[str] = Field(None, description="Display name")
    password_hash: str = Field(..., description="Hex-encoded password hash")
    salt: str = Field(..., description="Per-user salt")
    is_active: bool = Field(True, description="Whether user can sign in")

class AuthToken(BaseModel):
    """
    Login tokens issued after authentication
    Collection name: "authtoken"
    """
    user_id: str = Field(..., description="ID of AuthUser document")
    token: str = Field(..., description="Opaque token string")
    expires_at: int = Field(..., description="Unix timestamp (seconds)")
