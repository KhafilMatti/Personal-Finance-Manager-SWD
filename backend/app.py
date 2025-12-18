from flask import Flask, request, jsonify, render_template, redirect, url_for, session, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from datetime import datetime 
import secrets
from functools import wraps

app = Flask(__name__)

# Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///finance_manager.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "c110f322443cf434fe658a8b8aaaa400aa78a39e37b9cebf0ad214c9594a4458"
app.config["JWT_SECRET_KEY"] = "another-long-secret-key"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")

    transactions = db.relationship("Transaction", backref="user", lazy=True)
    budgets = db.relationship("Budget", backref="user", lazy=True)


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "category": self.category,
            "amount": self.amount
        }

class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    limit = db.Column(db.Float, nullable=False)
    is_archived = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Routes
@app.route("/api")
def api_home():
    return jsonify({"message": "Welcome to Personal Finance Manager API"})

# Register
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "User already exists"}), 409

    hashed_pw = generate_password_hash(password)
    new_user = User(username=username, password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# Login
@app.route("/api/login", methods=["GET","POST"])
def api_login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify(access_token=access_token), 200

# Simulated Logout
@app.route("/api/logout", methods=["POST"])
@jwt_required()
def api_logout():
    return jsonify({"message": "Logout successful (client should delete token)"}), 200

# View All Transactions
@app.route("/api/transactions", methods=["GET"])
@jwt_required()
def get_transactions():
    user_id = get_jwt_identity()
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    return jsonify([t.to_dict() for t in transactions]), 200

# Add Transaction
@app.route("/api/transaction", methods=["POST"])
@jwt_required()
def add_transaction():
    data = request.get_json() or {}
    user_id = get_jwt_identity()

    if "category" not in data or "amount" not in data:
        return jsonify({"message": "category and amount are required"}), 400

    new_transaction = Transaction(
        user_id=user_id,
        category=data["category"],
        amount=data["amount"]
    )
    db.session.add(new_transaction)
    db.session.commit()

    return jsonify({"message": "Transaction added successfully"}), 201

# Edit Transaction
@app.route("/api/transaction/<int:transaction_id>", methods=["PUT"])
@jwt_required()
def update_transaction(transaction_id):
    data = request.get_json() or {}
    user_id = get_jwt_identity()

    transaction = Transaction.query.filter_by(id=transaction_id, user_id=user_id).first()
    if not transaction:
        return jsonify({"message": "Transaction not found"}), 404

    transaction.category = data.get("category", transaction.category)
    transaction.amount = data.get("amount", transaction.amount)
    db.session.commit()

    return jsonify({"message": "Transaction updated successfully"}), 200

# Delete Transaction
@app.route("/api/transaction/<int:transaction_id>", methods=["DELETE"])
@jwt_required()
def delete_transaction(transaction_id):
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))

    if not user or user.role != "admin":
        return jsonify({"message": "Contact administrator to delete transaction"})

    transaction = db.session.get(Transaction, transaction_id)
    if not transaction:
        return jsonify({"message": "Transaction not found"}), 404

    db.session.delete(transaction)
    db.session.commit()
    return jsonify({"message": "Transaction deleted successfully"}), 200

# Add Budget
@app.route("/api/budget", methods=["POST"])
@jwt_required()
def add_budget():
    data = request.get_json() or {}
    user_id = get_jwt_identity()

    if "category" not in data or "limit" not in data:
        return jsonify({"message":"category and limit are required"}), 400

    new_budget = Budget(
        user_id=user_id,
        category=data["category"],
        limit=data["limit"]
    )
    db.session.add(new_budget)
    db.session.commit()
    return redirect(url_for("dashboard"))

    return jsonify({"message": "Budget added successfully"}), 201

# View Budgets
@app.route("/api/budgets", methods=["GET"])
@jwt_required()
def view_budgets():
    user_id = get_jwt_identity()
    budgets = Budget.query.filter_by(user_id=user_id).all()
    return (jsonify([
        {"id": b.id, "category": b.category, "limit": b.limit, "is_achived": b.is_archived,}
        for b in budgets
    ]), 200,
    )
# Edit Budget
@app.route("/api/budget/<int:budget_id>", methods=["PUT"])
@jwt_required()
def update_budget(budget_id):
    data = request.get_json() or {}
    user_id = get_jwt_identity()
    budget = Budget.query.filter_by(id=budget_id, user_id=user_id).first()
    if not budget:
        return jsonify({"message": "Budget not found"}), 404

    budget.category = data.get("category", budget.category)
    budget.limit = data.get("limit", budget.limit)
    db.session.commit()

    return jsonify({"message": "Budget updated successfully"}), 200

# Budget Alert
@app.route("/api/budget_alert", methods=["GET"])
@jwt_required()
def budget_alert():
    user_id = get_jwt_identity()
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    budgets = Budget.query.filter_by(user_id=user_id).all()

    category_totals = {}
    for t in transactions:
        category_totals[t.category] = category_totals.get(t.category, 0) + t.amount

    alerts = []
    for b in budgets:
        if category_totals.get(b.category, 0) > b.limit:
            alerts.append(f" You exceeded your {b.category} budget!")

    return jsonify({"alerts": alerts}), 200

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.session.get(User, int(user_id))

def admin_required(f):
    @wraps(f)
    def wrapper(*args,**kwargs):
        user = current_user()

        if not user or user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper

@app.route("/")
def home():
    user = current_user()
    if user:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login_page"))

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        return render_template("login.html")
    username = request.form.get("username","").strip()
    password = request.form.get("password", "")

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return render_template("login.html", error= "Invalid username or password.")

    session["user_id"] = user.id
    return redirect(url_for("dashboard"))


@app.route("/admin/create_user", methods=["GET","POST"])
@admin_required
def admin_create_user():
    admin = current_user()

    if request.method == "GET":
        return render_template("admin_create_user.html", admin=admin)
    

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    confirm = request.form.get("confirm","").strip()
    role = request.form.get("role","user").strip().lower()


    if not username or not password:
        flash("Username and Password are required.", "danger")
        return redirect(url_for("admin_create_user"))

    if password != confirm:
        flash("Passwords dont match","danger")
        return redirect(url_for("admin_create_user"))

    if User.query.filter_by(username=username).first():
        flash("Username already exists", "danger")
        return redirect(url_for("admin_create_user"))

    if role not in ("admin", "user"):
        role = "user"

    hashed_pw = generate_password_hash(password)
    new_user = User(username=username, password_hash=hashed_pw, role=role)
    db.session.add(new_user)
    db.session.commit()

    flash(f"User '{username}' created successfully.", "success")
    return redirect(url_for("admin_users"))

@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")
    role = request.form.get("role", "user").strip().lower()

    if not username or not password:
        return render_template("register.html", error="Username and Password are required")

    if password != confirm:
        return render_template("register.html", error="Passwrods do not match")

    if User.query.filter_by(username=username).first():
        return render_template("register.html",error="Username already exists.")

    if role not in ("admin", "user"):
        role = "user"

    hashed_pw = generate_password_hash(password)
    new_user = User(username=username, password_hash=hashed_pw, role=role)
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for("login_page"))

@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login_page"))


    # user = User.query.get(user_id)
    budgets = Budget.query.filter_by(user_id=user.id, is_archived=False).all()
    transactions = Transaction.query.filter_by(user_id=user.id).all()
    archived_budgets = Budget.query.filter_by(user_id=user.id, is_archived=True).all()

    total_spent = sum(t.amount for t in transactions)

    category_totals = {}
    for t in transactions:
        category_totals[t.category] = category_totals.get(t.category, 0) + t.amount
    
    alerts = []
    for b in budgets:
        spent = category_totals.get(b.category, 0)
        if spent > b.limit:
            alerts.append({
                "category": b.category,
                "limit": b.limit,
                "spent": spent,
                "difference": spent - b.limit,
            })

    return render_template(
        "dashboard.html",
        user=user,
        budgets=budgets,
        transactions=transactions,
        archived_budgets=archived_budgets,
        total_spent=total_spent,
        category_totals=category_totals,
        alerts=alerts,
    )


# ---------- WEB ROUTES FOR BUDGETS ----------

@app.route("/budget/add", methods=["POST"])
def add_budget_web():
    user = current_user()
    if not user:
        return redirect(url_for("login_page"))

    category = request.form.get("category", "").strip()
    limit = request.form.get("limit", "").strip()

    if not category or not limit:
        # in future you can flash an error if you like
        return redirect(url_for("dashboard"))

    new_budget = Budget(
        user_id=user.id,
        category=category,
        limit=float(limit),
    )
    db.session.add(new_budget)
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/budget/<int:budget_id>/delete", methods=["POST"])
def delete_budget_web(budget_id):
    user = current_user()
    if not user:
        return redirect(url_for("login_page"))

    if user.role != "admin":
        flash("Contact administrator to delete a budget")
        return redirect(url_for("dashboard"))
    
    budget = db.session.get(Budget, budget_id)
    if not budget:
        flash("Budget not Found")
        return redirect(url_for("dashboard"))




    db.session.delete(budget)
    db.session.commit()
    flash("Budget deleted")
    return redirect(url_for("dashboard"))


@app.route("/budget/<int:budget_id>/edit", methods=["POST"])
def edit_budget_web(budget_id):
    user = current_user()
    if not user:
        return redirect(url_for("login_page"))

    budget = Budget.query.filter_by(id=budget_id, user_id=user.id).first()
    if not budget:
        return redirect(url_for("dashboard"))

    category = request.form.get("category", "").strip()
    limit = request.form.get("limit", "").strip()

    if category:
        budget.category = category
    if limit:
        budget.limit = float(limit)

    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/budget/<int:budget_id>/toggle_archive",methods=["POST"])
def toggle_budget_archive(budget_id):
    """Archive or unarchived a budget"""
    user = current_user()
    if not user:
        return redirect(url_for("login_page"))

    budget = Budget.query.filter_by(id=budget_id, user_id=user.id).first()
    if not budget:
        flash("Budget not found")
        return redirect(url_for("dashboard"))

    budget.is_archived = not budget.is_archived
    db.session.commit()
    flash("Budget archived")
    return redirect(url_for("dashboard"))



    @app.route("/budget/<int:budget_id>unarchive", methods=["POST"])
    def unarchive_budget(budget_id):
        user = current_user()
        if not user:
            return redirect(url_for("login_page"))

        budget = Budget.query.filter_by(id=budget_id,user_id=user.id).first()
        if not budget:
            flash("Budget not found")
            return redirect(url_for("archived_budgets"))

        budget.archived = False 
        db.session.commit()
        flash("Budget unarchived, return to dashboard")
        return redirect(url_for("dashboard"))

@app.route("/admin/user/<int:user_id>/reset_password",methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    admin = current_user()
    user = User.query.get_or_404(user_id)

    temp_password = secrets.token_urlsafe(8)[:12]

    user.password_hash = generate_password_hash(temp_password)
    db.session.commit()

    flash(f"Temporary password for {user.username}: {temp_password}", "warning")
    return redirect(url_for("admin_users"))

@app.route("/admin/user/<int:user_id>/delete",methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    admin = current_user()
    user = User.query.get_or_404(user_id)

    if user.id == admin.id:
        flash("You cannot delete your own admin account while logged in", "danger")
        return redirect(url_for("admin_users"))

    Transaction.query.filter_by(user_id=user.id).delete()
    Budget.query.filter_by(user_id=user.id).delete()

    db.session.delete(user)
    db.session.commit()

    flash(f"User '{user.username}' and all their data were is now deleted", "success")
    return redirect(url_for("admin_users"))

# ---------- WEB ROUTES FOR TRANSACTIONS ----------

@app.route("/transaction/add", methods=["POST"])
def add_transaction_web():
    user = current_user()
    if not user:
        return redirect(url_for("login_page"))

    category = request.form.get("category", "").strip()
    amount = request.form.get("amount", "").strip()

    if not category or not amount:
        return redirect(url_for("dashboard"))

    new_tx = Transaction(
        user_id=user.id,
        category=category,
        amount=float(amount),
    )
    db.session.add(new_tx)
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/transaction/<int:tx_id>/delete", methods=["POST"])
def delete_transaction_web(tx_id):
    user = current_user()
    if not user:
        return redirect(url_for("login_page"))

    if user.role != "admin":
        flash("Contact Administrator to delete transaction")
        return redirect(url_for("dashboard"))

    
    tx = db.session.get(Transaction, tx_id)
    if not tx:
        flash("Transaction not found")
        return redirect(url_for("dashboard"))


    db.session.delete(tx)
    db.session.commit()
    flash("Transaction is now deleted")
    return redirect(url_for("dashboard"))

@app.route("/budget/<int:budget_id>")
def budget_detail(budget_id):
    """Show details for a single busget and its transactions."""
    user = current_user()
    if not user:
        return redirect(url_for("login_page"))

    budget = Budget.query.filter_by(id=budget_id, user_id=user.id).first_or_404()

    transactions = Transaction.query.filter_by(
        user_id=user.id,
        category=budget.category
    ).all()

    total_spent = sum(t.amount for t in transactions)
    remaining = budget.limit - total_spent

    return render_template(
        "budget_details.html",
        user=user,
        budget=budget,
        transactions=transactions,
        total_spent=total_spent,
        remaining=remaining,
    )

@app.route("/admin/user/<int:user_id>")
@admin_required
def admin_user_detail(user_id):
    admin = current_user()

    target_user = User.query.get_or_404(user_id)
    budgets = Budget.query.filter_by(user_id=target_user.id).all()
    transactions = Transaction.query.filter_by(user_id=target_user.id).all()

    total_spent = sum(t.amount for t in transactions)

    category_totals = {}
    for t in transactions:
        category_totals[t.category] = category_totals.get(t.category, 0) + t.amount

    alerts = []
    for b in budgets:
        spent = category_totals.get(b.category, 0)
        if spent > b.limit:
            alerts.append({
                "category": b.b.category,
                "limit": b.limit,
                "spent":spent,
                "difference": spent - b.limit,
            })

    return render_template(
        "admin_user_detail.html",
        admin=admin,
        target_user=target_user,
        budgets=budgets,
        transactions=transactions,
        total_spent=total_spent,
        category_totals=category_totals,
        alerts=alerts,
    )


@app.route("/transaction/<int:tx_id>/edit", methods=["POST"])
def edit_transaction_web(tx_id):
    user = current_user()
    if not user:
        return redirect(url_for("login_page"))

    tx = Transaction.query.filter_by(id=tx_id, user_id=user.id).first()
    if not tx:
        return redirect(url_for("dashboard"))

    category = request.form.get("category", "").strip()
    amount = request.form.get("amount", "").strip()

    if category:
        tx.category = category
    if amount:
        tx.amount = float(amount)

    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/admin/users")
@admin_required
def admin_users():
    admin = current_user()
    users = User.query.order_by(User.username.asc()).all()
    return render_template("admin_users.html", admin=admin, users=users)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# Run app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

