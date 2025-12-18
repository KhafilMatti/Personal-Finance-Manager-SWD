import os
import sys
from getpass import getpass


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from backend.app import app, db, User, Transaction, Budget
from werkzeug.security import generate_password_hash, check_password_hash

# Register a New User 
def register_user():
    with app.app_context():
        username = input("Enter a new username: ").strip()
        if User.query.filter_by(username=username).first():
            print(" User already exists.")
            return
        password = getpass("Enter a password: ").strip()
        confirm = getpass("Confirm password: ").strip()
        if password != confirm:
            print("Passwords dont match, please try again")
            return
        hashed_pw = generate_password_hash(password)
        # new_user = User(username=username, password_hash=hashed_pw)
        role = input("Enter role ('admin' or 'user) [default user] : ").strip().lower()
        if role not in ("admin", "user"):
            role = "user"
        new_user = User(username=username, password_hash=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()
        print(" User registered successfully as {role}.")


def is_administrator(user):
    return getattr(user, "role", "user") == "admin"

# Login Existing User
def login_user():
    with app.app_context():
        username = input("Enter your username: ").strip()
        password = getpass("Enter your password: ").strip()
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            print(" Invalid credentials.")
            return None
        print(" Login successful.")
        return user


# Add Transaction 
def add_transaction(user):
    with app.app_context():
        category = input("Enter transaction category (e.g., groceries, rent): ").strip()
        try:
            amount = float(input("Enter transaction amount: "))
        except ValueError:
            print(" Invalid amount.")
            return
        new_txn = Transaction(user_id=user.id, category=category, amount=amount)
        db.session.add(new_txn)
        db.session.commit()

        
        print(f" Transaction added (ID: {new_txn.id}) for user {user.username}.")


# View Transactions 
def view_transactions(user):
    with app.app_context():
        # transactions = Transaction.query.filter_by(user_id=user.id).all()
        if not user:
            print(" User not found.")
            return
            
        print(f"\n Current user: {user.username}, role: {getattr(user, 'role', 'user')}")

        # If admin → see ALL transactions
        if is_administrator(user):
            query = Transaction.query.order_by(Transaction.id.asc())
        else:
            # Normal user → only their own
            query = Transaction.query.filter_by(user_id=user.id).order_by(Transaction.id.asc())

        transactions = query.all()

        if not transactions:
            if is_administrator(user):
                print(" No transactions found on the system.")
            else:
                print("No transactions yet")
            return

        if is_administrator(user):
            print("All transactions:")
            print("ID. | Category.   | Amount")
            for t in transactions:
                u = User.query.get(t.user_id)
                username = u.username if u else "Unknown"
                print(f"{t.id:<2} | {username:<10} | {t.category:<15} | {t.amount:<6}")
        else:
            print("\n Your Transactions:")
            print("ID. | Category.   | Amount")

            for t in transactions:
                print(f"{t.id:<2} | {t.category:<15} | {t.amount:<6}")

        # print("\n Your Transactions:")
        # for txn in transactions:
        #     print(f"{txn.id}. Category: {txn.category}, Amount: {txn.amount}")


def admin_view_all_transactions(user):
    with app.app_context():
        if not is_administrator(user):
            print("Not Permitted")
            return

        transactions = Transactions.query.order_by(Transaction.id.asc()).all()
        if not transactions:
            print("No transactions found")
            return

        print("All transactions:")
        print("ID | User  | Category ")
        for t in transactions:
            u = User.query.get(t.user_id)
            username = u.username if u else "Unknown"

            print(
                f"{t.id:<2} | {username:<11} | "
                f"{(t.category or ''):<14} | "
                f"{(t.description or ''):<25} | "
                f"{t.amount:<6}"
            )


# Edit Transaction
def edit_transaction(user):
    with app.app_context():
        transactions = Transaction.query.filter_by(user_id=user.id).all()
        if not transactions:
            print(" No transactions found.")
            return

        if not is_administrator(user):
            print("You dont have permission, please contact administrator")

        for txn in transactions:
            print(f"{txn.id}. Category: {txn.category}, Amount: {txn.amount}")
        try:
            txn_id = int(input("Enter ID of transaction to edit: "))
        except ValueError:
            print(" Invalid ID.")
            return
        txn = Transaction.query.filter_by(id=txn_id, user_id=user.id).first()
        if not txn:
            print(" Transaction not found.")
            return
        new_category = input(f"Enter new category (current: {txn.category}): ").strip()
        try:
            new_amount = float(input(f"Enter new amount (current: {txn.amount}): "))
        except ValueError:
            print(" Invalid amount.")
            return
        txn.category = new_category
        txn.amount = new_amount
        db.session.commit()
        print(" Transaction updated.")


# Budget Alerts 
def budget_alerts(user):
    with app.app_context():
        transactions = Transaction.query.filter_by(user_id=user.id).all()
        budgets = Budget.query.filter_by(user_id=user.id).all()
        category_totals = {}
        for t in transactions:
            category_totals[t.category] = category_totals.get(t.category, 0) + t.amount
        alerts = []
        for b in budgets:
            total = category_totals.get(b.category, 0)
            if total > b.limit:
                alerts.append(f"⚠️ Budget exceeded for {b.category}: {total} / {b.limit}")
        if alerts:
            print("\n Budget Alerts:")
            for alert in alerts:
                print(alert)
        else:
            print(" All budgets are within limits.")


# Add Budget 
def add_budget(user):
    with app.app_context():
        if not user:
            print("User not found.")
            return 
    
        category = input("Enter budget category (e.g., groceries, rent): ").strip()
        if not category:
            print("Category cannot be empty")
            return

        try:
            limit=float(input("Enter budget limit amount: ").strip())
        except ValueError:
            print(" Invalid amount.")
            return

        new_budget = Budget(
            user_id=user.id,
            category=category,
            limit=limit,
            is_archived=False
        )

        db.session.add(new_budget)
        db.session.commit()
        print(f" Budget added successfully (ID: {new_budget.id}).")



# Edit Budget 
def edit_budget(user):
    with app.app_context():
        budgets = Budget.query.filter_by(user_id=user.id).all()
        if not budgets:
            print(" No budgets found.")
            return
        print("\n Your Budgets:")
        for b in budgets:
            print(f"{b.id}. Category: {b.category}, Limit: {b.limit}")
        try:
            budget_id = int(input("Enter ID of budget to edit: "))
        except ValueError:
            print(" Invalid ID.")
            return
        budget = Budget.query.filter_by(id=budget_id, user_id=user.id).first()
        if not budget:
            print(" Budget not found.")
            return
        new_category = input(f"Enter new category (current: {budget.category}): ").strip()
        try:
            new_limit = float(input(f"Enter new limit amount (current: {budget.limit}): "))
        except ValueError:
            print(" Invalid amount.")
            return
        budget.category = new_category
        budget.limit = new_limit
        db.session.commit()
        print(" Budget updated.")


def list_budgets(user):
    with app.app_context():
        # user = User.query.filter_by(username=user).first()
        if not user:
            print("User not Found")
            return[]

        # q = Budget.query.filter_by(user_id=user.id)
        # if show_archived:
        #     q=q.filter_by(is_archived=True)
        # else:
        #     q=q.filter_by(is_archived=False)

        if is_administrator(user):
            query = Budget.query.filter_by(is_archived=False)
        else:
            query = Budget.query.filter_by(user_id=user.id, is_archived=False)
 
        budgets = query.order_by(Budget.id.asc()).all()

        if not budgets:
            print("No archived budgets:")
            return []

        if is_administrator(user):
            print("Active budgets (All Users)")
            print("ID.    |.   User.   |. Amount.    | Archived")
            for b in budgets:
                u = db.session.get(User, b.user_id)
                username = u.username if u else "Unknown"
                print(
                    f"{b.id:<2} | {username:<11} |  {b.category:<16} | {b.limit:<8} | {str(b.is_archived):<8}"
                )
        
        else:
            print("In your budgets:")
            print(" ID | Category   | Amount   | Archived")
            for b in budgets:
                print(f"{b.id:<2} | {b.category:<16} | {b.limit:<9} | {str(b.is_archived):<8}")
            
        return budgets 

def archive_budget_cli(user):
    with app.app_context():
        # user = User.query.filter_by(username=username).first()
        if not user:
            print("User not found")
            return

        budgets = list_budgets(user)
        if not budgets:
            return

        try:
            budget_id = int(input("Enter ID of the Budget to archive: ").strip())
        except ValueError:
            print(" Invalid ID")
            return



        if is_administrator(user):
            budget = Budget.query.filter_by(id=budget_id, is_archived=False).first()
        else:
            budget = Budget.query.filter_by(id=budget_id, user_id=user.id, is_archived=False).first()

        if not budget:
            print(" Budget not found or authorised")
            return

        budget.is_archived = True
        db.session.commit()
        print("Budget has been archived")

def delete_budget_cli(user):
    with app.app_context():
        # user = User.query.filter_by(username=user).first()
        if not user:
            print(" User not found")
            return

        print("(Active budgets)")
        list_budgets(user, show_archived=False)
        print("(Archived Budgets)")
        list_budgets(user, show_archived=True)

        try:
            budget_id = int(input("Enter the ID of the budget to DELETE:...").strip())
        except ValueError:
            print("Invalid ID")
            return

        budget = Budget.query.filter_by(id=budget_id, user_id=user.id).first()
        if not budget:
            print("Budget not found or unauthorised")
            return

        confirm = input("This will permanently remove the budget. Type 'DELETE' to confirm").strip()
        if confirm != "DELETE":
            print("Deletion cancelled")
            return
        
        db.session.delete(budget)
        db.session.commit()
        print("budget deleted successfully")

def view_archived_budget(user):
    with app.app_context():
        if not user:
            print(" User not found")
            return []

        print(f"[DEBUG] view_archived_budget: user={user.username}, role={getattr(user, 'role', 'user')}, admin={is_administrator(user)}")

        if is_administrator(user):
            query = Budget.query.filter_by(is_archived=True)
        else:
            query = Budget.query.filter_by(user_id=user.id, is_archived=True)

        budgets = query.order_by(Budget.id.asc()).all()

        print(f"[DEBUG] view_archived_budget: found {len(budgets)} archived budgets for this view")

        if not budgets:
            print("No archived budgets found")
            return []

        if is_administrator(user):
            print("Archived budgets (All users)")
            print(" ID | User        | Category         | Amount    | Archived")
            for b in budgets:
                u = db.session.get(User, b.user_id)
                username = u.username if u else "Unknown"
                print(f"{b.id:<2} | {username:<11} | {b.category:<16} | {b.limit:<9} | {str(b.is_archived):<8}")

        else:
            print("Your archived budgets")
            print(" ID | Category         | Amount    | Archived")
            for b in budgets:
                print(f"{b.id:<2} | {b.category:<16} | {b.limit:<9} | {str(b.is_archived):<8}")

        return budgets
    

def unarchive_budget_cli(user):
    with app.app_context():
        if not user:
            print("User not Found")
            return
        
        archived_budgets = view_archived_budget(user)
        if not archived_budgets:
            return

        try:
            budget_id = int(input("\n Enter the ID of the budget to unarchive: ").strip())
        except ValueError:
            print(" Invalid ID.")
            return

        if is_administrator(user):
            budget = Budget.query.filter_by(id=budget_id, is_archived=True).first()
        else:
            budget = Budget.query.filter_by(id=budget_id, user_id=user.id, is_archived=True).first()

        if not budget:
            print("Budget is not found or archived.")
            return
        
        budget.is_archived = False
        db.session.commit()
        print(" Budget unarchived successfully. It is now active again.")


def list_user_cli(user):
    with app.app_context():
        if not is_administrator(user):
            print("Cant perform action")
            return

        users = User.query.order_by(User.id.asc()).all()
        if not users:
            print("No user found")
            return

        print("Registered users:")
        print(" ID | Username | Role")
        for u in users:
            print(f"{u.id:<2} | {u.username:<15} | {u.role}")

# Main Menu 
def main():
    while True:
        print("\n Finance Dashboard Menu")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Select an option: ").strip()

        if choice == '1':
            register_user()
        elif choice == '2':
            user = login_user()
            if user:
                print(f"\n Welcome, {user.username}! (role:{user.role})")
                while True:
                    print("\n User Options")
                    print("1. Add Transaction")
                    print("2. View Transactions")
                    print("3. Add Budget")
                    print("4. Edit Budget")
                    print("5. Budget Alerts")
                    print("6. list budget")
                    print("7. Archive a budget")
                    print("8. Delete a budget")
                    print("9. View archived budgets")
                    print("10. Unarchive budget")
                    

                    if is_administrator(user):
                        print("11. Edit Transaction")
                        print("12. View all user")
                    
                    print("0. Logout")
                    
                    user_choice = input("Select an action: ").strip()

                    if user_choice == "1":
                        add_transaction(user)
                    elif user_choice == "2":
                        view_transactions(user)
                    elif user_choice == "11":
                        edit_transaction(user)
                    elif user_choice == "3":
                        add_budget(user)
                    elif user_choice == "4":
                        edit_budget(user)
                    elif user_choice == "5":
                        budget_alerts(user)
                    elif user_choice == "6":
                        list_budgets(user)
                    elif user_choice == "7":
                        archive_budget_cli(user)
                    elif user_choice == "8":
                        delete_budget_cli(user)
                    elif user_choice == "9":
                        view_archived_budget(user)
                    elif user_choice == "10":
                        unarchive_budget_cli(user)
                    elif user_choice == "12" and is_administrator(user):
                        list_user_cli(user) 
                    elif user_choice == "13" and is_administrator(user):
                        admin_view_all_transactions(user)
                    elif user_choice == "0":
                        print("Logging out...")
                        break
                    else:
                        print(" Invalid option. Try again.")
                # user_dashboard(user)
        elif choice == '3':
            print("Goodbye, see you soon!")
            break
        else:
            print(" Invalid choice. Try again.")


if __name__ == "__main__":
    main()
