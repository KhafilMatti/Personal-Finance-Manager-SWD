PERSONAL FINANCE MANAGER

A Flask based personal finance management system that helps users track expenses, manage budgets and transactions. This is a secure web application, implementing secure authentication, access control, inpuit validation and protecting the application against web vulnerabilities 

------------------------------------
Core features
-User registration and login/logout
-CRUD functionality for budgets 
-Add snd edit transactions
-Special panel for administrator

Security features
-Password Hashing
-Role Based Access Control
-Secure Session Handling 
-Input Validation
-SQLAlchemy ORM 

------------------------------------

Setup and Installation

- python
- pip
- VS Code

1) Create and activate Virtual Environment
   python -m venv venv
   source venv/bin/activate

2)Install dependencies 
  pip install -r requirements.txt
  
3) Initialise database
   python -c "from app import app, db; app.app_context().push(); db.create_all();        print('DB ready')

------------------------------------
Usage Guidelines
Register/ Login
1. Register a new user
2. Log in with your credentials
3. You will be directed to the dashboard
Budgets
1. Add a budget with a category and price limit
2. Edit an existing budget
3. Archive a budget (moves buddget to an archived budget widget section)
4. Unarchive a budget(moves budget to the budget widget section)
5. View budget details
Transactions
1.Add a transaction with a category and amount
2.Edit transaction if needed
Admin Privileges
1. View all users using Admin panel
2. Create user and assign roles
3. Delete budges and transactions
-------------------------------------
Brief Summary on Security Improvements
1. Authentication
   -Passwords are hashed
   -Sessions are used to track login state securly
2. Authorisation
   -Roles are assigned between and administrator accordingly
   -Administrator can perform certain actions such as reset passwords, delete users       and view user logs
3. Database security
   - SQLAlchemy ORM used to avoid raw SQL Injections risks
4. Access Control on data
   -Budget and transaction are fetched using the logged in users

-----------------------------------------
Testing Process
1. Verified unauthorised useers cannot access administrators functionalities
2. Cannot make duplicate login credentials
3. CRUD functionalities work as normal
4. General functionalities for both user and administrator work as normal
------------------------------------------
Contribution and References
Flask: Python Web Framework
SQLAlchemy: ORM database layer
Werkzeug: Password hashing to




