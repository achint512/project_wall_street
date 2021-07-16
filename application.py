import os
import re

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    stocks = db.execute("SELECT name, symbol, SUM(quantity) FROM share_transactions WHERE user_id = :id GROUP BY symbol HAVING SUM(quantity) > 0",
                        id=session["user_id"])
    cash = float(db.execute("SELECT cash FROM users WHERE id = :id",
                            id=session["user_id"])[0]['cash'])
    grand_total = cash

    for i in range(len(stocks)):
        quote = lookup(stocks[i]['symbol'])
        stocks[i]['current_price'] = usd(quote['price'])
        total_value = quote['price'] * stocks[i]['SUM(quantity)']
        stocks[i]['total_value'] = usd(total_value)
        grand_total = grand_total + total_value

    return render_template("index.html", stocks = stocks, cash = usd(cash), grand_total = usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy_shares.html")
    else:
        number_of_shares = request.form.get("shares")

        if not request.form.get("symbol"):
            return apology("must provide valid share symbol", 406)
        elif not number_of_shares or int(number_of_shares) < 1:
            return apology("must provide valid number of shares", 406)

        quotes = lookup(request.form.get("symbol").upper())

        if quotes == None:
            return apology("Invalid shares details", 406)

        cash_with_user = float(db.execute("SELECT cash FROM users WHERE id = :id",
                                    id=session["user_id"])[0]['cash'])

        required_cash = float(quotes['price']) * int(number_of_shares)

        if cash_with_user < required_cash:
            return apology("Insufficient funds!", 406)

        db.execute("INSERT INTO share_transactions (user_id, name, price, symbol, quantity, transaction_type) VALUES (:user_id, :name, :price, :symbol, :quantity, 0)",
                   user_id=session["user_id"], name=quotes['name'], price=quotes['price'], symbol=quotes['symbol'], quantity=number_of_shares)
        db.execute("UPDATE users SET cash = :cash WHERE id = :id;", cash=(cash_with_user - required_cash), id=session["user_id"])

        return render_template("buy_shares.html", message="Succefully purchased!")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    stocks = db.execute("SELECT * FROM share_transactions WHERE user_id = :id", id=session["user_id"])
    for i in range(len(stocks)):
        stocks[i]['price'] = usd(stocks[i]['price'])

    return render_template("history.html", stocks=stocks)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "GET":
        return render_template("quote.html", quotes="")
    else:
        quotes = lookup(request.form.get("symbol").upper())
        return render_template("quote.html", quotes=quotes)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "GET":
        return render_template("register.html")
    else:
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted and matches with confirmated password
        elif not request.form.get("password") or request.form.get("password") != request.form.get("confirmation"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username does not exist
        if len(rows) != 0:
            return apology("Username already exists", 403)

        password_hash = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                   username=request.form.get("username"), hash=password_hash)

        return redirect("/")


@app.route("/update_password", methods=["GET", "POST"])
@login_required
def update_password():
    """Update user password"""

    if request.method == "GET":
        return render_template("update_password.html")
    else:
        password = request.form.get("password")

        # Ensure password was submitted and matches with confirmated password
        if not password or password != request.form.get("confirmation"):
            return render_template("update_password.html", success = False, message = "Passwords dont match")

        reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"

        # compiling regex
        pattern = re.compile(reg)

        # searching regex
        match = re.search(pattern, password)

        if not match:
            return render_template("update_password.html", success = False, message = "Passwords must fulfill the required conditions")

        password_hash = generate_password_hash(password)
        db.execute("UPDATE users SET hash = :hash where id = :id",
                   hash=password_hash, id=session["user_id"])

        return render_template("update_password.html", success = True)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "GET":
        stock_symbols = db.execute("SELECT name, symbol FROM share_transactions WHERE user_id = :id GROUP BY symbol HAVING SUM(quantity) > 0",
                                   id=session["user_id"])
        if not stock_symbols:
            return render_template("sell.html", symbols = stock_symbols, message = "Purchase stocks to sell!", success = False)
        else:
            return render_template("sell.html", symbols = stock_symbols, message = "", success = True)
    else:
        number_of_shares = request.form.get("shares")

        if not request.form.get("symbol"):
            return apology("must provide valid share symbol", 406)
        elif not number_of_shares or int(number_of_shares) < 1:
            return apology("must provide valid number of shares", 406)

        symbol = request.form.get("symbol").upper()
        quotes = lookup(symbol)

        if quotes == None:
            return apology("Invalid shares details", 406)

        number_of_shares = int(number_of_shares)
        shares_with_user = db.execute("SELECT COUNT(quantity) FROM share_transactions WHERE user_id = :id and symbol = :symbol GROUP BY symbol",
                                      id=session["user_id"], symbol=symbol)[0]['COUNT(quantity)']

        if (shares_with_user - number_of_shares) < 0:
            return apology("Insufficient shares!", 406)

        cash_with_user = float(db.execute("SELECT cash FROM users WHERE id = :id",
                                          id=session["user_id"])[0]['cash'])
        cash_earned = float(quotes['price']) * number_of_shares

        db.execute("INSERT INTO share_transactions (user_id, name, price, symbol, quantity, transaction_type) VALUES (:user_id, :name, :price, :symbol, :quantity, 1)",
                   user_id=session["user_id"], name=quotes['name'], price=quotes['price'], symbol=quotes['symbol'], quantity=-number_of_shares)
        db.execute("UPDATE users SET cash = :cash WHERE id = :id;", cash=(cash_with_user + cash_earned), id=session["user_id"])

        return render_template("buy_shares.html", message = "Succefully sold!", success = True)


@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    """Add cash to user account"""

    if request.method == "GET":
        return render_template("add_cash.html")
    else:
        amount = request.form.get("amount")

        if not amount or int(amount) < 1:
            return render_template("add_cash.html", success = False)

        cash_with_user = float(db.execute("SELECT cash FROM users WHERE id = :id",
                                    id=session["user_id"])[0]['cash'])

        db.execute("UPDATE users SET cash = :cash WHERE id = :id;", cash=(cash_with_user + int(amount)), id=session["user_id"])

        return render_template("add_cash.html", success = True)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
