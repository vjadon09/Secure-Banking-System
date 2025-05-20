from tinydb import TinyDB, Query
from datetime import datetime

DB_PATH = 'database.json'
db = TinyDB(DB_PATH)

def add_user(username, password):
    try:
        query = Query()
        check = db.contains(query.username == username)
        if check:
            raise Exception("User already exists")
        else:
            db.insert({
                "username": username,
                "pass": password,
                "balance": 0})
            return "success"
    except Exception as e:
        raise Exception(e)

def auth(username, password):
    try:
        User = Query()
        account = db.search(User.username == username)       
        if (len(account) == 0):
            raise Exception("No account found lil bro")

        # print(account[0]['pass'])
        if str(account[0]["pass"]) == str(password):
            return account[0]["balance"]
            # return "success"
        else:
            raise Exception("Wrong password detected")

    except Exception as e:
        raise Exception(e)


def deposit(username: str, amount: int):
    try:
        User = Query()
        account = db.search(User.username == username)[0]
        if len(account) == 0:
            raise Exception("No account found lil bro")

        print("Old account:", account)
        newBalance = account["balance"] + amount
        db.update({"balance": newBalance}, User.username == username)

        updated_account = db.search(User.username == username)[0]
        print("Updated account:", updated_account)
        return newBalance

    except Exception as e:
        raise Exception(e)


def withdraw(username: str, amount: int):
    try:
        User = Query()
        account = db.search(User.username == username)[0]
        if len(account) == 0:
            raise Exception("No account found lil bro")

        print("Old account:", account)
        newBalance = account["balance"] - amount
        db.update({"balance": newBalance}, User.username == username)

        updated_account = db.search(User.username == username)[0]
        print("Updated account:", updated_account)
        return newBalance

    except Exception as e:
        raise Exception(e)


def getBalance(username: str):
    try:
        User = Query()
        account = db.search(User.username == username)[0]
        if len(account) == 0:
            raise Exception("No account found lil bro")

        return account["balance"]

    except Exception as e:
        raise Exception(e)


def getIDAndTime(username: str):
    try:
        User = Query()
        search = db.search(User.username == username)

        if len(search) == 0:
            raise Exception("No account found lil bro")

        account = search[0]

        now = datetime.now()
        time = now.strftime("%d-%m-%Y %H:%M:%S")

        return account.doc_id, time 

    except Exception as e:
        raise Exception(e)
