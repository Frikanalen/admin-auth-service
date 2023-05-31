from getpass import getpass
from werkzeug.security import generate_password_hash

def main():
    username = input("Enter username: ")
    password = getpass("Enter password: ")
    password_hash = generate_password_hash(password)
    print(f"{username}:{password_hash}")

if __name__ == "__main__":
    main()
