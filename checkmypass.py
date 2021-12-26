import requests
import hashlib
import sys


# Getting the actual count of breaches
def get_password_leak_count(hashes, tail):
    # Stripping the hashes and saving each hash into new variable hash
    hash = (line.split(':') for line in hashes.text.splitlines())
    # Extracting hash value and count for every hash
    for h, count in hash:
        # Checking if the tail of any hash matches our tail
        if h == tail:
            return count
    return 0


# Pre-processing the actual call
def pwned_password_check(password):
    # Generating the sha1 hash for the password argument
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # Extracting the first 5 letters of the hash and saving them to head and the rest to the tail
    head = sha1_password[:5]
    tail = sha1_password[5:]
    # Making a network call for fetching all the passwords that start with head
    response = request_api_data(head)
    # Making a call to get actual number of leaks
    return get_password_leak_count(response, tail)


# Requesting data for the head hash
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/'+query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"Error finding password, Response Code: {response.status_code}")

    return response


# Extracting and checking every password from the password list provided
def check_passwords(password_list):
    passwords = [password for password in password_list.split('\n')]
    for password in passwords:
        print('Checking '+password)
        count = pwned_password_check(password)
        if count:
            print(f'{password} appeared in {count} breaches')
        else:
            print(f'{password} was not included in any breach')

    return 'done'


# Extracting passwords list from the text file
def check_passwords_from_text_file():
    text_file = sys.argv[1]
    with open(text_file, 'r') as file:
        passwords = file.read()
        check_passwords(passwords)


if __name__ == "__main__":
    check_passwords_from_text_file()
