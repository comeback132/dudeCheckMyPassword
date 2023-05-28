import sys
import requests
import hashlib


def request_api_data(query_char):
    # Pwned Password API/ + Hashed password
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    # Response 200 means no errors
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, ch')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    # count how many leaks
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwn_api_check(password):
    # check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # to make sure that the Pwned Password won`t save the whole password
    # split our hashed password in *****, *******************
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwn_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should change your password')
        else:
            print(f'{password} was NOT found. Carry on!')
        return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
