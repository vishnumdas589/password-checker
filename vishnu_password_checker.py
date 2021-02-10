import sys
import requests
import hashlib


def api_req_senter(hashed_code):
    url = 'https://api.pwnedpasswords.com/range/' + hashed_code
    req = requests.get(url)
    if req.status_code != 200:
        raise RuntimeError(f'fetching error: {req.status_code}')
    return (req)


def request_count_checker(hashes, hash_checker):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_checker:
            return count
    return 0


def password_checker(xyz):
    hashing = hashlib.sha1(xyz.encode('utf8')).hexdigest().upper()
    first_5, tail = hashing[:5], hashing[5:]
    request = api_req_senter(first_5)
    list = request_count_checker(request, tail)
    return list


def main_password_checker():
    passwords = sys.argv[1:]
    for password in passwords:
        count = password_checker(password)
        password_checker(password)
        print(f'{password} had been hacked : {count}')

    print('all done!!')
    return 'all over...'


if __name__ == '__main__':
    sys.exit( main_password_checker())
