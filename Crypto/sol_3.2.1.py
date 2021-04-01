import pymd5
import sys
import urllib.parse

_, query_file, command3_file, output_file = sys.argv

test_password = '12345678'
assert(len(test_password) == 8)
test = False
def dprint(x):
    if test:print(x)
if test:
    dprint("TESTING!!!!!!!!!!!!!!!")
    dprint(f'{test_password=}')

with open(query_file) as query_file, open(command3_file) as command3_file, open(output_file, 'w') as output_file:
    query_file = query_file.read().strip()
    command3_file = command3_file.read().strip()
    dprint(f'{query_file=}')
    dprint(f'{command3_file=}')

    old_hash = query_file.split('&')[0].split('=')[1]
    old_2nd_half = query_file[len(query_file.split('&')[0])+1:]
    old_count = (8+len(old_2nd_half))*8
    old_padding = pymd5.padding(old_count)
    if test:
        md5test = pymd5.md5()
        md5test.update(test_password+old_2nd_half)
        old_hash = md5test.hexdigest()
        true_padding = pymd5.padding(len(test_password+old_2nd_half)*8)
        dprint(f'{true_padding=}')
    dprint(f'{old_hash=}')
    dprint(f'{old_2nd_half=}')
    dprint(f'{old_count=}')
    dprint(f'{old_padding=}')

    md5 = pymd5.md5(state=old_hash, count=old_count+len(old_padding)*8)
    md5.update(command3_file)
    new_hash = md5.hexdigest()
    dprint(f'{new_hash=}')

    padding_encoded = urllib.parse.quote_from_bytes(old_padding)
    new_2nd_half = old_2nd_half+padding_encoded+command3_file
    dprint(f'{new_2nd_half=}')
    if test:
        md5test = pymd5.md5()
        md5test.update(test_password+old_2nd_half)
        dprint(md5test.hexdigest())
        md5test.update(old_padding)
        dprint(md5test.hexdigest())
        md5test.update(command3_file)
        true_hash = md5test.hexdigest()
        dprint(f'{true_hash=}')

    final_url = f'token={new_hash}&{new_2nd_half}'
    print(f'{final_url=}')

    output_file.write(final_url)
