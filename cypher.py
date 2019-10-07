OUTPUT_FILE = "encrypted.txt"
INPUT_FILE = "plain_text.txt"
BASE_SIZE = 128
CHUNK_DIV = 15410


def break_apart(num,c=None):   # break a number into a list of it's digits
    if c is None:
        c = CHUNK_DIV
    gooshes = []
    while num >0:
        gooshes.append(num%c)
        num = num // c
    return gooshes


def join_together(gooshes, c=None):
    if c is None:
        c = CHUNK_DIV
    s = ''
    n = 0
    mag = 1
    max_digits = len(str(max(gooshes)))
    for a in gooshes:
        n += a*mag

        mag *= c

    return n


def random_from2_between(a,b, border):
    return ((a+b)**2)%border


def shuffle_using_key(l, key, duration=1):
    # shuffle the list l using the key
    for i in range(duration *len(l)):
        # for each item in the list, find a random place in the list, and push it there
        tmp = l[i]
        new_loc = random_from2_between(key, i, len(l))
        l[i] = l[new_loc]
        l[new_loc] = tmp
    return l


def int2string(num):
    s = ''
    while num >0:
        s += chr(num%BASE_SIZE)
        num = num // BASE_SIZE

    return s

def pad_left(w, l, c):
    # pad the string w to the length of l with the character c, to the left
    s = w   # start with the string w
    while len(s) < l:   # while it's too short
        s = c + s   # add to it's left another padding character
    return s    # return the padded string


def intlist2string(l, maximum):
    # create a string from a list of ints, and the maximum size an int can have
    max_len = len(str(len(str(maximum))))   # the amount of digits it takes to describe the amount of digits in the largest number possible
    n = '1' # n is the string form of the number to stringify
    for item in l:
        item_str = str(item)    # the number (in string form)
        item_l = pad_left(str(len(item_str)),max_len,'0') # the length number(in string form)
        n += item_l+item_str

    s = int2string(int(n))  # stringify the number
    return s


def break_joint(n, maximum):
    max_len = len(str(len(str(maximum))))   # the number of digits that are used to describe the amount of digits in one chunk

    s = str(string2int(n))  # get the number(in string format)
    #   print("s: " + s)
    l = []
    #   print(max_len)
    s = s[1:]
    while len(s) > 0:
        nxt_l = int(s[:max_len]) # the length of the next chunk
        #   print("len(s): " + str(len(s)) + ", nxt_l: " + str(nxt_l))
        num = int(s[max_len:nxt_l+max_len]) # use the achieved next digit length to pull the next chunk
        l.append(num)
        s = s[nxt_l+max_len:]   # cut the used part until now
    return l


def string2int(s):
    num = 0
    mag = 1
    for c in s:
        num += ord(c)*mag
        mag*=BASE_SIZE
    return num


def get_string_from_file(name=INPUT_FILE):
    with open(name, 'r', newline='') as f:
        s = f.read()
        f.close()
    return s


def put_string_to_file(data, name=OUTPUT_FILE):
    with open(name, 'w', newline='') as f:
        f.write(data)
        f.close()


def get_max(ch, key, it):
    # calculate the maximum number possible for encryption using a chunk_div_size, the key, and number of iterations
    num = ch
    for i in range(it):
        num = max(num*key, ((key*(num+i))+i)^key)
        #   print("key: " + str(key) + ", c: " + str(ch) + ", i: " + str(i) + "/" + str(it-1) + ", num: " + str(num))
    return num



def encrypt(p, k, iterations=1, ch=CHUNK_DIV, b=BASE_SIZE):
    """

    :param p: string plaintext
    :param k: int secret key
    :param iterations: int iterations
    :param c: int chunk_division_size
    :param b: int size of base for string-int transform(128 for normal ascii, as default)
    :return: encrypted string
    """
    plain = string2int(p)
    chunks = break_apart(plain, ch)

    shuffled_loc = list(range(len(chunks))) # initialize shuffle list: each cell in this array contains the index of the actuall index in the actual array

    for i in range(iterations): # for each iteration of encryption
        result = [-1] * len(chunks) # initialize results list
        shuffled_loc = shuffle_using_key(shuffled_loc[:], k)   # shuffle the shuffle list
        for c in range(len(chunks)):    # for each chunk
            my_loc = shuffled_loc[c]    # find actual location using the shuffle list
            if c != (k + i) % len(chunks):  # if not weak link
                nxt = shuffled_loc[(c + 1) % len(chunks)]  # find actual location of the referring chunk
                val = k * (chunks[my_loc] ^ chunks[nxt])  # calculate the next value of this chunk
            else:   # if is weak link
                val = ((k * chunks[my_loc]) + ((k + 1) * i)) ^ k    # calculate the next value of this chunk

            result[my_loc] = val
        chunks = result

    encrypted = intlist2string(chunks, get_max(ch, k, iterations))
    return encrypted


def decrypt(enc, k, its=1, ch=CHUNK_DIV, b=BASE_SIZE):
    result = break_joint(enc, get_max(ch, k, its))

    shuffled_loc = list(range(len(result)))
    shuffles = []
    for i in range(its):
        shuffled_loc = shuffle_using_key(shuffled_loc[:], k)
        shuffles.append(shuffled_loc)

    for i in range(its - 1, -1, -1):
        shuffled_loc = shuffles[i]
        #   print(shuffles[i])
        chuks = [-1] * len(result)  # blank list of empty chunks

        start_c = (k + i) % len(chuks)
        chuks[shuffled_loc[start_c]] = ((result[shuffled_loc[start_c]] ^ k) - ((k + 1) * i)) // k  # solve the weak link

        c = (start_c - 1) % len(chuks)  # go back
        prev = start_c
        while c != start_c:
            chuks[shuffled_loc[c]] = ((result[shuffled_loc[c]]//k) ^ chuks[shuffled_loc[prev]])  # use the key and the last discovered value to discover this value
            prev = c

            c = (c - 1) % len(chuks)
            #   c = shuffled_loc.index(c)

        result = chuks

    return int2string(join_together(result))


my_string = get_string_from_file(INPUT_FILE)

my_key = 3141895618
iterations = 10

E = encrypt(my_string,my_key,iterations)    # encrypt
print("FINISHED ENCRYPTING")

put_string_to_file(str(E))  #   save encrypted file


encr = get_string_from_file(OUTPUT_FILE)    # open encrypted file and read it


D = decrypt(encr, my_key, iterations) # decrypt the encrypted data
print("FINISHED DECRYPTING")
print(D)
