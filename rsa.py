import math, random

def random_prime(a,b):
    x = random.randint(a,b)
    while not prime_checker(x):
        x = random.randint(a,b)
    return x

def rsa_generate_pair(p:int ,q:int) -> tuple[int,int,int]:
    n = p*q
    phi = (p-1)*(q-1)
    e = random.randint(phi/2+1,phi-1)
    while(not co_prime_checker(e,phi)):
        e = random.randint(phi/2+1,phi-1)
    d = find_key_pair(phi,e)
    return e, d, n

def rsa_encypt(message: bytes,key: tuple[int,int]) -> bytes:
    ''' give in bytes for output bytes'''
    e, n= key
    b_size =  n
    m_int = int.from_bytes(message,"little")
    m_arr   = []
    
    while m_int >= 1:
        m_arr.append(m_int % b_size)
        m_int //= b_size
    enc_arr = []

    for i in m_arr[::-1]:
        enc_arr.append(bin_digest(i,e,n))
    enc_int = 0
    pow_b = 1
    for i in range(len(enc_arr)):
        enc_int+= pow_b * enc_arr[i]
        pow_b *= b_size
    return enc_int.to_bytes((enc_int.bit_length() + 7) // 8,'little')

def rsa_decypt(message: bytes,key: tuple[int,int]) -> bytes:
    ''' give in bytes for output bytes'''
    d, n = key
    b_size = n
    m_int = int.from_bytes(message,"little")
    m_arr   = []
   
    while m_int >= 1:
        m_arr.append(m_int % b_size)
        m_int //= b_size
        
    dec_arr = []
    for i in m_arr[::-1]:
        dec_arr.append(bin_digest(i,d,n))
    dec_int = 0
    pow_b = 1
    for i in range(len(dec_arr)):
        dec_int += pow_b * dec_arr[i]
        pow_b *= b_size
    return dec_int.to_bytes((dec_int.bit_length() + 7) // 8,'little')


def bin_digest(mes,exp,n):
        temp = mes % n
        fin = 1
        x = bin(exp)[:1:-1]
        for i in range(len(x)):
            if x[i] =='1':
                fin = (fin * temp) % n
            temp = (temp * temp) % n
        return fin % n

def co_prime_checker(a,b) -> bool:
    if math.gcd(a,b) == 1:
        return True
    return False

def prime_checker(n: int) -> bool:
    ''' based on rabin miller https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Deterministic_variants'''
    if(n % 2 == 0):
        return False
    n_1 = n - 1
    s = 0
    while n_1 %2 == 0:
        s += 1
        n_1 //= 2
    d = n_1
    for a in range(2,min(n-2,math.floor(2*math.log(n)**2))):
        x = bin_digest(a,d,n)
        for _ in range(s):
            y = x*x % n
            if y == 1 and x != 1 and x != n-1:
                return False
            x = y
        if y != 1:
            return False
        return True


def find_key_pair(phi:int, k1:int) -> int:
    '''extended euclid algorithm reference https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm'''
    o_r, r = phi, k1
    o_t, t = 0, 1
    while r != 0:
        quotient = o_r // r
        t1 = o_r - quotient * r
        t3 = o_t - quotient * t

        o_r, o_t = r, t
        r, t = t1, t3
    return (phi + o_t) % phi

if __name__ == "__main__":
    f = open("keys.txt","w")
    f.writelines(["Use rsa.py to genrate new\n"])
    e,d,n = rsa_generate_pair(random_prime(10**99,10**100),random_prime(10**99,10**100))
    f.writelines([f"CA: keu_enc:{e} key_dec:{d} n:{n}\n"])
    e,d,n = rsa_generate_pair(random_prime(10**99,10**100),random_prime(10**99,10**100))
    f.writelines([f"C1: keu_enc:{e} key_dec:{d} n:{n}\n"])
    e,d,n = rsa_generate_pair(random_prime(10**99,10**100),random_prime(10**99,10**100))
    f.writelines([f"C2: keu_enc:{e} key_dec:{d} n:{n}\n"])
    f.close()