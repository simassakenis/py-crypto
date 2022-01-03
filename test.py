from utils import H, gcd, mod_exp, G, S, V
from transactions import generate_transactions

if __name__ == '__main__':
    # from http://karpathy.github.io/2021/06/21/blockchain/
    assert (H('') ==
            0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)

    # from https://en.wikipedia.org/wiki/SHA-2
    msgbytes = b'here is a random bytes message, cool right?'
    msg = bin(int.from_bytes(msgbytes, byteorder='big'))[2:]
    while len(msg) % 8 != 0:
        msg = '0' + msg
    assert (H(msg) ==
            0x69b9779edaa573a509999cbae415d3408c30544bad09727a1d64eff353c95b89)

    assert gcd(1071, 462) == 21

    assert mod_exp(4, 13, 497) == 445

    msgbytes = b'labas!'
    msg = bin(int.from_bytes(msgbytes, byteorder='big'))[2:]
    while len(msg) % 8 != 0:
        msg = '0' + msg
    pk, sk = G()
    sigma = S(sk, msg)
    assert V(pk, msg, sigma)

    txs, bal = generate_transactions(M=1000, n=10, m=10)
    print(f'transactions: {txs}')
    print(f'final balance {bal}')
    txs, bal = generate_transactions(M=1000, n=10, m=10, balances=bal)
    print(f'new transactions: {txs}')
    print(f'new final balance {bal}')
