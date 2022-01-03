from utils import H

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
