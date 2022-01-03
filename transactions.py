import numpy as np

def generate_transactions(M=1000, n=10, m=100, balances=None):
    # M is the money supply (total number of digital coins)
    # n is the number of participants
    # m is the number of transactions to generate
    # balances is the starting balances (None means simulation uninitialized)

    if balances is None:
        balances = [M // n] * n
        balances[-1] = M - sum(balances[:-1])
    assert sum(balances) == M

    transactions = []
    for i in range(m):
        balances_norm = np.array(balances) / sum(balances)
        sender_id = np.random.choice(n, p=balances_norm)
        recipient_id = (sender_id + np.random.choice(n)) % n
        amount = int(np.floor(np.random.uniform() * balances[sender_id]))
        balances[sender_id] -= amount
        balances[recipient_id] += amount
        transactions.append((sender_id, recipient_id, amount))

    return transactions, balances
