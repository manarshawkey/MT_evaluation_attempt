from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pymerkle import InmemoryTree as MerkleTree
import hashlib
import timeit
import sys


# Function to perform AES-GCM encryption and return the authentication tag

def get_auth_tag_aes_gcm_encrypt(plaintext: str, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext.encode())
    return auth_tag  


def generate_leaf_nodes(num_leaves: int, key: bytes):
    leaves = []    
    for _ in range(num_leaves):
        msg = 'A'
        leaves.append(b'(msg)')
    
    return leaves


def get_merkle_tree_size(obj, seen=None):

    """ Recursively calculates the total size of a Merkle tree in memory. """
    if seen is None:
        seen = set()
    
    obj_id = id(obj)
    if obj_id in seen:
        return 0  # Avoid double counting
    seen.add(obj_id)
    
    size = sys.getsizeof(obj)
    
    if isinstance(obj, dict):
        size += sum(get_merkle_tree_size(k, seen) + get_merkle_tree_size(v, seen) for k, v in obj.items())
    elif isinstance(obj, (list, tuple, set)):
        size += sum(get_merkle_tree_size(i, seen) for i in obj)
    elif hasattr(obj, '__dict__'):  # Custom objects
        size += get_merkle_tree_size(obj.__dict__, seen)
    elif hasattr(obj, '__slots__'):  # Objects with __slots__
        size += sum(get_merkle_tree_size(getattr(obj, s), seen) for s in obj.__slots__ if hasattr(obj, s))
    
    return size

def build_merkle_tree(leaf_nodes): 

    tree = MerkleTree(algorithm='sha256')

    tag = get_auth_tag_aes_gcm_encrypt("A", get_random_bytes(32))

    for i in range(1, leaf_nodes):
        tree.append_entry(tag) 

    #print("Merkle Root:", tree.get_state())

    return tree


def sim_n_char_paragraph(n):

    bytes_received = 0

    for i in range(1, n):
        tree = build_merkle_tree(i)
        tree_size = get_merkle_tree_size(tree)
        bytes_received += tree_size
    
    print(f"received bytes for a {n} char paragraph: ", bytes_received/(1024 * 1024), " Megabytes.")

if __name__ == "__main__":

    n = 1950

    tree = build_merkle_tree(n)

    actual_tree_size = get_merkle_tree_size(tree)
    
    print("Total Merkle Tree Size in Memory:", actual_tree_size, "bytes")

    execution_time = timeit.timeit(lambda:sim_n_char_paragraph(n), number=10)/10 #average over 1s0 runs, output in seconds 

    execution_time *= 1000 #get output in milliseconds
    
    print(f"Simulation time for  Merkle trees recomputation for {n} nodes: {execution_time:.6f} milliseconds")





