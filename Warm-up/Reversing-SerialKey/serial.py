import random
import string

def generate_block():
    """Generate a random four-character block."""
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(4))

def generate_key(existing_keys):
    """Generate a unique key based on given constraints."""
    key_blocks = set()
    
    # Generate five unique blocks for the key
    while len(key_blocks) < 5:
        block = generate_block()
        if block not in key_blocks:
            key_blocks.add(block)
    
    # Formulate the key
    key = '-'.join(key_blocks)
    
    # Ensure the key hasn't been generated before
    while key in existing_keys:
        key = generate_key(existing_keys)
    
    return key

# Generate 100 unique keys
keys = []
for _ in range(100):
    key = generate_key(keys)
    keys.append(key)

formatted_list = "\n".join(keys)
print(formatted_list)
