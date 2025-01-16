
import random
import string

def random_string(length=10):
    chars = string.ascii_lowercase + string.digits + '_'
    return ''.join(random.choices(chars, k=length))

def random_byte_array():
    length = random.randint(1, 3)
    return [str(random.randint(0, 255)) for _ in range(length)]

def random_block():
    x = ' '.join(random_byte_array())
    y = random.randint(0, 1499)
    return f" ([{x}]" + (f", {y}" if y is not None else "") + ")"

def generate_file(filename, num_lines):
    event_types = [
        "Alert",
        "Notify",
        "TestEvent",
        "TestEvent1",
        "TestEvent2"
    ]

    with open(filename, 'w') as file:
        for _ in range(num_lines):
            event = random.choice(event_types)
            rule = random_string(random.randint(5, 15))
            num_blocks = random.randint(0, 3)
            blocks = ";".join(random_block() for _ in range(num_blocks))
            file.write(f"{event}; {rule};{blocks}\n")

generate_file('build/a_lot_of.rule', 1000)
