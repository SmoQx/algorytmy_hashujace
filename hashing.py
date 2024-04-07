import hashlib
import timeit
import bcrypt
import argon2


def timing_decorator(func):
    def wrapper(*args, **kwargs):
        execution_time = timeit.timeit(lambda: func(*args, **kwargs), number=1)
        print(f"Function '{func.__name__} {args[1] if type(args[1]) == str  else args[1].name}' took {execution_time:.10f} seconds to execute")
        return func(*args, **kwargs)
    return wrapper


@timing_decorator
def hashing_func(text: str, hasher) -> str:
    hasher = hasher
    hasher.update(text.encode("utf-8"))
    text = hasher.hexdigest()

    return str(text)


@timing_decorator
def argon2_hash(text: str, name: str) -> str:
    hasher = argon2.PasswordHasher()
    hashed = hasher.hash(text)
    return hashed


@timing_decorator
def bcrypt_hash(password: str, name: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()


if __name__ == "__main__":
    what_to_hash = "asdf"

    print(hashing_func(what_to_hash, hashlib.md5()), "\n")
    print(hashing_func(what_to_hash, hashlib.sha256()), "\n")
    print(hashing_func(what_to_hash, hashlib.sha3_256()), "\n")
    print(argon2_hash(what_to_hash, "argon2"), "\n")
    print(bcrypt_hash(what_to_hash, "bcrypt"), "\n")

