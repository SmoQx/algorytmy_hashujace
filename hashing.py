import hashlib
import timeit


def timing_decorator(func):
    def wrapper(*args, **kwargs):
        execution_time = timeit.timeit(lambda: func(*args, **kwargs), number=1)
        print(f"Function '{func.__name__} {args[1].name}' took {execution_time:.10f} seconds to execute")
        return func(*args, **kwargs)
    return wrapper


@timing_decorator
def hashing_func(text: str, hasher) -> str:
    hasher = hasher
    hasher.update(text.encode("utf-8"))
    text = hasher.hexdigest()

    return str(text)


if __name__ == "__main__":
    what_to_hash = "asdf"

    print(hashing_func(what_to_hash, hashlib.md5()), "\n")
    print(hashing_func(what_to_hash, hashlib.sha256()), "\n")
    print(hashing_func(what_to_hash, hashlib.sha512()), "\n")
