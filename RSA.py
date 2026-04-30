import random
from typing import Tuple, List


def gcd(a: int, b: int) -> int:
    """Вычисление наибольшего общего делителя по алгоритму Евклида."""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Расширенный алгоритм Евклида.
    Для заданных целых a и b находит тройку (d, x, y),
    удовлетворяющую соотношению a*x + b*y = d, где d = gcd(a, b).
    """
    if b == 0:
        return a, 1, 0

    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y

    return old_r, old_x, old_y


def mod_inverse(a: int, n: int) -> int:
    """
    Нахождение мультипликативного обратного элемента a^(-1) по модулю n.
    Если gcd(a, n) != 1, обратный элемент не существует и возбуждается исключение.
    """
    d, x, _ = extended_gcd(a, n)
    if d != 1:
        raise ValueError(f"Обратный элемент не существует: gcd({a}, {n}) = {d}")
    return x % n


def mod_pow(base: int, exp: int, mod: int) -> int:
    """
    Быстрое модульное возведение в степень методом двоичного разложения показателя.
    Вычисляет значение base^exp mod mod за O(log(exp)) умножений.
    """
    result = 1
    base = base % mod

    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod

    return result


def miller_rabin_test(n: int, rounds: int = 20) -> bool:
    """
    Вероятностный тест простоты Миллера — Рабина.

    Число n-1 представляется в виде 2^s * d, где d — нечётное.
    Для каждого раунда выбирается случайное основание a и проверяются
    условия, необходимые для простоты n.

    При количестве раундов k вероятность ложноположительного результата
    не превышает 4^(-k). При k = 20 это составляет порядка 10^(-12).
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Представление n - 1 = 2^s * d, d — нечётное
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        composite = True
        for _ in range(s - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                composite = False
                break

        if composite:
            return False

    return True


def generate_prime(bits: int) -> int:
    """
    Генерация вероятно простого числа заданной битовой длины.
    Старший бит устанавливается в 1 для гарантии требуемой разрядности,
    младший бит — в 1 для обеспечения нечётности кандидата.
    """
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1

        if miller_rabin_test(candidate):
            return candidate


def generate_rsa_keys(bits: int = 512) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Генерация ключевой пары RSA.

    Параметр bits задаёт общую длину модуля n в битах.
    Простые числа p и q генерируются длиной bits // 2 каждое.

    Открытая экспонента e по умолчанию выбирается равной 65537
    (четвёртое простое число Ферма). Если gcd(e, φ(n)) != 1,
    производится поиск ближайшего подходящего нечётного значения.

    Возвращает кортеж ((e, n), (d, n)), где (e, n) — открытый ключ,
    (d, n) — закрытый ключ.
    """
    half = bits // 2

    p = generate_prime(half)
    q = generate_prime(half)
    while q == p:
        q = generate_prime(half)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = mod_inverse(e, phi)

    return (e, n), (d, n)


def split_into_blocks(data: bytes, block_size: int) -> List[bytes]:
    """Разбиение байтовой последовательности на блоки фиксированного размера."""
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def rsa_encrypt(plaintext: str, public_key: Tuple[int, int]) -> List[int]:
    """
    Шифрование текстового сообщения с использованием открытого ключа RSA.

    Исходный текст кодируется в UTF-8 и разбивается на блоки, размер
    которых выбирается так, чтобы числовое значение блока не превышало
    модуль n. Каждый блок преобразуется в целое число m и шифруется
    по формуле c = m^e mod n.
    """
    e, n = public_key
    raw_bytes = plaintext.encode('utf-8')

    max_block = (n.bit_length() - 1) // 8
    blocks = split_into_blocks(raw_bytes, max_block)

    encrypted = []
    for block in blocks:
        m = int.from_bytes(block, byteorder='big')
        c = mod_pow(m, e, n)
        encrypted.append(c)

    return encrypted


def rsa_decrypt(cipher_blocks: List[int], private_key: Tuple[int, int]) -> str:
    """
    Расшифрование списка числовых блоков с использованием закрытого ключа RSA.

    Для каждого блока шифртекста c вычисляется m = c^d mod n.
    Полученные числа преобразуются обратно в байтовые последовательности,
    которые объединяются и декодируются из UTF-8.
    """
    d, n = private_key
    recovered = bytearray()

    for c in cipher_blocks:
        m = mod_pow(c, d, n)
        byte_len = (m.bit_length() + 7) // 8 or 1
        recovered.extend(m.to_bytes(byte_len, byteorder='big'))

    return recovered.decode('utf-8')


def main():
    """Демонстрация работы алгоритма RSA: генерация ключей, шифрование и расшифрование."""

    print("Генерация ключевой пары RSA (512 бит)...\n")
    pub, priv = generate_rsa_keys(bits=512)

    print(f"Открытый ключ:  e = {pub[0]}")
    print(f"                n = {pub[1]}")
    print(f"Закрытый ключ:  d = {priv[0]}\n")

    message = (
        "Криптография с открытым ключом позволяет безопасно передавать информацию "
        "по незащищённым каналам связи. В данной работе реализован алгоритм RSA, "
        "использующий большие числа, генерацию ключей, шифрование текста по блокам "
        "и последующее восстановление исходного сообщения."
    )

    print("Исходное сообщение:")
    print(message)

    encrypted = rsa_encrypt(message, pub)
    print(f"\nШифртекст ({len(encrypted)} блоков):")
    for i, block in enumerate(encrypted):
        print(f"  Блок {i}: {block}")

    decrypted = rsa_decrypt(encrypted, priv)
    print("\nРезультат расшифрования:")
    print(decrypted)

    if message == decrypted:
        print("\nПроверка пройдена: расшифрованный текст совпадает с исходным.")
    else:
        print("\nОшибка: расшифрованный текст отличается от исходного.")


if __name__ == "__main__":
    main()
