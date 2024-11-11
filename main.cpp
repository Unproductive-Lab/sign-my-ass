#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/integer.hpp>
#include <boost/random.hpp>
#include <boost/container_hash/hash.hpp>
#include <random>
#include <stdexcept>

using namespace boost::multiprecision;
using namespace boost::random;

typedef int256_t big_int;

// Параметры эллиптической кривой P-192
const big_int p("97");
const big_int a("2");
const big_int b("3");
const big_int Gx("3");
const big_int Gy("6");
const big_int n("5");

boost::hash<std::string> string_hash;

// Вычисление обратного элемента по модулю
big_int mod_inverse(const big_int& k, const big_int& mod) {
    if (k < 1 || mod < 2)
        return -1;

    big_int u1 = mod;
    big_int u2 = 0;
    big_int v1 = k;
    big_int v2 = 1;

    while (v1 != 0) {
        big_int q = u1 / v1;
        big_int t1 = u1 - q * v1;
        big_int t2 = u2 - q * v2;
        u1 = v1;
        u2 = v2;
        v1 = t1;
        v2 = t2;
    }

    return u1 == 1 ? (u2 + mod) % mod : -1;
}

struct Point {
    big_int x;
    big_int y;
    bool is_infinity = false;

    Point() : x(0), y(0), is_infinity(true) {}
    Point(big_int _x, big_int _y) : x(_x), y(_y), is_infinity(false) {}

    Point operator+(const Point& other) const {
        if (is_infinity) return other;
        if (other.is_infinity) return *this;
        if (x == other.x && y != other.y) return Point();
        //big_int inv_k;

        big_int m;
        if (x == other.x) {
            /*while (1)
            {
                inv_k = mod_inverse(2 * y, p);
                if (inv_k == -1) continue;
                else break;
            }*/
            m = (3 * x * x + a) * mod_inverse(2 * y, p) % p;
        }
        else {
            /*while (1)
            {
                inv_k = mod_inverse(other.x - x, p);
                if (inv_k == -1) continue;
                else break;
            }*/
            m = (other.y - y) * mod_inverse(other.x - x, p) % p;
        }

        big_int x_r = (m * m - x - other.x) % p;
        big_int y_r = (m * (x - x_r) - y) % p;
        return Point(x_r < 0 ? x_r + p : x_r, y_r < 0 ? y_r + p : y_r);
    }

    Point operator*(const big_int& scalar) const {
        Point result;
        Point base = *this;
        big_int k = scalar;

        while (k != 0) {
            if (k % 2 != 0) {
                result = result + base;
            }
            base = base + base;
            k /= 2;
        }

        return result;
    }
};

// Генерация случайного числа в диапазоне [1, max - 1]
big_int random_big_int(const big_int& max) {
    static boost::random::mt19937 gen(static_cast<unsigned int>(std::time(0)));
    big_int result = 0;
    big_int base = 1;

    while (result < max) {
        boost::random::uniform_int_distribution<uint64_t> dist(0, std::numeric_limits<uint64_t>::max());
        result += base * dist(gen);
        base <<= 64;
    }

    return result % max;
}

// Генерация ключей
void generate_key_pair(big_int& private_key, Point& public_key) {
    private_key = random_big_int(n);
    public_key = Point(Gx, Gy) * private_key;
}

// Подпись сообщения
void sign_message(const big_int& private_key, const std::string& message, big_int& r, big_int& s) {
    big_int z = string_hash(message);
    big_int k;  // Переместили объявление переменной k вне цикла

    while (true) {
        k = random_big_int(n);  // Генерируем случайное значение k
        Point R = Point(Gx, Gy) * k;
        r = R.x % n;
        //big_int inv_k;

        if (r == 0) continue;

        /*while (1)
         {
            inv_k = mod_inverse(k, n);
            if (inv_k == -1) continue;
            else break;
        }*/
        s = (mod_inverse(k, n) * (z + r * private_key)) % n;
        if (s != 0) break;
    }

    // Отладочный вывод
    std::cout << "Debug Info - Message Hash: " << z << std::endl;
    std::cout << "Debug Info - Random k: " << k << std::endl;
    std::cout << "Debug Info - r: " << r << ", s: " << s << std::endl;
}

// Проверка подписи
bool verify_signature(const Point& public_key, const std::string& message, const big_int& r, const big_int& s) {
    if (r <= 0 || r >= n || s <= 0 || s >= n) return false;
    //big_int inv_k;

    big_int z = string_hash(message);
    /*while (1)
    {
        inv_k = mod_inverse(s, n);
        if (inv_k == -1) continue;
        else break;
    }*/
    big_int w = mod_inverse(s, n);
    big_int u1 = (z * w) % n;
    big_int u2 = (r * w) % n;

    // Отладочный вывод
    std::cout << "Debug Info - Verification Hash: " << z << std::endl;
    std::cout << "Debug Info - w (s^-1 mod n): " << w << std::endl;
    std::cout << "Debug Info - u1 (z * w mod n): " << u1 << std::endl;
    std::cout << "Debug Info - u2 (r * w mod n): " << u2 << std::endl;

    // Вычисление точки R
    Point R = Point(Gx, Gy) * u1 + public_key * u2;

    // Отладочный вывод для значения R
    std::cout << "Debug Info - Verification R.x: " << R.x << std::endl;
    std::cout << "Debug Info - Verification R.y: " << R.y << std::endl;
    std::cout << "Debug Info - Provided r: " << r << std::endl;

    // Сравнение R.x % n с r и отладка результата
    big_int R_x_mod_n = R.x % n;
    std::cout << "Debug Info - R.x % n: " << R_x_mod_n << std::endl;

    bool is_valid = (R_x_mod_n == r);

    // Дополнительный вывод для конечного результата
    std::cout << "Signature is " << (is_valid ? "valid" : "invalid") << std::endl;

    return is_valid;
}

int main() {
    big_int private_key;
    Point public_key;

    // Генерация пары ключей
    generate_key_pair(private_key, public_key);
    std::cout << "Private key: " << private_key << std::endl;
    std::cout << "Public key: (" << public_key.x << ", " << public_key.y << ")" << std::endl;

    // Подпись сообщения
    std::string message = "Hello, world!";
    big_int r, s;
    sign_message(private_key, message, r, s);
    std::cout << "Signature (r, s): (" << r << ", " << s << ")" << std::endl;

    // Проверка подписи
    bool valid = verify_signature(public_key, message, r, s);
    std::cout << "Signature is " << (valid ? "valid" : "invalid") << std::endl;

    return 0;
}
