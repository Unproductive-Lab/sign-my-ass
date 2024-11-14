#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/integer.hpp>
#include <boost/random.hpp>
#include <boost/container_hash/hash.hpp>
#include <random>
#include <stdexcept>

using namespace boost::multiprecision;
using namespace boost::random;

//typedef int256_t cpp_int;

// Параметры эллиптической кривой P-192
const cpp_int p("6277101735386680763835789423207666416083908700390324961279");
const cpp_int a("-3");
const cpp_int b("486662");
const cpp_int Gx("6020462823637492042502212081282494647802495754375245628291");
const cpp_int Gy("1741981231981953455700642022569653433483344651014216122020");
const cpp_int n("6277101735386680763835789423176059013767194773182842284081");

boost::hash<std::string> string_hash;

// Вычисление обратного элемента по модулю
/*cpp_int mod_inverse(const cpp_int& k, const cpp_int& mod) {
    if (k < 1 || mod < 2)
        return -1;

    cpp_int u1 = mod;
    cpp_int u2 = 0;
    cpp_int v1 = k;
    cpp_int v2 = 1;

    while (v1 != 0) {
        cpp_int q = u1 / v1;
        cpp_int t1 = u1 - q * v1;
        cpp_int t2 = u2 - q * v2;
        u1 = v1;
        u2 = v2;
        v1 = t1;
        v2 = t2;
    }

    return u1 == 1 ? (u2 + mod) % mod : -cpp_int(1);
}*/

cpp_int gcdExtended(cpp_int a, cpp_int b, cpp_int& x, cpp_int& y) {
    if (a == 0) {
        x = 0;
        y = 1;
        return b;
    }

    cpp_int x1, y1;
    cpp_int gcd = gcdExtended(b % a, a, x1, y1);

    x = y1 - (b / a) * x1;
    y = x1;

    return gcd;
}

// Функция поиска обратного элемента по модулю
cpp_int mod_inverse(cpp_int a, cpp_int m) {
    cpp_int x, y;
    cpp_int g = gcdExtended(a, m, x, y);

    if (g != 1) {
        return -1;
    }
    else {
        return x % m;
    }
}

struct Point {
    cpp_int x;
    cpp_int y;
    bool is_infinity = false;

    Point() : x(0), y(0), is_infinity(true) {}
    Point(cpp_int _x, cpp_int _y) : x(_x), y(_y), is_infinity(false) {}

    Point operator+(const Point& other) const {
        if (is_infinity) return other;
        if (other.is_infinity) return *this;
        if (x == other.x && y != other.y) return Point();
        //cpp_int inv_k;

        cpp_int m;
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

        cpp_int x_r = (m * m - x - other.x) % p;
        cpp_int y_r = (m * (x - x_r) - y) % p;
        return Point(x_r < 0 ? x_r + p : x_r, y_r < 0 ? y_r + p : y_r);
    }

    Point operator*(const cpp_int& scalar) const {
        Point result;
        Point base = *this;
        cpp_int k = scalar;

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
cpp_int random_cpp_int(const cpp_int& max) {
    std::random_device seed;
    boost::random::mt19937 gen(seed());
    boost::random::uniform_int_distribution<cpp_int> dist(1, max - 1);

    return dist(gen);
}

// Генерация ключей
void generate_key_pair(cpp_int& private_key, Point& public_key) {
    private_key = 11;//random_cpp_int(n);
    public_key = Point(Gx, Gy) * private_key;
}

// Подпись сообщения
void sign_message(const cpp_int& private_key, const std::string& message, cpp_int& r, cpp_int& s) {
    cpp_int z = string_hash(message);
    cpp_int k;  // Переместили объявление переменной k вне цикла

    while (true) {
        k = 7;// random_cpp_int(n);  // Генерируем случайное значение k
        Point R = Point(Gx, Gy) * k;
        r = R.x % n;
        //cpp_int inv_k;
        if (r == 0) continue;

        /*while (1)
         {
            inv_k = mod_inverse(k, n);
            if (inv_k == -1) continue;
            else break;
        }*/
        //std::cerr << "1\n";
        s = (mod_inverse(k, n) * (z + r * private_key)) % n;
        std::cerr << k << "\n" << mod_inverse(k, n) << "\n";

            if (s != 0) break;
    }

    // Отладочный вывод
    std::cout << "Debug Info - Message Hash: " << z << std::endl;
    std::cout << "Debug Info - Random k: " << k << std::endl;
    std::cout << "Debug Info - r: " << r << ", s: " << s << std::endl;
}

// Проверка подписи
bool verify_signature(const Point& public_key, const std::string& message, const cpp_int& r, const cpp_int& s) {
    if (r <= 0 || r >= n || s <= 0 || s >= n) return false;
    //cpp_int inv_k;

    cpp_int z = string_hash(message);
    /*while (1)
    {
        inv_k = mod_inverse(s, n);
        if (inv_k == -1) continue;
        else break;
    }*/
    cpp_int w = mod_inverse(s, n);
    cpp_int u1 = (z * w) % n;
    cpp_int u2 = (r * w) % n;

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
    cpp_int R_x_mod_n = R.x % n;
    std::cout << "Debug Info - R.x % n: " << R_x_mod_n << std::endl;

    bool is_valid = (R_x_mod_n == r);

    // Дополнительный вывод для конечного результата
    std::cout << "Signature is " << (is_valid ? "valid" : "invalid") << std::endl;

    return is_valid;
}

int main() {
    setlocale(LC_ALL, "Rus");
    cpp_int private_key;
    Point public_key;
    try {
    // Генерация пары ключей
    generate_key_pair(private_key, public_key);
    std::cout << "Private key: " << private_key << std::endl;
    std::cout << "Public key: (" << public_key.x << ", " << public_key.y << ")" << std::endl;

    // Подпись сообщения
    std::string message = "Hello, world!";
    cpp_int r, s;
    sign_message(private_key, message, r, s);
    std::cout << "Signature (r, s): (" << r << ", " << s << ")" << std::endl;

    // Проверка подписи
    bool valid = verify_signature(public_key, message, r, s);
    std::cout << "Signature is " << (valid ? "valid" : "invalid") << std::endl;
    }
    catch (const std::invalid_argument& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }

    return 0;
}