#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/integer.hpp>
#include <boost/random.hpp>
#include <boost/container_hash/hash.hpp>
#include <random>
#include <stdexcept>
#include <fstream>
#include <string>

using namespace boost::multiprecision;
using namespace boost::random;
using namespace std;

// Параметры эллиптической кривой P-192
const cpp_int p("6277101735386680763835789423207666416083908700390324961279");
const cpp_int a("-3");
const cpp_int b("2455155546008943817740293915197451784769108058161191238065");
const cpp_int Gx("602046282375688656758213480587526111916698976636884684818");
const cpp_int Gy("174050332293622031404857552280219410364023488927386650641");
const cpp_int n("6277101735386680763835789423176059013767194773182842284081");

boost::hash<std::string> string_hash;

cpp_int gcdExtended(cpp_int a, cpp_int b, cpp_int& x, cpp_int& y)
{
    if (a == 0) 
    {
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

cpp_int mod_inverse(cpp_int a, cpp_int m) 
{
    cpp_int x, y;
    cpp_int g = gcdExtended(a, m, x, y);
    if (g != 1) 
        return -1;
    else
        return x % m;
}

struct Point 
{
    cpp_int x;
    cpp_int y;
    bool is_infinity = false;

    Point() : x(0), y(0), is_infinity(true) {}
    Point(cpp_int _x, cpp_int _y) : x(_x), y(_y), is_infinity(false) {}

    Point operator+(const Point& other) const 
    {
        if (is_infinity) 
            return other;
        if (other.is_infinity) 
            return *this;
        if (x == other.x && y != other.y) 
            return Point();
        cpp_int m;
        if (x == other.x) 
            m = (3 * x * x + a) * mod_inverse(2 * y, p) % p;
        else 
            m = (other.y - y) * mod_inverse(other.x - x, p) % p;
        if (m < 0)
            m += p;
        cpp_int x_r = (m * m - x - other.x) % p;
        if (x_r < 0)
            x_r += p;
        cpp_int y_r = (m * (x - x_r) - y) % p;
        if (y_r < 0)
            y_r += p;
        return Point(x_r < 0 ? x_r + p : x_r, y_r < 0 ? y_r + p : y_r);
    }

    Point operator*(const cpp_int& scalar) const 
    {
        Point result;
        Point base = *this;
        cpp_int k = scalar;
        while (k != 0)
        {
            if (k % 2 != 0)
                result = result + base;
            base = base + base;
            k /= 2;
        }
        return result;
    }
};

cpp_int random_cpp_int(const cpp_int& max) 
{
    random_device seed;
    boost::random::mt19937 gen(seed());
    boost::random::uniform_int_distribution<cpp_int> dist(1, max - 1);
    return dist(gen);
}

void generate_key_pair(cpp_int& private_key, Point& public_key) 
{
    private_key = random_cpp_int(n);
    public_key = Point(Gx, Gy) * private_key;
    cout << "Секретный ключ: " << private_key << "\n";
    cout << "Публичный ключ: (" << public_key.x << ", " << public_key.y << ")\n";
}

void sign_message(const cpp_int& private_key, const std::string& message, cpp_int& r, cpp_int& s) 
{
    cpp_int z = string_hash(message);
    cpp_int k; 
    while (true) 
    {
        k = random_cpp_int(n); 
        Point R = Point(Gx, Gy) * k;
        r = R.x % n;
        if (r == 0) 
            continue;
        s = (mod_inverse(k, n) * (z + r * private_key)) % n;
        if (s != 0) 
            break;
    }
    if (r < 0)
        r += n;
    if (s < 0)
        s += n;
    cout << "Хэш: " << z << "\n";
    cout << "Случайное k: " << k << "\n";
    cout << "Подпись (r, s): (" << r << ", " << s << ")\n";
}

void verify_signature(const Point& public_key, const std::string& message, const cpp_int& r, const cpp_int& s) 
{
    if (r <= 0 || r >= n || s <= 0 || s >= n)
    {
        cout << "Подпись недействительна\n";
        return;
    }
    cpp_int z = string_hash(message);
    cpp_int w = mod_inverse(s, n);
    if (w < 0)
        w += n;
    cpp_int u1 = (z * w) % n;
    if (u1 < 0)
        u1 += n;
    cpp_int u2 = (r * w) % n;
    if (u2 < 0)
        u2 += n;
    cout << "Хэш: " << z << "\n";
    cout << "w (s^-1 mod n): " << w << "\n";
    cout << "u1(z * w mod n) : " << u1 << "\n";
    cout << "u2 (r * w mod n): " << u2 << "\n";
    Point R = Point(Gx, Gy) * u1 + public_key * u2;
    if (R.x < 0)
        R.x += p;
    if (R.y < 0)
        R.y += p;
    cout << "R.x: " << R.x << "\n";
    cout << "R.y: " << R.y << "\n";
    cout << "r: " << r << "\n";
    cpp_int R_x_mod_n = R.x % n;
    std::cout << "R.x % n: " << R_x_mod_n << "\n";
    bool is_valid = (R_x_mod_n == r);
    std::cout << "Подпись " << (is_valid ? "действительна" : "недействительна") << "\n";
}

int main() 
{
    setlocale(LC_ALL, "Rus");
    cpp_int private_key;
    Point public_key;
    ifstream Text;
    string message;
    int opt;
    cpp_int r, s;
    while (1)
    {
        cout << "1.Подписать файл.\n2.Проверить подпись.\n3.Выход.\n";
        cin >> opt;
        switch (opt){
            case 1 : {
                Text.open("D://Message.txt", ios::in);
                getline(Text, message);
                Text.close();
                try
                {
                    generate_key_pair(private_key, public_key);
                    sign_message(private_key, message, r, s);
                }
                catch (const std::invalid_argument& e)
                {
                    cerr << "Ошибка: " << e.what() << std::endl;
                }
                break;
            }
            case 2 : {
                Text.open("D://Message.txt", ios::in);
                getline(Text, message);
                Text.close();
                try
                {
                    verify_signature(public_key, message, r, s);
                }
                catch (const std::invalid_argument& e)
                {
                    cerr << "Ошибка: " << e.what() << std::endl;
                }
                break;
            }
            case 3 : break;
        }
        

        
    }
    return 0;
}