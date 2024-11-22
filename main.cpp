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

// Параметры эллиптической кривой P-256
const cpp_int p("115792089210356248762697446949407573530086143415290314195533631308867097853951");
const cpp_int a("115792089210356248762697446949407573530086143415290314195533631308867097853948");
const cpp_int b("41058363725152142129326129780047268409114441015993725554835256314039467401291");
const cpp_int Gx("48439561293906451759052585252797914202762949526041747995844080717082404635286");
const cpp_int Gy("36134250956749795798585127919587881956611106672985015071877198253568414405109");
const cpp_int n("115792089210356248762697446949407573529996955224135760342422259061068512044369");

boost::hash<std::string> string_hash;

cpp_int mod_inverse(cpp_int a, cpp_int m)
{
    cpp_int exp = m - 2;
    cpp_int result = 1;
    a = a % m;
    while (exp > 0) 
    {
        if (exp % 2 == 1)
            result = (result * a) % m;
        a = (a * a) % m;
        exp /= 2;
    }
    return result;

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
            m = ((3 * x * x + a) * mod_inverse(2 * y, p)) % p;
        else 
            m = ((other.y - y) * mod_inverse(other.x - x, p)) % p;
        if (m < 0)
            m += p;
        cpp_int x_r = (m * m - x - other.x) % p;
        cpp_int y_r = (m * (x - x_r) - y) % p;

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
    //cout << "Секретный ключ: " << private_key << "\n";
    cout << "Публичный ключ: (" << public_key.x << ", " << public_key.y << ")\n";
}


void sign_message(const cpp_int& private_key, const std::string& message, cpp_int& r, cpp_int& s) 
{
    cpp_int h = string_hash(message);
    cpp_int k; 
    while (true) 
    {
        k = random_cpp_int(n); 
        Point R = Point(Gx, Gy) * k;
        r = R.x % n;
        if (r == 0) 
            continue;
        s = (mod_inverse(k, n) * (h + r * private_key)) % n;
        if (s != 0) 
            break;

    }
    if (r < 0)
        r += n;
    if (s < 0)
        s += n;
    //cout << "Хэш: " << h << "\n";
    //cout << "Случайное k: " << k << "\n";
    cout << "Подпись (r, s): (" << r << ", " << s << ")\n";
    system("pause");
}


void verify_signature(const Point& public_key, const std::string& message, const cpp_int& r, const cpp_int& s) 
{
    if (r <= 0 || r >= n || s <= 0 || s >= n)
    {
        cout << "Подпись недействительна\n";
        return;
    }
    cpp_int h = string_hash(message);
    cpp_int v = mod_inverse(s, n);
    if (v < 0)
        v += n;
    cpp_int u1 = (h * v) % n;
    if (u1 < 0)
        u1 += n;
    cpp_int u2 = (r * v) % n;
    if (u2 < 0)
        u2 += n;
    //cout << "Хэш: " << h << "\n";
    //cout << "v (s^-1 mod n): " << v << "\n";
    //cout << "u1 (h * v mod n) : " << u1 << "\n";
    //cout << "u2 (r * v mod n): " << u2 << "\n";
    Point X = Point(Gx, Gy) * u1 + public_key * u2;
    if (X.x < 0)
        X.x += p;
    if (X.y < 0)
        X.y += p;
    //cout << "X.x: " << X.x << "\n";
    //cout << "X.y: " << X.y << "\n";
    //cout << "r: " << r << "\n";
    cpp_int X_x_mod_n = X.x % n;
    //cout << "X.x % n: " << X_x_mod_n << "\n";
    bool is_valid = (X_x_mod_n == r);
    cout << "Подпись " << (is_valid ? "действительна" : "недействительна") << "\n";
    system("pause");

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
        system("cls");
        cout << "1.Подписать файл.\n2.Проверить подпись.\n3.Выход.\n";
        cin >> opt;
        if (opt == 1)
        {
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
        }
        else if (opt == 2)
        {
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
        }
        else if (opt == 3)
            break;
    }

    return 0;
}
