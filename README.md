
![Static Badge](https://img.shields.io/badge/%D0%A0%D0%B0%D0%B1%D0%BE%D1%82%D0%B0%D0%B5%D1%82%3F-%D0%94%D0%B0!-green) ![Static Badge](https://img.shields.io/badge/%D0%A5%D0%BE%D1%80%D0%BE%D1%88%D0%BE%3F-%D0%9D%D0%B5%D1%8F%D1%81%D0%BD%D0%BE-yellow) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/9bc5977cad4248d8942488e670813d58)](https://app.codacy.com/gh/Unproductive-Lab/sign-my-ass/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)



## Проект создания цифровой подписи на основе эллиптической кривой
Требования - библиотека boost (но ты можешь просто везде понатыкать longint и прописать свои функции)
## Кр. теория
[Референс материал](https://www.youtube.com/watch?v=vO5h-9Ibmck) <br>
Эллиптические кривые - это кривые, похожие на графике на сосочки, которые делают свою магию.

#### Константы эллиптической кривой
Fair warning - в этом проекте представлена кривая Р-256. Это **ДАЛЕКО** не единственная кривая в мире, и если вы хотите чтобы у вас был шанс на коммерческое использование, присмотритесь, например, к кривой [**ГОСТ 34.10-2012** или её родне.](https://neuromancer.sk/std/gost/)
| Параметр | Тип     | Description                |
| :-------- | :------- | :------------------------- |
| `P` | `cpp_int (boost)` | Модуль, по которому выполняются вычисления. <br>Он определяет конечное поле GF(p) , в котором определяются точки эллиптической кривой |
| `a & b` | `cpp_int (boost)` | Эти параметры задают уравнение эллиптической кривой в форме <br>**y^2=x^3+ax+by 2=x 3 + ax + b (mod p).** |
| `m` | `cpp_int (boost)` | aka. порядок группы. Это количество точек на эллиптической кривой, включая "нулевую" точку|
| `Gx & Gy` | `cpp_int (boost)` | Координаты базовой точки. <br>Такой, что есть порядок q; q*P[Gx, Gy] = O, где O - нулевая точка|
| `n` | `cpp_int (boost)` | Порядок точки [Gx, Gy]|


Для получения текста на подпись, программа [читает файл](https://github.com/Unproductive-Lab/sign-my-ass/blob/21c8e324562f7af94d036e2072c441f32cbb3bed/main.cpp#L193) по пути ниже. <br> **Вы можете хотеть поменять это.**
```
line 193 : Text.open("D://Message.txt", ios::in);
```

