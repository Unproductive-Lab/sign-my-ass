## Подпиши моё очко - проект создания цифровой подписи на основе эллиптической кривой
Требования - библиотека boost (но ты можешь просто везде понатыкать longint и прописать свои функции)
## Кр. теория
Эллиптические кривые - это кривые, похожие на графике на сосочки, которые делают свою магию.

#### Переменные эллиптической кривой
| Параметр | Тип     | Description                |
| :-------- | :------- | :------------------------- |
| `P` | `cpp_int (boost)` | Модуль, по которому выполняются вычисления. <br>Он определяет конечное поле GF(p) , в котором определяются точки эллиптической кривой |
| `a & b` | `cpp_int (boost)` | Эти параметры задают уравнение эллиптической кривой в форме <br>**y^2=x^3+ax+by 2=x 3 + ax + b (mod p).** |
