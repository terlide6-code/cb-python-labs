# Лабораторна робота №3 — REST API та SQLite

## Тема і мета

Тема: **«Реєстр вразливостей мережевих сервісів»**. Мета роботи — навчитися
створювати синхронний REST API на FastAPI, зберігати дані в SQLite та безпечно
виконувати параметризовані SQL-запити і транзакції.

Студент: Перестюк Назарій Романович, група КБ-205. Варіант: **2**.

Предметна область — облік результатів навчальної перевірки безпеки мережевих
сервісів. Оцінка небезпеки має діапазон від 0 до 10; поріг небезпеки — 6.0.

## Технології та структура

Використано Python, FastAPI, Pydantic 2, стандартний модуль `sqlite3`, Uvicorn
та Ruff. ORM не застосовується.

```text
labs/lab03/
├── config.py          # константи варіанта і шляхи
├── database.py        # з'єднання та ініціалізація SQLite
├── main.py            # FastAPI-застосунок
├── repository.py      # параметризовані SQL-запити
├── schema.sql         # схема бази даних
├── schemas.py         # Pydantic-моделі
├── seed.py            # ідемпотентне початкове наповнення
├── routers/
│   ├── categories.py
│   └── records.py
└── data/seed.json
```

База `data/lab3.sqlite3` створюється автоматично та ігнорується Git.

## Модель даних

`categories`: `id` (PRIMARY KEY), `name` (NOT NULL, UNIQUE).

`records`: `id` (PRIMARY KEY), `category_id` (NOT NULL, FOREIGN KEY), `code`
(NOT NULL, UNIQUE), `title` (NOT NULL), `value` (NOT NULL, CHECK 0..10),
`status` (NOT NULL, CHECK: `new`, `in_progress`, `done`). Один запис належить
одній категорії; категорію з записами не можна видалити (`ON DELETE RESTRICT`).
Для кожного з'єднання увімкнено `PRAGMA foreign_keys = ON`.

## Встановлення і запуск

```bash
python3 -m pip install -r requirements.txt
python3 -m labs.lab03.seed
uvicorn labs.lab03.main:app --reload
```

Після запуску документація Swagger UI доступна за адресою
[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

Повторний запуск `seed` безпечний: він не створює дублікатів та не змінює
наявних даних. Вісім початкових записів вставляються в одній транзакції; при
помилці виконується rollback.

## Endpoints

| Метод | Шлях | Призначення |
|---|---|---|
| GET | `/ping` | Перевірка роботи API |
| GET | `/student` | Дані студента з `shared/student.py` |
| GET, POST | `/categories` | Перегляд і створення категорій |
| DELETE | `/categories/{category_id}` | Видалення порожньої категорії |
| GET, POST | `/records` | Перегляд і створення записів |
| GET, PUT, DELETE | `/records/{record_id}` | CRUD для одного запису |
| POST | `/records/bulk` | Атомарне створення 1–100 записів |

`GET /records` приймає необов'язкові фільтри `category_id`, `status`,
`min_value`, `q`, `limit` (1–100, типово 20) і `offset` (типово 0). Фільтри
поєднуються через AND, `q` є буквальним регістрозалежним підрядком, а результат
сортується за `id ASC`.

## Приклади

```bash
curl http://127.0.0.1:8000/ping
curl 'http://127.0.0.1:8000/records?status=new&min_value=6'

curl -X POST http://127.0.0.1:8000/categories \
  -H 'Content-Type: application/json' \
  -d '{"name":"web"}'

curl -X POST http://127.0.0.1:8000/records \
  -H 'Content-Type: application/json' \
  -d '{"category_id":1,"code":"V02-09","title":"Перевірка сервісу 09","value":7.2,"status":"new"}'
```

Приклад успішної відповіді `POST /records` (201):

```json
{
  "id": 9,
  "category_id": 1,
  "category_name": "mail",
  "code": "V02-09",
  "title": "Перевірка сервісу 09",
  "value": 7.2,
  "status": "new"
}
```

Приклад конфлікту (409), зокрема для повторного `code` або категорії з
записами:

```json
{"detail":"Duplicate code or unknown category"}
```

Некоректні типи, невідомі поля, порожні рядки, значення поза 0..10 та неповні
PUT-запити отримують 422. Відсутні ресурси, зокрема `category_id` під час
створення чи оновлення запису, повертають 404. Внутрішні деталі SQL та шляхи
файлів клієнтові не розкриваються; технічні помилки логуються.

## Виконані перевірки

У робочому середовищі виконано:

```bash
python3 -m labs.lab03.seed
python3 -m labs.lab03.seed
ruff check labs/lab03
ruff format --check labs/lab03
ruff check .
ruff format --check .
```

Повторний seed залишив у базі рівно 3 категорії та 8 записів. Перевірено CRUD
функцій репозиторію, фільтрацію, 404, `ON DELETE RESTRICT`, валідацію Pydantic,
rollback bulk-вставки для дубліката `code` і неіснуючої категорії, а також
буквальний пошук із рядком SQL-ін'єкції. Обидві перевірки Ruff для `lab03`
пройшли; `ruff check .` також пройшла. `ruff format --check .` виявляє лише
п'ять наявних до цієї роботи файлів Lab 01/shared, які не змінювалися.

У цьому контейнері неможливо виконати HTTP-запит до синхронного маршруту:
середовище не дозволяє відкрити локальний порт, а Python 3.14/AnyIO зависає
навіть на мінімальному запуску потоку. Це обмеження середовища перевірки, не
результат API; маршрути, імпорти та OpenAPI-додаток успішно завантажуються.
