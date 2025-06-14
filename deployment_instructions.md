# Інструкція з розгортання бекенду Lending на Render

## Вступ

Цей документ містить детальні інструкції з розгортання повної версії інтернет-магазину "Lending" з бекендом на Flask та базою даних PostgreSQL на платформі Render. Ці інструкції призначені для новачків і не вимагають глибоких знань програмування.

## Передумови

1. Обліковий запис на [Render](https://render.com)
2. Обліковий запис на [GitHub](https://github.com) (рекомендовано, але не обов'язково)
3. Завантажені файли проєкту з бекендом

## Крок 1: Підготовка репозиторію на GitHub

### Якщо у вас є GitHub:

1. Увійдіть у свій обліковий запис GitHub
2. Створіть новий репозиторій:
   - Натисніть "+" у верхньому правому куті
   - Виберіть "New repository"
   - Назвіть репозиторій, наприклад, "lending-backend"
   - Залиште репозиторій публічним
   - Натисніть "Create repository"
3. Завантажте файли проєкту:
   - Натисніть "uploading an existing file"
   - Перетягніть всі файли з папки `lending_backend`
   - Натисніть "Commit changes"

### Якщо у вас немає GitHub:

Ви можете завантажити файли безпосередньо на Render, але це менш зручно для подальших оновлень.

## Крок 2: Створення бази даних на Render

1. Увійдіть у свій обліковий запис Render
2. Натисніть "New" у верхньому правому куті
3. Виберіть "PostgreSQL"
4. Заповніть форму:
   - **Name**: lending-database
   - **Database**: lending_db
   - **User**: lending_user
   - **Region**: виберіть найближчий до вас регіон
   - **PostgreSQL Version**: залиште за замовчуванням (останню версію)
   - **Instance Type**: Free (безкоштовний план)
5. Натисніть "Create Database"
6. Після створення бази даних, запишіть наступні дані:
   - **Internal Database URL**: це внутрішня URL для підключення
   - **External Database URL**: це зовнішня URL для підключення
   - **PSQL Command**: команда для підключення до бази даних
   - **Password**: пароль для користувача бази даних

## Крок 3: Створення веб-сервісу на Render

1. Натисніть "New" у верхньому правому куті
2. Виберіть "Web Service"

### Якщо ви використовуєте GitHub:

3. Виберіть "Connect a repository"
4. Знайдіть і виберіть свій репозиторій "lending-backend"

### Якщо ви не використовуєте GitHub:

3. Виберіть "Upload Files"
4. Завантажте всі файли з папки `lending_backend`

### Продовження налаштування:

5. Заповніть форму:
   - **Name**: lending-shop-backend
   - **Region**: виберіть той самий регіон, що і для бази даних
   - **Branch**: main (якщо використовуєте GitHub)
   - **Runtime**: Python
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `cd src && python main.py`
   - **Instance Type**: Free (безкоштовний план)

6. Додайте змінні середовища (Environment Variables):
   - Натисніть "Advanced" і прокрутіть до розділу "Environment Variables"
   - Додайте наступні змінні:
     - `DB_USERNAME`: lending_user
     - `DB_PASSWORD`: [пароль, який ви отримали при створенні бази даних]
     - `DB_HOST`: [внутрішній хост бази даних, частина Internal Database URL до @]
     - `DB_PORT`: 5432
     - `DB_NAME`: lending_db
     - `SECRET_KEY`: [придумайте випадковий рядок для безпеки, наприклад, "lending-secret-key-12345"]
     - `PORT`: 10000

7. Натисніть "Create Web Service"

## Крок 4: Перевірка розгортання

1. Дочекайтеся завершення розгортання (це може зайняти кілька хвилин)
2. Після успішного розгортання, ви отримаєте URL вашого сервісу (наприклад, lending-shop-backend.onrender.com)
3. Перейдіть за цим URL, щоб перевірити, що ваш сайт працює

## Крок 5: Вхід в адмін-панель

1. Перейдіть за URL вашого сервісу
2. Натисніть на "Кабінет" у верхньому меню
3. Введіть дані адміністратора:
   - Email: admin@lending.ua
   - Пароль: admin123
4. Після входу ви побачите опцію "Адмін-панель" у меню або в особистому кабінеті
5. **Важливо**: Після першого входу змініть пароль адміністратора на більш надійний через розділ "Налаштування" в адмін-панелі

## Крок 6: Налаштування власного домену (опціонально)

1. У налаштуваннях вашого веб-сервісу на Render перейдіть у розділ "Custom Domain"
2. Додайте свій домен і слідуйте інструкціям для налаштування DNS

## Усунення несправностей

### Проблема: Помилка підключення до бази даних

1. Перевірте правильність змінних середовища
2. Переконайтеся, що база даних і веб-сервіс знаходяться в одному регіоні
3. Спробуйте перезапустити веб-сервіс

### Проблема: Помилка 500 Internal Server Error

1. Перевірте логи сервісу на Render
2. Переконайтеся, що всі залежності встановлені правильно
3. Перевірте, чи правильно налаштовані змінні середовища

### Проблема: Не вдається увійти в адмін-панель

1. Переконайтеся, що ви використовуєте правильні облікові дані
2. Перевірте, чи була успішно створена база даних і таблиці
3. Спробуйте очистити кеш браузера і спробувати знову

## Подальші кроки

1. **Додавання товарів**: Використовуйте адмін-панель для додавання нових товарів
2. **Налаштування категорій**: Створіть і налаштуйте категорії товарів
3. **Тестування замовлень**: Перевірте процес оформлення замовлення
4. **Налаштування доставки**: Налаштуйте параметри доставки через адмін-панель

## Підтримка

Якщо у вас виникнуть питання або проблеми з розгортанням, будь ласка, зв'яжіться з нами для отримання допомоги.
