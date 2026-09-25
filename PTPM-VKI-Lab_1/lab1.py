import os
import re
import hashlib
import logging
import traceback
import getpass
from typing import Tuple

# ==========================================
# 1. НАСТРОЙКА СКВОЗНОГО ЛОГИРОВАНИЯ
# ==========================================
logger = logging.getLogger("UserValidationLogger")
logger.setLevel(logging.DEBUG)

# Формат логов: Дата и время, Уровень, Сообщение
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Хендлер для записи в файл
file_handler = logging.FileHandler("registration.log", encoding="utf-8")
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)

# Хендлер для вывода в консоль
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

# ==========================================
# 2. РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ И КОНСТАНТЫ
# ==========================================
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
PHONE_REGEX = re.compile(r'^\+\d-\d{3}-\d{3}-\d{4}$')
STRING_LOGIN_REGEX = re.compile(r'^[a-zA-Z0-9_]{5,}$')

# Пароль должен состоять только из кириллицы, цифр и спецсимволов (\W и знак подчеркивания _)
ALLOWED_PASSWORD_CHARS = re.compile(r'^[а-яА-ЯёЁ0-9\W_]+$')
CYRILLIC_UPPER = re.compile(r'[А-ЯЁ]')
CYRILLIC_LOWER = re.compile(r'[а-яё]')
DIGIT = re.compile(r'[0-9]')
SPECIAL_CHAR = re.compile(r'[\W_]')

# Предустановленный черный список логинов
BLACKLIST_LOGINS = {"admin", "root", "administrator", "moderator", "guest", "support", "user"}


# ==========================================
# 3. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ БЕЗОПАСНОСТИ
# ==========================================
def mask_password(password: str) -> str:
    """
    Маскирует пароль с помощью SHA-256 хеширования (Вариант 2).
    Возвращает одинаковый результат для одинаковых паролей и разный для отличающихся,
    не раскрывая исходный пароль в лог-файлах.
    """
    if not password:
        return "[EMPTY]"
    # Соль для защиты от радужных таблиц
    salt = "SecureRegistrationSalt_2026_"
    hashed = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    return f"[MASKED_SHA256:{hashed[:12]}...]"


# ==========================================
# 4. ОСНОВНОЙ МЕТОД ВАЛИДАЦИИ
# ==========================================
def validate_user_registration(login: str, password: str, password_confirm: str) -> Tuple[bool, str]:
    """
    Выполняет комплексную валидацию учетных данных.
    Возвращает кортеж: (Результат: bool, Сообщение: str)
    """
    # Маскируем пароли для безопасного сквозного логирования входных параметров
    masked_pwd = mask_password(password)
    masked_confirm = mask_password(password_confirm)
    
    try:
        # --- ВАЛИДАЦИЯ ЛОГИНА ---
        if not login:
            error_msg = "Логин не может быть пустым."
            logger.warning(f"Неуспешный запрос. Логин: '{login}', Пароль: {masked_pwd}. Ошибка: {error_msg}")
            return False, error_msg

        # Определение типа логина и его валидация согласно маскам
        is_email = "@" in login
        is_phone = login.startswith("+") or any(c.isdigit() for c in login if login.index(c) < 2)

        if is_email:
            if not EMAIL_REGEX.match(login):
                error_msg = "Причина 1: Логин распознан как Email, но не соответствует стандартной маске."
                logger.warning(f"Неуспешный запрос. Логин: '{login}', Пароль: {masked_pwd}. Ошибка: {error_msg}")
                return False, error_msg
        elif is_phone or (len(login) > 0 and login == '+'):
            if not PHONE_REGEX.match(login):
                error_msg = "Причина 2: Логин распознан как телефон, но не соответствует маске +x-xxx-xxx-xxxx."
                logger.warning(f"Неуспешный запрос. Логин: '{login}', Пароль: {masked_pwd}. Ошибка: {error_msg}")
                return False, error_msg
        else:
            if not STRING_LOGIN_REGEX.match(login):
                error_msg = "Причина 3: Логин-строка должен быть не менее 5 символов и содержать только латиницу, цифры и '_'."
                logger.warning(f"Неуспешный запрос. Логин: '{login}', Пароль: {masked_pwd}. Ошибка: {error_msg}")
                return False, error_msg

        # Проверка по черному списку
        if login.lower() in BLACKLIST_LOGINS:
            error_msg = "Причина 4: Указанный логин находится в предустановленном черном списке запрещенных имен."
            logger.warning(f"Неуспешный запрос. Логин: '{login}', Пароль: {masked_pwd}. Ошибка: {error_msg}")
            return False, error_msg

        # --- ВАЛИДАЦИЯ ПАРОЛЕЙ ---
        if password != password_confirm:
            error_msg = "Причина 5: Пароль и подтверждение пароля не совпадают."
            logger.warning(f"Неуспешный запрос. Логин: '{login}', Пароль: {masked_pwd}, Подтверждение: {masked_confirm}. Ошибка: {error_msg}")
            return False, error_msg

        if len(password) < 7:
            error_msg = "Причина 6: Пароль слишком короткий (минимальная длина — 7 символов)."
            logger.warning(f"Неуспешный запрос. Логин: '{login}', Пароль: {masked_pwd}. Ошибка: {error_msg}")
            return False, error_msg

        if not ALLOWED_PASSWORD_CHARS.match(password):
            error_msg = "Причина 7: Пароль содержит запрещенные символы. Разрешены только кириллица, цифры и спецсимволы."
            logger.warning(f"Неуспешный запрос. Логин: '{login}', Пароль: {masked_pwd}. Ошибка: {error_msg}")
            return False, error_msg

        if not CYRILLIC_UPPER.search(password):
            error_msg = "Причина 8: Пароль должен содержать минимум одну заглавную букву на кириллице."
            logger.warning(f"Неуспешный запрос. Логин: '{login}', Пароль: {masked_pwd}. Ошибка: {error_msg}")
            return False, error_msg

        if not CYRILLIC_LOWER.search(password):
            error_msg = "Причина 9: Пароль должен содержать минимум одну строчную букву на кириллице."
            logger.warning(f"Неуспешный запрос. Логин: '{login}', Пароль: {masked_pwd}. Ошибка: {error_msg}")
            return False, error_msg

        if not DIGIT.search(password):
            error_msg = "Причина 10: Пароль должен содержать минимум одну цифру."
            logger.warning(f"Неуспешный запрос. Логин: '{login}', Пароль: {masked_pwd}. Ошибка: {error_msg}")
            return False, error_msg

        if not SPECIAL_CHAR.search(password):
            error_msg = "Причина 11: Пароль должен содержать минимум один специальный символ."
            logger.warning(f"Неуспешный запрос. Логин: '{login}', Пароль: {masked_pwd}. Ошибка: {error_msg}")
            return False, error_msg

        # --- УСПЕШНАЯ РЕГИСТРАЦИЯ ---
        logger.info(f"Успешный запрос. Логин: '{login}', Пароль: {masked_pwd}, Результат: Регистрация успешна.")
        return True, ""

    except Exception as e:
        # В случае непредвиденного сбоя логируем трассировку стека исключений (traceback)
        tb_str = traceback.format_exc()
        error_msg = f"Критический сбой системы при валидации: {str(e)}"
        logger.critical(f"Неуспешный запрос. Логин: '{login}', Пароль: {masked_pwd}.\nТекст ошибки: {error_msg}\nТрассировка стека:\n{tb_str}")
        return False, error_msg


# ==========================================
# 5. ИНТЕРАКТИВНЫЙ ВВОД ПОЛЬЗОВАТЕЛЯ
# ==========================================
if __name__ == "__main__":
    print("=== Регистрация нового пользователя ===")
    print("Принимаются форматы логина:")
    print("  - Телефон (+x-xxx-xxx-xxxx)")
    print("  - Email (example@mail.com)")
    print("  - Обычная строка (от 5 символов: только латиница, цифры и '_')\n")

    # Ввод Строки1 (Логин)
    login_input = input("Введите Логин (Строка1): ").strip()
    
    # Ввод Строки2 и Строки3 с маскированием символов в терминале (getpass)
    password_input = getpass.getpass("Введите Пароль (Строка2): ")
    confirm_input = getpass.getpass("Подтвердите Пароль (Строка3): ")

    print("\n[Выполнение валидации данных...]\n")
    
    # Вызов метода валидации
    success, message = validate_user_registration(login_input, password_input, confirm_input)

    # Вывод выходных данных строго по ТЗ
    print("=" * 50)
    print(f"Строка1 (Результат) — {success}")
    print(f"Строка2 (Сообщение) — '{message}'")
    print("=" * 50)

    if success:
        print("🎉 Успех! Пользователь прошел валидацию.")
    else:
        print("❌ Отказано. Причина выведена выше и продублирована в файл 'registration.log'.")
