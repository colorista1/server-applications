import unittest
from fastapi.testclient import TestClient
from main import app, User, Token, engine, get_db
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

# Настройка тестовой базы данных
TEST_DATABASE_URL = "sqlite:///./test_users.db"
test_engine = create_engine(TEST_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Переопределение зависимости для тестовой базы данных
def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[lambda: get_db] = override_get_db

class TestAuthAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        # Очистка тестовой базы данных перед каждым тестом
        User.__table__.drop(test_engine, checkfirst=True)
        Token.__table__.drop(test_engine, checkfirst=True)
        User.__table__.create(test_engine)
        Token.__table__.create(test_engine)
        os.environ["MAX_TOKENS"] = "5"  # Значение по умолчанию

    def test_1_1_register_success(self):
        """Тест 1.1: Успешная регистрация"""
        response = self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["username"], "Username")
        db = TestingSessionLocal()
        user = db.query(User).filter(User.username == "Username").first()
        self.assertIsNotNone(user)  # Проверка, что пользователь сохранен
        db.close()

    def test_1_2_register_duplicate_username(self):
        """Тест 1.2: Ошибка при дубликате имени пользователя"""
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        response = self.client.post("/api/auth/register", json={
            "username": "UserName",
            "email": "username2@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        self.assertEqual(response.status_code, 422)
        self.assertIn("Имя пользователя уже занято", response.json()["detail"])

    def test_1_3_register_duplicate_email(self):
        """Тест 1.3: Ошибка при дубликате email"""
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        response = self.client.post("/api/auth/register", json={
            "username": "UserName2",
            "email": "userName@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        self.assertEqual(response.status_code, 422)
        self.assertIn("Email уже используется", response.json()["detail"])

    def test_1_4_register_underage(self):
        """Тест 1.4: Ошибка при возрасте менее 14 лет"""
        response = self.client.post("/api/auth/register", json={
            "username": "UserName1",
            "email": "userName1@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2012-10-10"
        })
        self.assertEqual(response.status_code, 422)
        self.assertIn("Пользователь должен быть старше 14 лет", response.json()["detail"])

    def test_1_5_register_invalid_password(self):
        """Тест 1.5: Ошибка при неверном формате пароля"""
        response = self.client.post("/api/auth/register", json={
            "username": "UserName2",
            "email": "userName2@test.ru",
            "password": "password",
            "c_password": "password",
            "birthday": "2009-09-09"
        })
        self.assertEqual(response.status_code, 422)
        self.assertIn("Пароль должен содержать минимум одну заглавную букву", response.json()["detail"])

    def test_2_1_login_success(self):
        """Тест 2.1: Успешная авторизация"""
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        response = self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "Password1"
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())
        self.assertIn("refresh_token", response.json())

    def test_2_2_login_invalid_password(self):
        """Тест 2.2: Ошибка авторизации при неверном пароле"""
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        response = self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "WrongPassword"
        })
        self.assertEqual(response.status_code, 422)
        self.assertIn("Неверные учетные данные", response.json()["detail"])

    def test_2_3_token_information(self):
        """Тест 2.3: Проверка содержимого токена"""
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        response = self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "Password1"
        })
        access_token = response.json()["access_token"]
        token_parts = access_token.split("_")
        self.assertEqual(len(token_parts), 3)  # user_id, uuid, timestamp
        db = TestingSessionLocal()
        user = db.query(User).filter(User.username == "Username").first()
        if not user:
            self.fail("Пользователь не найден в базе данных")
        self.assertEqual(token_parts[0], str(user.id))  # Токен содержит user_id
        db.close()

    def test_2_4_max_tokens_4(self):
        """Тест 2.4: Проверка лимита токенов (4 токена)"""
        os.environ["MAX_TOKENS"] = "4"
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        tokens_list = []
        for _ in range(5):
            response = self.client.post("/api/auth/login", json={
                "username": "Username",
                "password": "Password1"
            })
            tokens_list.append(response.json()["access_token"])
        db = TestingSessionLocal()
        user = db.query(User).filter(User.username == "Username").first()
        if not user:
            self.fail("Пользователь не найден в базе данных")
        active_tokens = db.query(Token).filter(Token.user_id == user.id).all()
        self.assertEqual(len(active_tokens), 4)
        db.close()

    def test_2_5_max_tokens_change(self):
        """Тест 2.5: Изменение лимита токенов с 8 до 2"""
        os.environ["MAX_TOKENS"] = "8"
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        tokens_list = []
        for _ in range(8):
            response = self.client.post("/api/auth/login", json={
                "username": "Username",
                "password": "Password1"
            })
            tokens_list.append(response.json()["access_token"])
        db = TestingSessionLocal()
        user = db.query(User).filter(User.username == "Username").first()
        if not user:
            self.fail("Пользователь не найден в базе данных")
        active_tokens = db.query(Token).filter(Token.user_id == user.id).all()
        self.assertEqual(len(active_tokens), 8)
        os.environ["MAX_TOKENS"] = "2"
        self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "Password1"
        })
        active_tokens = db.query(Token).filter(Token.user_id == user.id).all()
        self.assertEqual(len(active_tokens), 2)
        db.close()

    def test_3_1_get_me(self):
        """Тест 3.1: Получение информации о пользователе"""
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        login_response = self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "Password1"
        })
        token = login_response.json()["access_token"]
        response = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["username"], "Username")
        self.assertNotIn("password", response.json())

    def test_3_2_get_me_after_logout(self):
        """Тест 3.2: Ошибка доступа после выхода"""
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        login_response = self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "Password1"
        })
        token = login_response.json()["access_token"]
        self.client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        response = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 401)

    def test_4_1_logout(self):
        """Тест 4.1: Проверка выхода из системы"""
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        login_response = self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "Password1"
        })
        token = login_response.json()["access_token"]
        response = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200)
        logout_response = self.client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(logout_response.status_code, 200)
        response = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 401)

    def test_5_1_logout_all(self):
        """Тест 5.1: Отзыв всех токенов"""
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        login1 = self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "Password1"
        })
        token1 = login1.json()["access_token"]
        login2 = self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "Password1"
        })
        token2 = login2.json()["access_token"]
        logout_response = self.client.post("/api/auth/logout-all", headers={"Authorization": f"Bearer {token1}"})
        self.assertEqual(logout_response.status_code, 200)
        response = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token2}"})
        self.assertEqual(response.status_code, 401)

    def test_6_1_get_tokens(self):
        """Тест 6.1: Получение списка токенов"""
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        login_response = self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "Password1"
        })
        token = login_response.json()["access_token"]
        self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "Password1"
        })
        response = self.client.get("/api/auth/tokens", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 1)

    def test_7_1_refresh_token(self):
        """Тест 7.1: Успешное обновление токена"""
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        login_response = self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "Password1"
        })
        refresh_token = login_response.json()["refresh_token"]
        response = self.client.post("/api/auth/refresh", json={"refresh_token": refresh_token})
        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())
        self.assertIn("refresh_token", response.json())

    def test_7_2_refresh_token_reuse(self):
        """Тест 7.2: Ошибка при повторном использовании токена обновления"""
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        login_response = self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "Password1"
        })
        token = login_response.json()["access_token"]
        refresh_token = login_response.json()["refresh_token"]
        response = self.client.post("/api/auth/refresh", json={"refresh_token": refresh_token})
        self.assertEqual(response.status_code, 200)
        response = self.client.post("/api/auth/refresh", json={"refresh_token": refresh_token})
        self.assertEqual(response.status_code, 422)
        response = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 401)

    def test_8_1_change_password(self):
        """Тест 8.1: Успешная смена пароля"""
        self.client.post("/api/auth/register", json={
            "username": "Username",
            "email": "username@test.ru",
            "password": "Password1",
            "c_password": "Password1",
            "birthday": "2009-09-09"
        })
        login_response = self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "Password1"
        })
        token = login_response.json()["access_token"]
        response = self.client.post("/api/auth/change-password", json={
            "old_password": "Password1",
            "new_password": "NewPassword1"
        }, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200)
        login_response = self.client.post("/api/auth/login", json={
            "username": "Username",
            "password": "NewPassword1"
        })
        self.assertEqual(login_response.status_code, 200)

if __name__ == "__main__":
    unittest.main()