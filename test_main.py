from fastapi.testclient import TestClient
from main import app

# Создаём тестовый клиент
client = TestClient(app)

# Тест для корневого маршрута (русский язык)
def test_read_root_ru():
    response = client.get("/", headers={"Accept-Language": "ru"})
    assert response.status_code == 200
    assert response.json() == {"message": "Добро пожаловать в Лабораторную работу №1!"}

# Тест для маршрута /info/server
def test_get_server_info():
    response = client.get("/info/server")
    assert response.status_code == 200
    assert "python_version" in response.json()
    assert "system" in response.json()
    assert "server_time" in response.json()

# Тест для маршрута /info/client
def test_get_client_info():
    response = client.get("/info/client")
    assert response.status_code == 200
    assert "ip" in response.json()
    assert "useragent" in response.json()

# Тест для маршрута /info/database
def test_get_database_info():
    response = client.get("/info/database")
    assert response.status_code == 200
    assert "database" in response.json()
    assert "version" in response.json()