import React, { useState } from "react";
import axios from "axios";
import { useNavigate, NavLink } from "react-router-dom";
import "./Register.scss";

function Register({ setToken }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    if (password !== confirmPassword) {
      setError("Пароли не совпадают");
      return;
    }

    if (password.length < 6) {
      setError("Пароль должен быть не менее 6 символов");
      return;
    }

    setLoading(true);

    try {
      // Регистрация
      await axios.post("http://localhost:8000/auth/register", {
        username,
        password,
      });

      // Автоматический вход после регистрации
      const loginResponse = await axios.post(
        "http://localhost:8000/auth/login",
        {
          username,
          password,
        },
      );

      setToken(loginResponse.data.access_token);
      navigate("/dashboard");
    } catch (err) {
      if (err.response && err.response.data) {
        setError(err.response.data.detail || "Ошибка при регистрации");
      } else {
        setError("Ошибка сети. Пожалуйста, попробуйте снова.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h2>Регистрация</h2>
        {error && <div className="error-message">{error}</div>}
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Имя пользователя:</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              disabled={loading}
            />
          </div>
          <div className="form-group">
            <label>Пароль:</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={loading}
            />
          </div>
          <div className="form-group">
            <label>Подтвердить пароль:</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              disabled={loading}
            />
          </div>
          <button type="submit" disabled={loading}>
            {loading ? "Регистрация..." : "Зарегистрироваться"}
          </button>
        </form>
        <p>
          Уже есть аккаунт? <NavLink to="/login">Войти</NavLink>
        </p>
      </div>
    </div>
  );
}

export default Register;
