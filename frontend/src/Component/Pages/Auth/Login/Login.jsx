import React, { useState } from "react";
import axios from "axios";
import { Router, useNavigate, NavLink } from "react-router-dom";
import "./Login.scss";

function Login({ setToken }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await axios.post("http://localhost:8000/auth/login", {
        username,
        password,
      });

      setToken(response.data.access_token);
      navigate("/dashboard");
    } catch (err) {
      if (err.response && err.response.data) {
        setError(err.response.data.detail || "Ошибка входа");
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
        <h2>Вход</h2>
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
          <button type="submit" disabled={loading}>
            {loading ? "Вход в систему..." : "Войти"}
          </button>
        </form>

        <p>
          Нет аккаунта? <NavLink to="/register">Зарегистрироваться</NavLink>
        </p>
      </div>
    </div>
  );
}

export default Login;
