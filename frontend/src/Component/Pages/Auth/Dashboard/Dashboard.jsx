import React, { useState, useEffect } from "react";
import axios from "axios";
import "./Dashboard.scss";
import { NavLink } from "react-router-dom";

function Dashboard({ token, onLogout }) {
  const [userData, setUserData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const response = await axios.get("http://localhost:8000/auth/me", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        setUserData(response.data);
      } catch (err) {
        setError("Не удалось загрузить данные пользователя");
        if (err.response && err.response.status === 401) {
          onLogout();
        }
      } finally {
        setLoading(false);
      }
    };

    if (token) {
      fetchUserData();
    }
  }, [token]);

  if (loading) return <div className="loading">Загрузка...</div>;
  if (error) return <div className="error-message">{error}</div>;

  return (
    <div className="dashboard">
      <div className="dashboard__container">
        <div className="dashboard-header">
          <h1>Добро пожаловать, {userData?.username}!</h1>
          <div className="btn__header">
            <button onClick={onLogout} className="logout-btn">
              Выйти
            </button>
            <NavLink to="/" className="nav-link">
              На главную
            </NavLink>
          </div>
        </div>
        <div className="user-info">
          <h3>Информация о пользователе</h3>
          <p>
            <strong>ID:</strong> {userData?.id}
          </p>
          <p>
            <strong>Пользователь:</strong> {userData?.username}
          </p>
          <p>
            <strong>Дата регистрации:</strong>{" "}
            {userData?.created_at
              ? new Date(userData?.created_at).toLocaleDateString("ru-RU")
              : "Не указано"}
          </p>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
