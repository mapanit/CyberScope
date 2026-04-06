import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import "./Login.scss"; // Можно использовать свой CSS

const Login = ({ language }) => {
  const navigate = useNavigate();
  const [isLogin, setIsLogin] = useState(true); // Переключение между входом и регистрацией
  const [formData, setFormData] = useState({
    username: "",
    password: "",
    confirmPassword: "",
  });
  const [errors, setErrors] = useState({});
  const [successMessage, setSuccessMessage] = useState("");

  // Варианты анимации для форм
  const formVariants = {
    initial: {
      opacity: 0,
      x: isLogin ? -50 : 50,
      scale: 0.95
    },
    in: {
      opacity: 1,
      x: 0,
      scale: 1
    },
    out: {
      opacity: 0,
      x: isLogin ? 50 : -50,
      scale: 0.95
    }
  };

  const formTransition = {
    type: "tween",
    ease: "anticipate",
    duration: 0.4
  };

  // Обработка изменения полей
  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
    // Очищаем ошибку для этого поля при вводе
    if (errors[name]) {
      setErrors((prev) => ({
        ...prev,
        [name]: "",
      }));
    }
  };

  // Валидация формы
  const validateForm = () => {
    const newErrors = {};

    if (!formData.username.trim()) {
      newErrors.username = language === "ru" ? "Имя пользователя обязательно" : "Username is required";
    }

    if (!formData.password) {
      newErrors.password = language === "ru" ? "Пароль обязателен" : "Password is required";
    } else if (formData.password.length < 6) {
      newErrors.password = language === "ru" ? "Пароль должен содержать минимум 6 символов" : "Password must be at least 6 characters";
    }

    if (!isLogin && formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = language === "ru" ? "Пароли не совпадают" : "Passwords do not match";
    }

    return newErrors;
  };

  // Обработка отправки формы
  const handleSubmit = (e) => {
    e.preventDefault();
    const newErrors = validateForm();

    if (Object.keys(newErrors).length === 0) {
      // Имитация успешного запроса
      if (isLogin) {
        // Имитация входа
        const users = JSON.parse(localStorage.getItem("users") || "[]");
        const user = users.find(
          (u) => u.username === formData.username && u.password === formData.password,
        );

        if (user) {
          setSuccessMessage(language === "ru" ? "Вход выполнен успешно!" : "Login successful!");
          localStorage.setItem("currentUser", JSON.stringify(user));
          setTimeout(() => {
            navigate("/");
          }, 500);
        } else {
          setErrors({ general: language === "ru" ? "Неверное имя пользователя или пароль" : "Invalid username or password" });
        }
      } else {
        // Имитация регистрации
        const users = JSON.parse(localStorage.getItem("users") || "[]");
        const userExists = users.some((u) => u.username === formData.username);

        if (userExists) {
          setErrors({ general: language === "ru" ? "Пользователь с таким именем уже существует" : "User with this username already exists" });
        } else {
          const newUser = {
            id: Date.now(),
            username: formData.username,
            password: formData.password,
          };
          users.push(newUser);
          localStorage.setItem("users", JSON.stringify(users));
          setSuccessMessage(language === "ru" ? "Регистрация успешна! Теперь вы можете войти." : "Registration successful! You can now log in.");
          setFormData({
            username: "",
            password: "",
            confirmPassword: "",
          });
          // Переключаемся на форму входа через 2 секунды
          setTimeout(() => {
            setIsLogin(true);
            setSuccessMessage("");
          }, 2000);
        }
      }
    } else {
      setErrors(newErrors);
    }
  };

  // Переключение между формами
  const toggleForm = () => {
    setIsLogin(!isLogin);
    setErrors({});
    setSuccessMessage("");
    setFormData({
      username: "",
      password: "",
      confirmPassword: "",
    });
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <AnimatePresence mode="wait">
          <motion.h2
            key={isLogin}
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            transition={{ duration: 0.3 }}
          >
            {isLogin ? (language === "ru" ? "Вход в систему" : "Login") : (language === "ru" ? "Регистрация" : "Registration")}
          </motion.h2>
        </AnimatePresence>

        {successMessage && (
          <div className="success-message">{successMessage}</div>
        )}

        {errors.general && (
          <div className="error-message">{errors.general}</div>
        )}

        <AnimatePresence mode="wait">
          <motion.form
            key={isLogin}
            initial="initial"
            animate="in"
            exit="out"
            variants={formVariants}
            transition={formTransition}
            onSubmit={handleSubmit}
          >
            <div className="form-group">
              <label htmlFor="username">{language === "ru" ? "Имя пользователя" : "Username"}</label>
              <input
                type="text"
                id="username"
                name="username"
                value={formData.username}
                onChange={handleChange}
                placeholder={language === "ru" ? "Введите имя пользователя" : "Enter username"}
                className={errors.username ? "error" : ""}
              />
              {errors.username && <span className="error-text">{errors.username}</span>}
            </div>

            <div className="form-group">
              <label htmlFor="password">{language === "ru" ? "Пароль" : "Password"}</label>
              <input
                type="password"
                id="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                placeholder={language === "ru" ? "Минимум 6 символов" : "At least 6 characters"}
                className={errors.password ? "error" : ""}
              />
              {errors.password && (
                <span className="error-text">{errors.password}</span>
              )}
            </div>

            {!isLogin && (
              <div className="form-group">
                <label htmlFor="confirmPassword">{language === "ru" ? "Подтверждение пароля" : "Confirm Password"}</label>
                <input
                  type="password"
                  id="confirmPassword"
                  name="confirmPassword"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  placeholder={language === "ru" ? "Повторите пароль" : "Repeat password"}
                  className={errors.confirmPassword ? "error" : ""}
                />
                {errors.confirmPassword && (
                  <span className="error-text">{errors.confirmPassword}</span>
                )}
              </div>
            )}

            <button type="submit" className="submit-btn">
              {isLogin ? (language === "ru" ? "Войти" : "Login") : (language === "ru" ? "Зарегистрироваться" : "Register")}
            </button>
          </motion.form>
        </AnimatePresence>
            <button onClick={toggleForm} className="toggle-btn">
              {isLogin ? (language === "ru" ? "Зарегистрироваться" : "Register") : (language === "ru" ? "Войти" : "Login")}
            </button>
      </div>
    </div>
  );
};

export default Login;
