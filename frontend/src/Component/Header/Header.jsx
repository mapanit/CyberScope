import { NavLink, useNavigate, useLocation } from "react-router-dom";
import { useState, useEffect } from "react";
import "./Header.scss";

const Header = ({
  toggleLanguage,
  language,
}) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);

  useEffect(() => {
    const user = JSON.parse(localStorage.getItem("currentUser") || "null");
    if (user) {
      setIsLoggedIn(true);
      setCurrentUser(user);
    } else {
      setIsLoggedIn(false);
      setCurrentUser(null);
    }
  }, [location]); // Обновлять при изменении маршрута

  const handleLogout = () => {
    localStorage.removeItem("currentUser");
    setIsLoggedIn(false);
    setCurrentUser(null);
    navigate("/login");
  };



  return (
    <header className="App-header">
      <div className="container">
        <div className="nav">
          <NavLink to="/about-tools" className="a" activeClassName="active">
            {language === "ru" ? "Об инструменте" : "About Tools"}
          </NavLink>
          <NavLink to="/questions" className="a" activeClassName="active">
            {language === "ru" ? "Вопросы" : "Questions"}
          </NavLink>
          <NavLink to="/Analytic" className="a" activeClassName="active">
            {language === "ru" ? "Аналитика" : "Analytic"}
          </NavLink>
          <NavLink to="/" className="a" activeClassName="active">
            CyberScope
          </NavLink>
        </div>

        <div className="nav_language-exit">
          <button className="btn__language" onClick={toggleLanguage}>
            {language === "ru" ? "English" : "Русский"}
          </button>
          {isLoggedIn ? (
            <button className="btn__logout" onClick={handleLogout}>
              {language === "ru" ? "Выйти" : "Logout"}
            </button>
          ) : (
            <NavLink to="/login" className="btn__login">
              {language === "ru" ? "Войти" : "Login"}
            </NavLink>
          )}
        </div>
      </div>
    </header>
  );
};

export default Header;
