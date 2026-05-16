import { NavLink, useNavigate, useLocation } from "react-router-dom";
import "./Header.scss";

const Header = ({
  toggleLanguage,
  language,
  onLogout,
  isAuthenticated,
}) => {
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = () => {
    onLogout();
    navigate("/login");
  };



  return (
    <header className="App-header">
      <div className="container">
        <div className="nav">
          <NavLink to="/about-tools" className="a" activeClassName="active">
            {language === "ru" ? "Об инструменте" : "About Tools"}
          </NavLink>
          <NavLink to="/Tools" className="a" activeClassName="active">
            {language === "ru" ? "Виды скриптов" : "Script Types"}
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
          {isAuthenticated ? (
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