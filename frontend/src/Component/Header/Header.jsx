import { NavLink, useNavigate } from "react-router-dom";
import "./Header.scss";

const Header = ({
  toggleLanguage,
  language,
}) => {
  const navigate = useNavigate();



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
          <NavLink to="/task" className="a" activeClassName="active">
            {language === "ru" ? "Цель" : "Task"}
          </NavLink>
          <NavLink to="/" className="a" activeClassName="active">
            CyberScope
          </NavLink>
        </div>

        <div className="nav_language-exit">
          <button className="btn__language" onClick={toggleLanguage}>
            {language === "ru" ? "English" : "Русский"}
          </button>
          <button className="btn__exit" onClick={() => navigate(-1)}>
            {language === "ru" ? "Обратно" : "Back"}
          </button>
        </div>
      </div>
    </header>
  );
};

export default Header;
