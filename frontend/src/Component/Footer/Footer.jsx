import { Link } from "react-router-dom";
import './Footer.scss';

const Footer = ({language}) => {
    return (
        <footer className='footer'>
            <div className="container">
                <a href="https://github.com/mapanit" target="_blank" rel="noopener noreferrer">
                    <p>Github</p>
                </a>
                <Link to="/">
                {language === "ru" ? <p>Главная</p> : <p>Home</p>}
                </Link>
            </div>
        </footer>
    );
};

export default Footer;