import {
  BrowserRouter as Router,
  Routes,
  Route,
  useLocation,
  Navigate,
} from "react-router-dom";
import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";

import "./App.scss";

import Header from "./Component/Header/Header";
import Search from "./Component/Pages/Home/Home";
import Footer from "./Component/Footer/Footer";
import AboutTools from "./Component/Pages/AboutTools/AboutTools";
import Analytic from "./Component/Pages/Analytics/Analytic";
import Modal from "./Component/Modal/Modal";
import Help from "./Component/Pages/Help/Help";
import Login from "./Component/Pages/Auth/Login/Login";
import Register from "./Component/Pages/Auth/Register/Register";
import Dashboard from "./Component/Pages/Auth/Dashboard/Dashboard";
import ProtectedRoute from "./Component/ProtectedRoute";

const pageVariants = {
  initial: {
    opacity: 0,
    y: 20,
    scale: 0.98,
  },
  in: {
    opacity: 1,
    y: 0,
    scale: 1,
  },
  out: {
    opacity: 0,
    y: -20,
    scale: 0.98,
  },
};

const pageTransition = {
  type: "tween",
  ease: "anticipate",
  duration: 0.4,
};

// Варианты анимации для модального окна
const modalVariants = {
  hidden: {
    opacity: 0,
    scale: 0.8,
    y: -20,
  },
  visible: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: {
      type: "spring",
      damping: 25,
      stiffness: 300,
    },
  },
  exit: {
    opacity: 0,
    scale: 0.8,
    y: 20,
  },
};

// Компонент для анимированных страниц
const AnimatedPage = ({ children }) => {
  return (
    <motion.div
      initial="initial"
      animate="in"
      exit="out"
      variants={pageVariants}
      transition={pageTransition}
      style={{ width: "100%" }}
    >
      {children}
    </motion.div>
  );
};

function App() {
  const location = useLocation();

  const [language, setLanguage] = useState("ru");
  const [activeHeader, setActiveHeader] = useState(true);
  const [activeModal, setActiveModal] = useState(false);

  const [token, setToken] = useState(localStorage.getItem("token"));

  // Скрываем Header и Footer на auth страницах
  const isAuthPage = ["/login", "/register"].includes(location.pathname);

  useEffect(() => {
    if (token) {
      localStorage.setItem("token", token);
    } else {
      localStorage.removeItem("token");
    }
  }, [token]);

  const handleLogout = () => {
    setToken(null);
    localStorage.removeItem("token");
  };

  const toggleLanguage = () => {
    setLanguage((prevLang) => (prevLang === "ru" ? "en" : "ru"));
  };

  return (
    <div className="App">
      {!isAuthPage && (
        <Header
          activeHeader={activeHeader}
          setActiveHeader={setActiveHeader}
          toggleLanguage={toggleLanguage}
          language={language}
          onLogout={handleLogout}
          isAuthenticated={!!token}
        />
      )}

      <AnimatePresence mode="wait">
        <Routes location={location} key={location.pathname}>
          <Route
            path="/"
            element={
              <ProtectedRoute token={token}>
                <AnimatedPage>
                  <Search language={language} />
                </AnimatedPage>
              </ProtectedRoute>
            }
          />
          <Route
            path="/about-tools"
            element={
              <ProtectedRoute token={token}>
                <AnimatedPage>
                  <AboutTools
                    activeModal={activeModal}
                    setActiveModal={setActiveModal}
                    language={language}
                  />
                </AnimatedPage>
              </ProtectedRoute>
            }
          />
          <Route
            path="/analytic"
            element={
              <ProtectedRoute token={token}>
                <AnimatedPage>
                  <Analytic language={language} />
                </AnimatedPage>
              </ProtectedRoute>
            }
          />
          <Route
            path="/help"
            element={
              <ProtectedRoute token={token}>
                <AnimatedPage>
                  <Help language={language} />
                </AnimatedPage>
              </ProtectedRoute>
            }
          />
          <Route
            path="/register"
            element={
              !token ? (
                <AnimatedPage>
                  <Register setToken={setToken} />
                </AnimatedPage>
              ) : (
                <Navigate to="/" replace />
              )
            }
          />
          <Route
            path="/login"
            element={
              !token ? (
                <AnimatedPage>
                  <Login setToken={setToken} />
                </AnimatedPage>
              ) : (
                <Navigate to="/" replace />
              )
            }
          />
          <Route
            path="/dashboard"
            element={
              token ? (
                <AnimatedPage>
                  <Dashboard token={token} onLogout={handleLogout} />
                </AnimatedPage>
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AnimatePresence>

      <AnimatePresence>
        {activeModal && (
          <motion.div
            initial="hidden"
            animate="visible"
            exit="exit"
            variants={modalVariants}
          >
            <Modal
              language={language}
              activeModal={activeModal}
              setActiveModal={setActiveModal}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {!isAuthPage && <Footer language={language} />}
    </div>
  );
}

// Главный компонент с Router
export default function AppWrapper() {
  return (
    <Router>
      <App />
    </Router>
  );
}
