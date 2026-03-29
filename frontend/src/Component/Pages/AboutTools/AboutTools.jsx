import React from "react";

import "./AboutTools.scss";

const AboutTools = ({ language, activeModal, setActiveModal }) => {
  return (
    <main className="main main__tools">
      <div className="container">
        <h3 className="h3">
          {language === "ru"
            ? "CyberScope - это мощная веб-платформа для комплексного анализа и разведки веб-сайтов. Автоматизируйте процесс сканирования на уязвимости, обнаружения скрытых каталогов и сбора разведывательной информации в одном интерфейсе."
            : "CyberScope is a powerful web platform for complex analysis and exploration of websites. Automate the process of vulnerability scanning, hidden directory detection, and intelligence gathering in a single interface."}
        </h3>
        <button
          className={activeModal ? "btn active" : "btn"}
          onClick={() => setActiveModal(true)}
        >
          {language === "ru" ? "Предисловие" : "The preface"}
        </button>
      </div>
    </main>
  );
};

export default AboutTools;
