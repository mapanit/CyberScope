import React from "react";
import "./Modal.scss";

const Modal = ({ activeModal, setActiveModal, language }) => {
  return (
    <div
      className={activeModal ? "modal active" : "modal"}
      onClick={() => setActiveModal(false)}
    >
      <div
        className={activeModal ? "modal__content active" : "modal__content"}
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="h3">
          {language === "ru"
            ? "Создатель проекта не несет ответственность за использование инструмента, представленных на данном ресурсе"
            : "The creator of the project is not responsible for the use of the tools presented on this resource."}
        </h3>
        <button className="btn" onClick={() => setActiveModal(false)}>
          <span className="line"></span>
          <span className="line"></span>
        </button>
        <div className="content__menu">
          <h4 className="h4">
            {language === "ru"
              ? "Цель предоставления инструментов"
              : "The purpose of providing tools"}
          </h4>
          <span>
            {language === "ru"
              ? " Все материалы и инструменты на сайте предназначены исключительно для ознакомительных, образовательных и этичных целей. Они не должны использоваться для незаконных действий, нарушения конфиденциальности или причинения вреда."
              : "All materials and tools on the site are intended solely for informational, educational and ethical purposes. They should not be used for illegal activities, violation of confidentiality or causing harm."}
          </span>
          <h4 className="h4">
            {language === "ru"
              ? "Соблюдение законодательства"
              : "Compliance with the law"}
          </h4>
          <span>
            {language === "ru"
              ? "Пользователь обязан самостоятельно убедиться, что его действия соответствуют законам страны, в которой он находится. Создатель сайта не контролирует и не отвечает за возможные нарушения со стороны посетителей."
              : "The user must independently verify that his actions comply with the laws of the country in which he is located. The creator of the website does not control and is not responsible for possible violations on the part of visitors."}
          </span>
          <h4 className="h4">
            {language === "ru" ? "Технические риски" : "Technical risks"}
          </h4>
          <span>
            {language === "ru"
              ? "Сайт не гарантирует 100% точность результатов. Данные из открытых источников могут быть устаревшими или ошибочными. Пользователь использует инструменты на свой страх и риск."
              : "The site does not guarantee 100% accuracy of the results. Data from open sources may be outdated or erroneous. The user uses the tools at their own risk."}
          </span>
          <h4 className="h4">
            {language === "ru" ? "Этические нормы" : "Ethical standards"}
          </h4>
          <span>
            {language === "ru"
              ? "Пользователь обязуется использовать инструменты в соответствии с этическими нормами, уважая права и конфиденциальность других лиц."
              : "The user undertakes to use the tools in accordance with ethical standards, respecting the rights and confidentiality of others."}
          </span>
        </div>
      </div>
    </div>
  );
};

export default Modal;
