import React, { useState } from "react";
import "./Questions.scss";

const Questions = ({ language }) => {
  const [activeQuestionIndex, setActiveQuestionIndex] = useState(null);

  const questions = [
    {
      title: {
        ru: "1. Как использовать данный инструмент?",
        en: "1. How to use this tool?"
      },
      text: {
        ru: "Для использования инструмента перейдите на главную страницу и введите адрес сайта или ключевое слово в поле поиска. Нажмите кнопку 'Найти', чтобы получить результаты.",
        en: "To use the tool, go to the main page and enter a website address or keyword in the search field. Click the 'Find' button to get results."
      }
    },
    {
      title: {
        ru: "2. Как работает поиск?",
        en: "2. How does the search work?"
      },
      text: {
        ru: "Поиск работает на основе введенных ключевых слов или адреса сайта. Система анализирует данные и предоставляет результаты, соответствующие запросу.",
        en: "The search works based on entered keywords or website address. The system analyzes data and provides results matching the query."
      }
    },
    {
      title: {
        ru: "3. Какие данные можно анализировать?",
        en: "3. What data can be analyzed?"
      },
      text: {
        ru: "Инструмент позволяет анализировать данные веб-сайтов, включая их структуру, ключевые слова и метаинформацию.",
        en: "The tool allows you to analyze website data, including their structure, keywords and meta information."
      }
    },
    {
      title: {
        ru: "4. Как связаться с поддержкой?",
        en: "4. How to contact support?"
      },
      text: {
        ru: "Вы можете связаться с поддержкой через форму обратной связи на сайте или отправить письмо на указанный адрес электронной почты.",
        en: "You can contact support through the feedback form on the website or by sending an email to the specified email address."
      }
    },
  ];

  const toggleQuestion = (index) => {
    setActiveQuestionIndex((prevIndex) => (prevIndex === index ? null : index));
  };

  return (
    <main className="main__question">
      <div className="container">
        <h2 className="main__title-question">
          {language === "ru" ? "Вопросы" : "Questions"}
        </h2>
        <div className="container__question">
          {questions.map((question, index) => (
            <div
              key={index}
              className={`questions__item ${
                activeQuestionIndex === index ? "active" : ""
              }`}
              onClick={() => toggleQuestion(index)}
            >
              <div className="questions__subtitle">
                <h3>{question.title[language] || question.title.en}</h3>
                <button className="btn__vector" />
              </div>
              {activeQuestionIndex === index && (
                <p className="questions__text">
                  {question.text[language] || question.text.en}
                </p>
              )}
            </div>
          ))}
        </div>
      </div>
    </main>
  );
};

export default Questions;