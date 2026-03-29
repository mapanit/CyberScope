import React from "react";
import "./Task.scss";

const Task = ({ language }) => {
  return (
    <main className="main">
      <div className="container">
        <h2 className="h2">
          {language === "ru"
            ? "Цель проекта: реализовать проект по поиску информации о сайте с помощью различных инструментов и технологий, обеспечивая удобный интерфейс для пользователей."
            : "The purpose of the project: to implement a project to search for information about a website using various tools and technologies, providing a user-friendly interface."}
        </h2>
        <span className="span">
          {language === "ru"
            ? "Сканируйте с умом. Защищайте с уверенностью."
            : "Scan wisely. Defend with confidence."}
        </span>
      </div>
    </main>
  );
};

export default Task;
