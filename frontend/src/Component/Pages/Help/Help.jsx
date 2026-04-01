import React from 'react';
import { Link } from "react-router-dom";

import './Help.scss';

const Help = ({ language = "ru" }) => {
  const tools = [
    {
      id: "scanner",
      label: "Scanner",
      info: language === "ru" 
        ? "Проверяет SQL инъекции, XSS, security headers, чувствительные файлы и другие уязвимости" 
        : "Checks for SQL injections, XSS, security headers, sensitive files and other vulnerabilities",
      description: language === "ru"
        ? "Базовый сканер уязвимостей, который проверяет веб-сайты на наличие распространенных проблем безопасности, включая SQL-инъекции, XSS, отсутствующие security headers, чувствительные файлы и конфигурации SSL/TLS."
        : "A basic vulnerability scanner that checks websites for common security issues, including SQL injections, XSS, missing security headers, sensitive files and SSL/TLS configurations."
    },
    {
      id: "nuclei",
      label: "Nuclei",
      info: language === "ru"
        ? "Быстрое сканирование на основе YAML шаблонов для выявления CVE"
        : "Fast scanning based on YAML templates for CVE discovery",
      description: language === "ru"
        ? "Мощный фреймворк для тестирования безопасности, использующий предопределенные YAML-шаблоны для выявления известных уязвимостей (CVE), технологических ошибок и проблем конфигурации."
        : "A powerful security testing framework using predefined YAML templates to identify known vulnerabilities (CVE), technology errors and configuration issues."
    },
    {
      id: "whatweb",
      label: "WhatWeb",
      info: language === "ru"
        ? "Идентификация веб-серверов, CMS, аналитики и плагинов"
        : "Identification of web servers, CMS, analytics and plugins",
      description: language === "ru"
        ? "Специализированный сканер для идентификации веб-технологий, включая веб-серверы, системы управления контентом, системы аналитики, CRM и другие приложения на целевом сайте."
        : "A specialized scanner for identifying web technologies, including web servers, content management systems, analytics systems, CRM and other applications on the target site."
    },
    {
      id: "whois",
      label: "WhoIS",
      info: language === "ru"
        ? "Получение информации о регистрации и владельце домена"
        : "Retrieval of domain registration and owner information",
      description: language === "ru"
        ? "Утилита для получения информации о регистрации доменных имен, включая данные о владельце, регистраре, дате регистрации, сроках действия и контактной информации."
        : "A utility for retrieving domain registration information, including owner data, registrar, registration date, expiration dates and contact details."
    },
    {
      id: "amass",
      label: "Amass",
      info: language === "ru"
        ? "Перечисление поддоменов через поиск в открытых источниках"
        : "Subdomain enumeration through open source search",
      description: language === "ru"
        ? "Мощный инструмент для перечисления поддоменов, использующий множество открытых источников данных, включая DNS, SSL сертификаты, поисковые системы и другие каналы разведки."
        : "A powerful tool for subdomain enumeration using multiple open data sources, including DNS, SSL certificates, search engines and other reconnaissance channels."
    },
    {
      id: "katana",
      label: "Katana",
      info: language === "ru"
        ? "Глубокое краулирование сайта для поиска скрытых путей и API"
        : "Deep site crawling to find hidden paths and APIs",
      description: language === "ru"
        ? "Современный инструмент для глубокого краулирования веб-сайтов, способный обнаруживать скрытые пути, конечные точки API, JavaScript файлы, параметры и другие компоненты приложения."
        : "A modern tool for deep web crawling capable of discovering hidden paths, API endpoints, JavaScript files, parameters and other application components."
    },
    {
      id: "subfinder",
      label: "Subfinder",
      info: language === "ru"
        ? "Пассивное перечисление поддоменов из множества источников"
        : "Passive subdomain enumeration from multiple sources",
      description: language === "ru"
        ? "Быстрый и мощный утилита для пассивного перечисления поддоменов, использующая различные источники данных, включая сертификаты SSL, поисковые системы, API и другие каналы разведки без прямого взаимодействия с целевым сервером."
        : "A fast and powerful utility for passive subdomain enumeration using various data sources, including SSL certificates, search engines, APIs and other reconnaissance channels without direct target server interaction."
    },
    {
      id: "waybackreport",
      label: "Wayback Report",
      info: language === "ru"
        ? "Анализ архивных данных сайта для поиска старых путей и файлов"
        : "Analysis of archived site data to find old paths and files",
      description: language === "ru"
        ? "Инструмент для анализа данных из Wayback Machine (Internet Archive), позволяющий обнаруживать исторические версии сайта, удаленные страницы, старые API endpoints и файлы, которые могут содержать чувствительную информацию."
        : "A tool for analyzing Wayback Machine (Internet Archive) data, allowing you to discover historical site versions, deleted pages, old API endpoints and files that may contain sensitive information."
    },
    {
      id: "jsfinder",
      label: "JSFinder",
      info: language === "ru"
        ? "Поиск URL и поддоменов в JavaScript файлах"
        : "Search for URLs and subdomains in JavaScript files",
      description: language === "ru"
        ? "Специализированный инструмент для анализа JavaScript файлов и извлечения скрытых URL, API endpoints, поддоменов и других конечных точек, которые часто содержат ценную информацию о структуре приложения."
        : "A specialized tool for analyzing JavaScript files and extracting hidden URLs, API endpoints, subdomains and other endpoints that often contain valuable information about application structure."
    },
    {
      id: "gobuster",
      label: "Gobuster",
      info: language === "ru"
        ? "Брутфорс директорий и файлов на веб-сервере"
        : "Brute force directories and files on a web server",
      description: language === "ru"
        ? "Мощный и быстрый сканер для перебора директорий, файлов и доменов на веб-серверах, использующий параллельные потоки для эффективного поиска скрытых путей и ресурсов, которые не индексируются поисковыми системами."
        : "A powerful and fast scanner for enumerating directories, files and domains on web servers using parallel threads for efficient discovery of hidden paths and resources not indexed by search engines."
    },
    {
      id: "nmap",
      label: "Nmap",
      info: language === "ru"
        ? "Сканирование портов и определение сервисов на целевом хосте"
        : "Port scanning and service detection on target host",
      description: language === "ru"
        ? "Универсальный инструмент для исследования сетей и аудита безопасности, позволяющий сканировать открытые порты, определять версии сервисов, обнаруживать операционную систему и выявлять потенциальные уязвимости на сетевом уровне."
        : "A universal tool for network exploration and security audit, allowing you to scan open ports, detect service versions, discover the operating system and identify potential network-level vulnerabilities."
    },
    {
      id: "wappalyzer",
      label: "Wappalyzer",
      info: language === "ru"
        ? "Идентификация используемых веб-технологий и приложений"
        : "Identification of web technologies and applications in use",
      description: language === "ru"
        ? "Интеллектуальный анализатор для определения технологий, используемых на веб-сайтах, включая фреймворки, библиотеки, аналитику, CMS, серверное ПО, языки программирования и другие компоненты технологического стека."
        : "An intelligent analyzer for determining technologies used on websites, including frameworks, libraries, analytics, CMS, server software, programming languages and other components of the technology stack."
    }
  ];

  return (
    <main className="help__page">
      <div className="container">
        <div className="block__help">
          <h1 className="help__title">{language === "ru" ? "Помощь и Поддержка" : "Help & Support"}</h1>
          <Link to="/" className="about__tools-link">{language === "ru" ? "Обратно" : "Back"}</Link>
        </div>

        <div className="help__tools-grid">
          {tools.map((tool) => (
            <div key={tool.id} className="help__tool-card">
              <div className="tool-card-header">
                <h3 className="tool-card-title">{tool.label}</h3>
                <span className="tool-card-id">{tool.id}</span>
              </div>
              <p className="tool-card-short">{tool.info}</p>
              <p className="tool-card-description">{tool.description}</p>
            </div>
          ))}
        </div>

        <section className="help__section">
          <h2 className="help__subtitle">
            {language === "ru" ? "Как использовать инструменты?" : "How to use the tools?"}
          </h2>
          <div className="help__instructions">
            <ol>
              <li>
                {language === "ru" 
                  ? "Выберите один или несколько инструментов из доступного списка" 
                  : "Select one or more tools from the available list"}
              </li>
              <li>
                {language === "ru" 
                  ? "Введите URL целевого сайта в поле поиска" 
                  : "Enter the target website URL in the search field"}
              </li>
              <li>
                {language === "ru" 
                  ? "Нажмите кнопку \"начать\" для запуска сканирования" 
                  : "Click the \"Start\" button to run the scan"}
              </li>
              <li>
                {language === "ru" 
                  ? "Дождитесь завершения сканирования" 
                  : "Wait for the scan to complete"}
              </li>
              <li>
                {language === "ru" 
                  ? "Просмотрите результаты и скачайте отчет в формате DOCX если необходимо" 
                  : "View the results and download the report in DOCX format if needed"}
              </li>
            </ol>
          </div>
        </section>

        <section className="help__section">
          <h2 className="help__subtitle">
            {language === "ru" ? "Советы по безопасности" : "Security Tips"}
          </h2>
          <div className="help__tips">
            <ul>
              <li>
                <strong>
                  {language === "ru" ? "Отмена сканирования:" : "Cancel Scanning:"}
                </strong> 
                {" "}
                {language === "ru" 
                  ? "Вы можете отменить текущее сканирование, нажав кнопку \"Отменить\"" 
                  : "You can cancel the current scan by clicking the \"Cancel\" button"}
              </li>
              <li>
                <strong>
                  {language === "ru" ? "Время сканирования:" : "Scan Time:"}
                </strong> 
                {" "}
                {language === "ru" 
                  ? "Полное сканирование может занять некоторое время в зависимости от размера сайта" 
                  : "A full scan may take some time depending on the size of the website"}
              </li>
              <li>
                <strong>
                  {language === "ru" ? "Требуется разрешение:" : "Permission Required:"}
                </strong> 
                {" "}
                {language === "ru" 
                  ? "Сканируйте только сайты, на которые у вас есть письменное разрешение" 
                  : "Scan only websites that you have written permission to scan"}
              </li>
            </ul>
          </div>
        </section>
      </div>
    </main>
  );
};

export default Help;