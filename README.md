# 🔍 MetaExtract – Digital Forensic Metadata Analyzer

MetaExtract is a **Digital Forensic Metadata Extraction and Analysis Tool** developed to extract, analyze, and interpret metadata from digital evidence such as images.

The system combines **EXIF metadata extraction, Machine Learning, GPS/location analysis, Reverse Geocoding, Generative AI, and automated forensic report generation** into a single platform.

---

## 🚀 Features

- 📷 Extract EXIF metadata from images
- 📍 Extract GPS coordinates from image metadata
- 🌍 Convert GPS coordinates into readable locations
- 🧠 Machine Learning-based image analysis
- 🌲 Random Forest (RF) model
- 📊 Support Vector Machine (SVM) model
- 🤖 AI-powered forensic analysis using Groq
- 🗺️ Reverse geocoding using OpenCage API
- 🛣️ Location processing using OpenRouteService (ORS)
- 📄 Automated forensic report generation
- 🌐 Spring Boot REST API
- 📤 Image/file upload functionality
- 🐳 Dockerized deployment
- 🔐 Environment-based API key configuration
- 💾 Persistent file storage using Docker volume mapping

---

# 🏗️ System Architecture

```text
                    ┌──────────────────────┐
                    │        User          │
                    │    Web Interface     │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │      MetaExtract     │
                    │     Spring Boot      │
                    │       Port 8081      │
                    └──────────┬───────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
             ▼                 ▼                 ▼
      ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
      │   EXIF      │   │     ML      │   │   Groq AI   │
      │ Extraction  │   │  RF + SVM   │   │   Analysis  │
      └──────┬──────┘   └─────────────┘   └──────┬──────┘
             │                                    │
             ▼                                    │
      ┌─────────────┐                             │
      │ GPS / EXIF  │                             │
      │   Analysis  │                             │
      └──────┬──────┘                             │
             │                                    │
       ┌─────┴──────────────┐                     │
       ▼                    ▼                     ▼
┌───────────────┐   ┌────────────────┐    ┌───────────────┐
│   OpenCage    │   │ OpenRouteService│    │ AI-generated  │
│ Geocoding API │   │      API        │    │   Insights    │
└───────┬───────┘   └───────┬────────┘    └───────┬───────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                    ┌──────────────────────┐
                    │   Forensic Report    │
                    │     Generation       │
                    └──────────────────────┘
```

---

# 🛠️ Technology Stack

## Backend

- Java 17
- Spring Boot 3.2.5
- Spring MVC
- REST APIs
- Maven

## Machine Learning

- Random Forest
- Support Vector Machine (SVM)
- Vision/Image Dataset

## Artificial Intelligence

- Groq API
- AI-assisted forensic analysis
- Automated forensic report generation

## Location Services

- OpenCage Geocoding API
- OpenRouteService (ORS) API

## Frontend

- HTML
- CSS
- JavaScript
- Spring Boot Templates

## DevOps

- Docker
- Multi-stage Docker Build
- Docker Volume

## Tools

- Git
- GitHub
- Docker Desktop
- Postman
- IntelliJ IDEA / VS Code

---

# 📁 Project Structure

```text
metaextract/
│
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── ...
│   │   │
│   │   └── resources/
│   │       ├── static/
│   │       ├── templates/
│   │       ├── dataset.csv
│   │       └── application.properties
│   │
│   └── test/
│
├── lib/
│
├── uploads/
│
├── Dockerfile
├── .dockerignore
├── .gitignore
├── pom.xml
├── README.md
└── .env
```

# 🔄 Complete Application Workflow

```text
                 User
                  │
                  ▼
          Upload Digital Image
                  │
                  ▼
           MetaExtract API
                  │
        ┌─────────┼─────────┐
        │         │         │
        ▼         ▼         ▼
      EXIF       ML       AI Analysis
   Extraction  Analysis    using Groq
        │         │         │
        └─────────┼─────────┘
                  │
                  ▼
          GPS Information
                  │
                  ▼
        OpenCage / ORS APIs
                  │
                  ▼
          Location Analysis
                  │
                  ▼
         Forensic Report
```

---

# 🎯 Use Cases

MetaExtract can be used for:

- Digital forensic investigations
- Image metadata analysis
- Digital evidence examination
- Location identification
- Image analysis
- Automated forensic reporting
- Cybersecurity education
- Digital forensics research

---

# 👨‍💻 Developer

**Grishwar S V**

Bachelor of Engineering – Computer Science and Engineering

Sri Ramakrishna Engineering College

---

# 📜 License

This project is developed for **academic, research, and educational purposes**.

---

# ⭐ Project Highlights

**MetaExtract = Digital Forensics + EXIF Analysis + Machine Learning + Generative AI + Geolocation + Docker**

The project provides an automated platform for extracting metadata, analyzing digital evidence, identifying location information, generating AI-assisted insights, and producing forensic reports.
