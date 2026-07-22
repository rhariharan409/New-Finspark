# Bank of Turtles

Bank of Turtles is a demo banking platform designed to evolve into a behavioral fraud detection and explainable risk analysis system.

## Project Structure

```
Finspark_new_project/
├── package.json               # Application manifest
├── server.js                  # Main server entry point
├── README.md                  # Project overview documentation
├── src/                       # Logical backend modules
│   ├── auth/                  # Authentication module
│   ├── db/                    # Database and data management
│   ├── session/               # Session management
│   ├── telemetry/             # Telemetry & event logging
│   ├── banking/               # Banking operations
│   └── risk/                  # Risk & behavioral fraud engine
└── public/                    # Frontend static assets
    ├── index.html             # Main HTML entry point
    ├── css/                   # Stylesheets
    └── components/            # Shared UI client components
```

## Logical Areas Overview

- **Authentication (`src/auth`)**: Handles user identity verification and credentials.
- **Database (`src/db`)**: Data access layer and database connections.
- **Session Management (`src/session`)**: Manages active user sessions.
- **Telemetry (`src/telemetry`)**: Logs client interaction events and telemetry signals for risk analysis.
- **Banking Operations (`src/banking`)**: Core banking functionality (accounts, transfers).
- **Risk/Fraud Engine (`src/risk`)**: Behavioral analysis and fraud detection scoring.
- **Shared UI Components (`public/components`, `public/css`)**: Client-side interface components and styling.
