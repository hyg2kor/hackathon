# Vulnerability Scanner UI

This application provides a user interface for scanning source code with Trivy and Grype to identify security vulnerabilities.

## Features

-   Scan source code directly from the UI using Trivy and Grype
-   View vulnerabilities by severity level
-   Sort and filter vulnerabilities
-   Create a fix priority list for vulnerabilities
-   View detailed information about each vulnerability including CVSS scores and references
-   Generate combined AI-enhanced reports for deeper vulnerability analysis
-   Browse file system to select source code directories
-   Empty state by default - shows data only when scans are performed

## Setup Instructions

### Prerequisites

1. Node.js (v14 or later)
2. Trivy and Grype executables (included in the project)

### Installation

1. Install dependencies:

    ```
    npm install
    ```

2. Start both frontend and backend:

    ```
    npm run dev
    ```

    Or use the included batch file:

    ```
    start.bat
    ```

3. Access the application at [http://localhost:3000](http://localhost:3000)

### Using the Application

1. Enter the path to your source code directory in the "Source Code Path" field
2. Click "Run Trivy Scan" or "Run Grype Scan" to analyze the code
3. View and filter the results
4. Add important vulnerabilities to the Fix Priority List for tracking

## API Endpoints

The backend server exposes the following endpoints:

-   `POST /run-trivy` - Run a Trivy scan on a directory
-   `POST /run-grype` - Run a Grype scan on a directory
-   `GET /api/trivy-report` - Get the latest Trivy scan report
-   `GET /api/grype-report` - Get the latest Grype scan report

## Architecture

The application consists of:

1. **Frontend**: React application with Material-UI components
2. **Backend**: Express server that executes Trivy and Grype commands and serves the results

## Command Reference

Trivy command:

```
trivy_0.62.1_windows-64bit\trivy.exe fs <SOURCE_PATH> --format json --output trivy-report.json
```

Grype command:

```
grype_0.92.0_windows_amd64\grype.exe dir:<SOURCE_PATH> -o json > outputs/grype-report.json
```

## Learn More

You can learn more in the [Create React App documentation](https://facebook.github.io/create-react-app/docs/getting-started).

To learn React, check out the [React documentation](https://reactjs.org/).

### Code Splitting

This section has moved here: [https://facebook.github.io/create-react-app/docs/code-splitting](https://facebook.github.io/create-react-app/docs/code-splitting)

### Analyzing the Bundle Size

This section has moved here: [https://facebook.github.io/create-react-app/docs/analyzing-the-bundle-size](https://facebook.github.io/create-react-app/docs/analyzing-the-bundle-size)

### Making a Progressive Web App

This section has moved here: [https://facebook.github.io/create-react-app/docs/making-a-progressive-web-app](https://facebook.github.io/create-react-app/docs/making-a-progressive-web-app)

### Advanced Configuration

This section has moved here: [https://facebook.github.io/create-react-app/docs/advanced-configuration](https://facebook.github.io/create-react-app/docs/advanced-configuration)

### Deployment

This section has moved here: [https://facebook.github.io/create-react-app/docs/deployment](https://facebook.github.io/create-react-app/docs/deployment)

### `npm run build` fails to minify

This section has moved here: [https://facebook.github.io/create-react-app/docs/troubleshooting#npm-run-build-fails-to-minify](https://facebook.github.io/create-react-app/docs/troubleshooting#npm-run-build-fails-to-minify)
