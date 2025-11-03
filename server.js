const express = require('express');
const axios = require('axios');
const { exec } = require('child_process');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const app = express();
const port = 3001;

// Enable CORS for all routes
app.use(cors());
// Increase JSON payload size limit to 50MB
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('public'));
app.use('/src', express.static('src'));

// Route to run Trivy scan
app.post('/run-trivy', (req, res) => {
    const { sourcePath } = req.body;

    if (!sourcePath) {
        return res.status(400).json({ error: 'Source path is required' });
    }
    const outputPath = path.join(__dirname, 'src', 'trivy-report.json');
    const command = `trivy_0.62.1_windows-64bit\\trivy.exe fs "${sourcePath}" --format json --output "${outputPath}"`;

    console.log(`Running command: ${command}`);

    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error: ${error.message}`);
            return res.status(500).json({ error: error.message });
        }

        if (stderr) {
            console.error(`stderr: ${stderr}`);
        }

        try {
            // Try to read the generated file
            const reportData = fs.readFileSync(outputPath, 'utf8');
            const jsonData = JSON.parse(reportData);

            // Create a flag file to indicate a scan has been performed
            const flagPath = path.join(
                __dirname,
                'src',
                '.trivy-scan-performed'
            );
            fs.writeFileSync(flagPath, new Date().toISOString());

            res.json({ success: true, data: jsonData });
        } catch (readError) {
            console.error(`Error reading report: ${readError.message}`);
            res.status(500).json({
                error: `Failed to read report: ${readError.message}`,
            });
        }
    });
});

// Route to run Grype scan
app.post('/run-grype', (req, res) => {
    const { sourcePath } = req.body;

    if (!sourcePath) {
        return res.status(400).json({ error: 'Source path is required' });
    }

    const outputPath = path.join(__dirname, 'src', 'grype-report.json');
    const command = `grype_0.92.0_windows_amd64\\grype.exe dir:"${sourcePath}" -o json > "${outputPath}"`;

    console.log(`Running command: ${command}`);

    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error: ${error.message}`);
            return res.status(500).json({ error: error.message });
        }

        if (stderr) {
            console.error(`stderr: ${stderr}`);
        }
        try {
            // Try to read the generated file
            const reportData = fs.readFileSync(outputPath, 'utf8');
            const jsonData = JSON.parse(reportData);

            // Create a flag file to indicate a scan has been performed
            const flagPath = path.join(
                __dirname,
                'src',
                '.grype-scan-performed'
            );
            fs.writeFileSync(flagPath, new Date().toISOString());

            res.json({ success: true, data: jsonData });
        } catch (readError) {
            console.error(`Error reading report: ${readError.message}`);
            res.status(500).json({
                error: `Failed to read report: ${readError.message}`,
            });
        }
    });
});

// Route to run both Trivy and Grype scans
app.post('/run-both-scans', async (req, res) => {
    const { sourcePath } = req.body;

    if (!sourcePath) {
        return res.status(400).json({ error: 'Source path is required' });
    }

    // Define output paths
    const trivyOutputPath = path.join(__dirname, 'src', 'trivy-report.json');
    const grypeOutputPath = path.join(__dirname, 'src', 'grype-report.json');

    try {
        // Run Trivy scan
        const trivyCommand = `trivy_0.62.1_windows-64bit\\trivy.exe fs "${sourcePath}" --format json --output "${trivyOutputPath}"`;
        console.log(`Running command: ${trivyCommand}`);

        // Run Trivy scan as a promise
        const trivyScanPromise = new Promise((resolve, reject) => {
            exec(trivyCommand, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Trivy error: ${error.message}`);
                    reject(error);
                }
                resolve('Trivy scan completed');
            });
        });

        // Run Grype scan
        const grypeCommand = `grype_0.92.0_windows_amd64\\grype.exe dir:"${sourcePath}" -o json > "${grypeOutputPath}"`;
        console.log(`Running command: ${grypeCommand}`);

        // Run Grype scan as a promise
        const grypeScanPromise = new Promise((resolve, reject) => {
            exec(grypeCommand, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Grype error: ${error.message}`);
                    reject(error);
                }
                resolve('Grype scan completed');
            });
        });

        // Wait for both scans to complete
        await Promise.all([trivyScanPromise, grypeScanPromise]);

        // Read the generated files
        let trivyData, grypeData;
        try {
            const trivyReport = fs.readFileSync(trivyOutputPath, 'utf8');
            trivyData = JSON.parse(trivyReport);
            // Create flag file for trivy scan
            const trivyFlagPath = path.join(
                __dirname,
                'src',
                '.trivy-scan-performed'
            );
            fs.writeFileSync(trivyFlagPath, new Date().toISOString());
        } catch (readError) {
            console.error(`Error reading Trivy report: ${readError.message}`);
            trivyData = {};
        }

        try {
            const grypeReport = fs.readFileSync(grypeOutputPath, 'utf8');
            grypeData = JSON.parse(grypeReport);
            // Create flag file for grype scan
            const grypeFlagPath = path.join(
                __dirname,
                'src',
                '.grype-scan-performed'
            );
            fs.writeFileSync(grypeFlagPath, new Date().toISOString());
        } catch (readError) {
            console.error(`Error reading Grype report: ${readError.message}`);
            grypeData = {};
        }

        res.json({
            success: true,
            trivyData,
            grypeData,
        });
    } catch (error) {
        console.error(`Error running scans: ${error.message}`);
        res.status(500).json({
            error: `Failed to run scans: ${error.message}`,
        });
    }
});

// Get Trivy report
app.get('/api/trivy-report', (req, res) => {
    const filePath = path.join(__dirname, 'src', 'trivy-report.json');
    const scanFlagPath = path.join(__dirname, 'src', '.trivy-scan-performed');

    try {
        // Check if a scan has been performed (flag file exists)
        if (fs.existsSync(scanFlagPath) && fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf8');
            res.json(JSON.parse(data));
        } else {
            res.status(404).json({ error: 'No scan has been performed yet' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get Grype report
app.get('/api/grype-report', (req, res) => {
    const filePath = path.join(__dirname, 'src', 'grype-report.json');
    const scanFlagPath = path.join(__dirname, 'src', '.grype-scan-performed');

    try {
        // Check if a scan has been performed (flag file exists)
        if (fs.existsSync(scanFlagPath) && fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf8');
            res.json(JSON.parse(data));
        } else {
            res.status(404).json({ error: 'No scan has been performed yet' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Endpoint to process combined data with external API

// Endpoint to process combined data with external API
app.post('/process-combined', async (req, res) => {
    try {
        console.log('Processing combined data request...');
        const combinedData = req.body;

        // Log the size of the data being sent
        console.log(
            `Request payload size: ${JSON.stringify(combinedData).length} bytes`
        ); // Set up retry parameters with exponential backoff
        const MAX_RETRIES = 5; // Increase max retries
        const BASE_DELAY_MS = 2000; // Start with 2 seconds
        let retries = 0;
        let lastError = null;

        // Function to make the API call with exponential backoff retry logic
        const makeApiCallWithRetry = async () => {
            try {
                console.log(
                    `API call attempt ${retries + 1} of ${MAX_RETRIES + 1}`
                ); // Configure axios with increased timeout for large requests
                const response = await axios({
                    method: 'post',
                    url: 'https://bgsw-gendigitalhackathon-server-001-dwe6eydrgnbscvbv.eastus-01.azurewebsites.net/api/process_json',
                    data: combinedData,
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    timeout: 180000, // 3-minute timeout (further increased)
                    maxContentLength: 100 * 1024 * 1024, // 100 MB
                    maxBodyLength: 100 * 1024 * 1024, // 100 MB
                    validateStatus: function (status) {
                        // Consider any status other than 2xx as an error
                        return status >= 200 && status < 300;
                    },
                });

                // Check if response contains HTML error message (sometimes errors come back with 200 status)
                const responseData = response.data;
                if (
                    typeof responseData === 'string' &&
                    responseData.includes('<!DOCTYPE HTML>') &&
                    responseData.includes('Error response')
                ) {
                    // This is actually an HTML error response
                    console.error(
                        'Received HTML error response with 200 status code'
                    );

                    // Extract error code if possible
                    let errorCode = 500;
                    if (responseData.includes('Error code: 503')) {
                        errorCode = 503;
                    }

                    throw new Error(
                        `External API returned HTML error with status ${errorCode}`
                    );
                }

                console.log('Successfully received response from external API');
                return responseData;
            } catch (error) {
                lastError = error;

                // Check if error is retriable (server overload or network issues)
                const isRetriable =
                    (error.response &&
                        [503, 502, 504, 429].includes(error.response.status)) ||
                    error.code === 'ECONNRESET' ||
                    error.code === 'ETIMEDOUT';

                if (isRetriable && retries < MAX_RETRIES) {
                    retries++;

                    // Calculate exponential backoff with jitter for better distribution
                    const delayMs = Math.min(
                        30000, // Cap at 30 seconds
                        BASE_DELAY_MS * Math.pow(2, retries - 1) +
                            Math.random() * 1000
                    );

                    console.log(
                        `Retriable error (${
                            error.response?.status || error.code
                        }). Retry #${retries} in ${delayMs.toFixed(0)}ms`
                    );
                    await new Promise((resolve) =>
                        setTimeout(resolve, delayMs)
                    );
                    return await makeApiCallWithRetry(); // Retry recursively
                }

                // If not retriable or we've exceeded max retries, throw the error
                throw error;
            }
        };

        // Make the API call with retry logic
        const responseData = await makeApiCallWithRetry();
        res.json(responseData);
    } catch (error) {
        console.error(`Error processing combined data: ${error.message}`);
        if (error.response) {
            // The request was made and the server responded with a status code
            console.error(`Response status: ${error.response.status}`);
            console.error(
                `Response headers: ${JSON.stringify(error.response.headers)}`
            );

            // If it's a 503 error, return a more specific error message
            if (error.response.status === 503) {
                console.log('External API unavailable (503) after retries.');
                return res.status(503).json({
                    error: 'The AI service is currently overloaded. Please try again later.',
                    details:
                        'After multiple retry attempts, the service is still unavailable.',
                });
            }
        } else if (error.request) {
            // The request was made but no response was received
            console.error('No response received from server');
            return res.status(504).json({
                error: 'Unable to reach the AI service. Please check your connection and try again.',
                details:
                    'The request was made but no response was received from the external service.',
            });
        }

        res.status(500).json({
            error: `Failed to process combined data after retries: ${error.message}`,
        });
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
