import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
    Container,
    Typography,
    Card,
    CardContent,
    CardActions,
    Button,
    Collapse,
    Table,
    TableBody,
    TableRow,
    TableCell,
    Link,
    Chip,
    Box,
    ButtonGroup,
    Paper,
    TableHead,
    TableContainer,
    Select,
    MenuItem,
    FormControl,
    InputLabel,
    Grid,
    Badge,
    Alert,
    Skeleton,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import SecurityIcon from '@mui/icons-material/Security';
import CompareArrowsIcon from '@mui/icons-material/CompareArrows';
import BugReportIcon from '@mui/icons-material/BugReport';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import InfoIcon from '@mui/icons-material/Info';
import PriorityHighIcon from '@mui/icons-material/PriorityHigh';
import FileDownloadIcon from '@mui/icons-material/FileDownload';

// No longer needed - we'll get this data from the API
// import combinedData from './combined-report.json';

const getSeverityColor = (severity) => {
    severity = severity.toLowerCase();
    switch (severity) {
        case 'critical':
            return '#7B1FA2'; // Purple
        case 'high':
            return '#C62828'; // Red
        case 'medium':
            return '#EF6C00'; // Orange
        case 'low':
            return '#FFC107'; // Amber
        default:
            return '#78909C'; // Blue Grey
    }
};

const getSeverityIcon = (severity) => {
    severity = severity.toLowerCase();
    switch (severity) {
        case 'critical':
            return <ErrorIcon fontSize="small" />;
        case 'high':
            return <PriorityHighIcon fontSize="small" />;
        case 'medium':
            return <WarningIcon fontSize="small" />;
        case 'low':
            return <InfoIcon fontSize="small" />;
        default:
            return <InfoIcon fontSize="small" />;
    }
};

export default function CR1() {
    const [expandedIndex, setExpandedIndex] = useState(null);
    const [filterSeverity, setFilterSeverity] = useState('ALL');
    const [currentData, setCurrentData] = useState({});
    const [dataSource, setDataSource] = useState('trivy');
    const [vulnerabilitiesToFix, setVulnerabilitiesToFix] = useState([]);
    const [sortBy, setSortBy] = useState('severity');
    const [sourcePath, setSourcePath] = useState('');
    const [isScanning, setIsScanning] = useState(false);
    const [scanMessage, setScanMessage] = useState('');
    const [dataLoaded, setDataLoaded] = useState(false);
    const [trivyReport, setTrivyReport] = useState(null);
    const [grypeReport, setGrypeReport] = useState(null);
    const [combinedReport, setCombinedReport] = useState(null);
    const [loadingProgress, setLoadingProgress] = useState(0);
    const getVulnerabilities = (data, source) => {
        if (!data) {
            console.warn(`No data available for source: ${source}`);
            return [];
        }

        try {
            if (source === 'trivy') {
                // Check if Results exists and is an array
                if (data.Results && Array.isArray(data.Results)) {
                    // Collect vulnerabilities from all results entries
                    let allVulnerabilities = [];

                    // Iterate through all Results entries
                    for (let i = 0; i < data.Results.length; i++) {
                        const result = data.Results[i];
                        if (result && Array.isArray(result.Vulnerabilities)) {
                            allVulnerabilities = [
                                ...allVulnerabilities,
                                ...result.Vulnerabilities,
                            ];
                        }
                    }

                    return allVulnerabilities;
                }
                return [];
            } else if (source === 'grype') {
                return Array.isArray(data.matches) ? data.matches : [];
            } else if (source === 'combined') {
                // Check various possible locations for vulnerability data
                if (data && Array.isArray(data)) {
                    return data;
                }

                // Last resort: look for any array property
                for (const key in data) {
                    if (Array.isArray(data[key]) && data[key].length > 0) {
                        console.log(
                            `Found potential vulnerability array in key: ${key}`
                        );
                        return data[key];
                    }
                }
            }
        } catch (error) {
            console.error(
                `Error extracting vulnerabilities for ${source}:`,
                error
            );
        }

        return [];
    }; // Get key vulnerability properties based on data source
    const getVulnerabilityProps = (vuln, source) => {
        if (source === 'trivy') {
            return {
                id: vuln.VulnerabilityID,
                packageName: vuln.PkgName,
                packageVersion: vuln.InstalledVersion,
                severity: vuln.Severity,
                description: vuln.Description || vuln.Title,
                fixVersions: vuln.FixedVersion ? [vuln.FixedVersion] : [],
                references: vuln.References || [],
                dataSource: vuln.DataSource ? vuln.DataSource.Name : 'Unknown',
                cvss: vuln.CVSS,
            };
        } else if (source === 'grype') {
            return {
                id: vuln.vulnerability ? vuln.vulnerability.id : 'Unknown',
                packageName: vuln.artifact ? vuln.artifact.name : 'Unknown',
                packageVersion: vuln.artifact
                    ? vuln.artifact.version
                    : 'Unknown',
                severity: vuln.vulnerability
                    ? vuln.vulnerability.severity
                    : 'Unknown',
                description: vuln.vulnerability
                    ? vuln.vulnerability.description
                    : 'No description',
                fixVersions:
                    vuln.vulnerability && vuln.vulnerability.fix
                        ? vuln.vulnerability.fix.versions || []
                        : [],
                references: vuln.vulnerability
                    ? vuln.vulnerability.urls || []
                    : [],
                dataSource: vuln.vulnerability
                    ? vuln.vulnerability.dataSource
                    : 'Unknown',
                cvss: vuln.vulnerability ? vuln.vulnerability.cvss : null,
                risk: vuln.vulnerability ? vuln.vulnerability.risk : 0,
            };
        } else if (source === 'combined') {
            // Handle the response from the external API
            // This structure may need to be adjusted based on the actual API response
            return {
                id:
                    vuln.id ||
                    vuln.VulnerabilityID ||
                    vuln.vulnerability_id ||
                    'Unknown',
                packageName:
                    vuln.package_name || vuln.PkgName || vuln.name || 'Unknown',
                packageVersion:
                    vuln.package_version ||
                    vuln.version ||
                    vuln.InstalledVersion ||
                    '',
                severity: vuln.severity || vuln.Severity || 'Unknown',
                description:
                    vuln.description ||
                    vuln.Description ||
                    vuln.message ||
                    'No description available',
                fixVersions: vuln.fix_versions ? [vuln.fix_versions] : [],
                references:
                    vuln.references || vuln.References || vuln.urls || [],
                dataSource: 'AI Combined Analysis',
                cvss: vuln.cvss || vuln.CVSS || null,
                risk: vuln.risk || vuln.Risk || 0,
                aiSuggestion: vuln.ai_suggestion || vuln.recommendation || '',
                priority: vuln.priority || 'Medium',
                cvss_score:
                    vuln.cvss_score ||
                    vuln['cvss score'] ||
                    vuln.CVSS_Score ||
                    null,
                epss_score:
                    vuln.epss_score ||
                    vuln['epss score'] ||
                    vuln.EPSS_Score ||
                    null,
                baseScore: vuln.baseScore,
                exploitabilityScore: vuln.exploitabilityScore,
                impactScore: vuln.impactScore,
                V3Vector: vuln.V3Vector,
            };
        }
        return {};
    };

    // Get all vulnerabilities
    const results = getVulnerabilities(currentData, dataSource);
    // Filter results based on severity
    const filteredResults =
        filterSeverity === 'ALL'
            ? results
            : results.filter((vuln) => {
                  if (dataSource === 'trivy') {
                      return (
                          vuln.Severity &&
                          vuln.Severity.toUpperCase() === filterSeverity
                      );
                  } else if (dataSource === 'grype') {
                      return (
                          vuln.vulnerability &&
                          vuln.vulnerability.severity &&
                          vuln.vulnerability.severity.toUpperCase() ===
                              filterSeverity
                      );
                  } else if (dataSource === 'combined') {
                      return (
                          (vuln.severity &&
                              vuln.severity.toUpperCase() === filterSeverity) ||
                          (vuln.Severity &&
                              vuln.Severity.toUpperCase() === filterSeverity)
                      );
                  }
                  return false;
              });
    // Sort results
    const sortedResults = [...filteredResults].sort((a, b) => {
        const getProperty = (item, prop) => {
            if (dataSource === 'trivy') {
                if (prop === 'severity') {
                    const severityOrder = {
                        CRITICAL: 4,
                        HIGH: 3,
                        MEDIUM: 2,
                        LOW: 1,
                        UNKNOWN: 0,
                    };
                    return severityOrder[item.Severity?.toUpperCase()] || 0;
                }
                return item[prop] || '';
            } else if (dataSource === 'grype') {
                if (prop === 'severity') {
                    const severityOrder = {
                        CRITICAL: 4,
                        HIGH: 3,
                        MEDIUM: 2,
                        LOW: 1,
                        UNKNOWN: 0,
                    };
                    return (
                        severityOrder[
                            item.vulnerability?.severity?.toUpperCase()
                        ] || 0
                    );
                } else if (prop === 'risk') {
                    return item.vulnerability?.risk || 0;
                }
                return (
                    item.vulnerability?.[prop] || item.artifact?.[prop] || ''
                );
            } else if (dataSource === 'combined') {
                if (prop === 'severity') {
                    const severityOrder = {
                        CRITICAL: 4,
                        HIGH: 3,
                        MEDIUM: 2,
                        LOW: 1,
                        UNKNOWN: 0,
                    };
                    return (
                        severityOrder[
                            (item.severity || item.Severity)?.toUpperCase()
                        ] || 0
                    );
                }
                return item[prop] || '';
            }
            return '';
        };

        const valueA = getProperty(a, sortBy);
        const valueB = getProperty(b, sortBy);

        if (sortBy === 'severity' || sortBy === 'risk') {
            return valueB - valueA; // Higher severity/risk first
        }

        // Default string comparison
        if (typeof valueA === 'string' && typeof valueB === 'string') {
            return valueA.localeCompare(valueB);
        }

        return 0;
    });

    // Group vulnerabilities by package
    const vulnerabilitiesByPackage = {};
    sortedResults.forEach((vuln) => {
        const props = getVulnerabilityProps(vuln, dataSource);
        const key = props.packageName;

        if (!vulnerabilitiesByPackage[key]) {
            vulnerabilitiesByPackage[key] = [];
        }
        vulnerabilitiesByPackage[key].push(vuln);
    });

    const toggleExpand = (index) => {
        setExpandedIndex(expandedIndex === index ? null : index);
    };

    const isInFixList = (id) => {
        return vulnerabilitiesToFix.some((v) => v.id === id);
    };

    // function to run Trivy scan
    const runTrivyScan = async () => {
        if (!sourcePath.trim()) {
            setScanMessage('Please enter a valid source code path');
            return;
        }

        setIsScanning(true);
        setScanMessage('Running Trivy scan...');

        try {
            // Call our backend API to run Trivy
            const response = await axios.post(
                'http://localhost:3001/run-trivy',
                {
                    sourcePath,
                }
            );

            if (response.data.success) {
                // Set the data directly from the response
                setCurrentData(response.data.data);
                setDataSource('trivy');
                setDataLoaded(true);
                setScanMessage('Trivy scan completed successfully');
            } else {
                throw new Error(response.data.error || 'Unknown error');
            }
        } catch (error) {
            setScanMessage(`Error running Trivy scan: ${error.message}`);
            console.error('Trivy scan error:', error);
        } finally {
            setIsScanning(false);
        }
    };

    // function to run Grype scan
    const runGrypeScan = async () => {
        if (!sourcePath.trim()) {
            setScanMessage('Please enter a valid source code path');
            return;
        }

        setIsScanning(true);
        setScanMessage('Running Grype scan...');

        try {
            // Call our backend API to run Grype
            const response = await axios.post(
                'http://localhost:3001/run-grype',
                {
                    sourcePath,
                }
            );

            if (response.data.success) {
                // Set the data directly from the response
                setCurrentData(response.data.data);
                setDataSource('grype');
                setDataLoaded(true);
                setScanMessage('Grype scan completed successfully');
            } else {
                throw new Error(response.data.error || 'Unknown error');
            }
        } catch (error) {
            setScanMessage(`Error running Grype scan: ${error.message}`);
            console.error('Grype scan error:', error);
        } finally {
            setIsScanning(false);
        }
    };

    // function to run both scans simultaneously
    const runBothScans = async () => {
        if (!sourcePath.trim()) {
            setScanMessage('Please enter a valid source code path');
            return;
        }

        setIsScanning(true);
        setScanMessage('Running both Trivy and Grype scans...');

        try {
            // Call our backend API to run both scans
            const response = await axios.post(
                'http://localhost:3001/run-both-scans',
                {
                    sourcePath,
                }
            );

            if (response.data.success) {
                // Store both reports in state
                setTrivyReport(response.data.trivyData);
                setGrypeReport(response.data.grypeData);

                // Set the current data to Trivy by default
                setCurrentData(response.data.trivyData);
                setDataSource('trivy');
                setDataLoaded(true);
                setScanMessage('Both scans completed successfully');
            } else {
                throw new Error(response.data.error || 'Unknown error');
            }
        } catch (error) {
            setScanMessage(`Error running scans: ${error.message}`);
            console.error('Scan error:', error);
        } finally {
            setIsScanning(false);
        }
    };

    // Function to generate combined report from API
    const generateCombinedReport = async () => {
        // Make sure we have both reports
        if (!trivyReport || !grypeReport) {
            setScanMessage(
                'Run both scans first before generating a combined report'
            );
            return;
        }
        setIsScanning(true);
        setScanMessage('Generating combined vulnerability report...');

        // Set the data source to combined right away to show the right view
        setDataSource('combined');
        // Clear current data and hide any old vulnerabilities while loading
        setCurrentData({});
        setDataLoaded(false);

        try {
            const combinedReportData = {
                trivy: trivyReport,
                grype: grypeReport,
            };

            // Call our LOCAL proxy endpoint instead of the Azure endpoint directly
            setScanMessage(
                'Sending data to AI analysis service... This may take a few minutes.'
            );
            try {
                console.log('Sending request to our local proxy endpoint');
                const response = await axios.post(
                    'https://bgsw-gendigitalhackathon-server-001-dwe6eydrgnbscvbv.eastus-01.azurewebsites.net/api/cr1',
                    combinedReportData,
                    {
                        timeout: 600000, // 10 minute timeout (in ms)
                        maxContentLength: Infinity,
                        maxBodyLength: Infinity,
                    }
                );

                // Check if the response is an HTML error message that got returned with a 200 status
                const responseData = response.data;
                if (
                    typeof responseData === 'string' &&
                    responseData.includes('<!DOCTYPE HTML>') &&
                    responseData.includes('Error response')
                ) {
                    throw new Error(
                        'AI service returned an HTML error response: Service unavailable (503)'
                    );
                }

                // Store in combinedReport state
                setCombinedReport(responseData);

                // Update current data and data source
                setCurrentData(responseData);
                setDataSource('combined');
                setDataLoaded(true);

                // Check if this is a fallback report

                setScanMessage('Combined report generated successfully');
            } catch (error) {
                console.error('API service error:', error);
                // No fallback: just show error and do not set combined report
                if (error.response) {
                    if (error.response.status === 503) {
                        setScanMessage(
                            'AI service is busy (503). Please try again later.'
                        );
                    } else {
                        setScanMessage(
                            `AI service error (${error.response.status}). Please try again later.`
                        );
                    }
                } else if (error.code === 'ECONNABORTED') {
                    setScanMessage(
                        'Request timed out. The AI service may be experiencing high load. Please try again later.'
                    );
                } else {
                    setScanMessage(`AI service error: ${error.message}`);
                }

                // Keep the combined view active even after error
                setDataSource('combined');
                setDataLoaded(false);
            }
        } catch (error) {
            setScanMessage(`Error preparing report data: ${error.message}`);
            console.error('Error preparing combined report:', error);
        } finally {
            setIsScanning(false);
        }
    };

    // Modify the changeDataSource function to use stored report data
    const changeDataSource = (source) => {
        setDataSource(source);
        setExpandedIndex(null);

        // First clear current data to prevent showing data from previous view
        setCurrentData({});
        setDataLoaded(false); // Ensure we're not showing any data until we explicitly set it

        if (source === 'trivy') {
            if (trivyReport) {
                // Use the already loaded trivy report data
                setCurrentData(trivyReport);
                setDataLoaded(true);
                setScanMessage('Loaded cached Trivy scan results');
            } else {
                // Don't try to load results automatically, just show empty state
                setScanMessage(
                    'No Trivy scan has been performed yet. Please upload a Trivy file.'
                );
            }
        } else if (source === 'grype') {
            if (grypeReport) {
                // Use the already loaded grype report data
                setCurrentData(grypeReport);
                setDataLoaded(true);
                setScanMessage('Loaded cached Grype scan results');
            } else {
                // Don't try to load results automatically, just show empty state
                setScanMessage(
                    'No Grype scan has been performed yet. Please upload a Grype file.'
                );
            }
        } else if (source === 'combined') {
            if (combinedReport) {
                // Use the already generated combined report
                console.log('Using cached combined report data');
                setCurrentData(combinedReport);
                setDataLoaded(true);
                setScanMessage('Loaded cached combined report');
            } else if (trivyReport && grypeReport) {
                if (isScanning) {
                    // If still processing, show loading message
                    setScanMessage(
                        'Sending data to AI analysis service... This may take a few minutes.'
                    );
                } else {
                    // Prompt to generate combined report only if not scanning
                    setScanMessage(
                        "Please click 'Generate AI Combined Report' to create the combined report."
                    );
                }
            } else {
                setScanMessage(
                    'Run both scans or upload both reports first to enable combined report view.'
                );
            }
        }
    };

    // Modify the countBySeverity function to count unique packages instead of individual vulnerabilities
    const countBySeverity = (severity) => {
        // Create a Set to track unique package names with this severity
        const uniquePackagesWithSeverity = new Set();

        results.forEach((vuln) => {
            let hasMatchingSeverity = false;

            if (dataSource === 'trivy') {
                hasMatchingSeverity =
                    vuln.Severity && vuln.Severity.toUpperCase() === severity;
                if (hasMatchingSeverity)
                    uniquePackagesWithSeverity.add(vuln.VulnerabilityID);
            } else if (dataSource === 'grype') {
                hasMatchingSeverity =
                    vuln.vulnerability &&
                    vuln.vulnerability.severity &&
                    vuln.vulnerability.severity.toUpperCase() === severity;
                if (hasMatchingSeverity)
                    uniquePackagesWithSeverity.add(vuln.vulnerability.id);
            } else if (dataSource === 'combined') {
                hasMatchingSeverity =
                    (vuln.severity &&
                        vuln.severity.toUpperCase() === severity) ||
                    (vuln.Severity && vuln.Severity.toUpperCase() === severity);
                if (hasMatchingSeverity)
                    uniquePackagesWithSeverity.add(
                        vuln.VulnerabilityID || 'Unknown'
                    );
            }
        });

        return uniquePackagesWithSeverity.size;
    };

    const addToFixList = (vuln) => {
        // Skip if already in list
        if (isInFixList(vuln.id)) return;

        // Add the vulnerability to the list with basic info
        const props = getVulnerabilityProps(vuln, dataSource);
        setVulnerabilitiesToFix([...vulnerabilitiesToFix, props]);
    };

    const removeFromFixList = (id) => {
        setVulnerabilitiesToFix(
            vulnerabilitiesToFix.filter((v) => v.id !== id)
        );
    };

    // Function to download the combined report as JSON
    const downloadCombinedReport = () => {
        if (!combinedReport) return;

        // Create a JSON string from the combined report data
        const jsonString = JSON.stringify(combinedReport, null, 2);

        // Create a blob
        const blob = new Blob([jsonString], { type: 'application/json' });

        // Create a download link
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'combined-vulnerability-report.json';

        // Append the link to the body, click it, and remove it
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        // Clean up the URL object
        URL.revokeObjectURL(url);
    };

    return (
        <Container maxWidth="lg" sx={{ py: 4 }}>
            <Box
                sx={{
                    display: 'flex',
                    alignItems: 'center',
                    mb: 3,
                    background:
                        'linear-gradient(90deg, #1a237e 0%, #3949ab 100%)',
                    borderRadius: '8px',
                    p: 3,
                    boxShadow: 3,
                }}
            >
                <SecurityIcon sx={{ fontSize: 42, color: 'white', mr: 2 }} />
                <Typography
                    variant="h3"
                    sx={{
                        fontWeight: 700,
                        color: 'white',
                        letterSpacing: '0.5px',
                        textShadow: '1px 1px 2px rgba(0,0,0,0.3)',
                    }}
                >
                    Vulnerability Scanner
                </Typography>
            </Box>{' '}
            {/* Source code path input and scan buttons */}
            <Paper
                elevation={3}
                sx={{
                    mb: 4,
                    p: 4,
                    borderRadius: '12px',
                    background: 'linear-gradient(145deg, #ffffff, #f9f9f9)',
                    boxShadow: '0 8px 30px rgba(0,0,0,0.12)',
                }}
            >
                <Typography
                    variant="h6"
                    sx={{ mb: 3, fontWeight: 600, color: '#333' }}
                >
                    Upload Vulnerability Reports
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                    <Box
                        sx={{
                            display: 'flex',
                            gap: 3,
                            flexWrap: 'wrap',
                            justifyContent: 'center',
                        }}
                    >
                        <Button
                            variant="outlined"
                            component="label"
                            color="primary"
                            sx={{
                                py: 1.5,
                                px: 3,
                                borderRadius: '8px',
                                borderWidth: '2px',
                                fontWeight: 600,
                                transition: 'all 0.3s ease',
                                '&:hover': {
                                    transform: 'translateY(-3px)',
                                    boxShadow: 3,
                                    borderWidth: '2px',
                                },
                            }}
                            startIcon={<SecurityIcon />}
                        >
                            Upload Trivy File
                            <input
                                type="file"
                                accept="application/json"
                                hidden
                                onChange={async (e) => {
                                    if (e.target.files && e.target.files[0]) {
                                        const file = e.target.files[0];
                                        const text = await file.text();
                                        // Parse the Trivy file and automatically switch to Trivy tab
                                        try {
                                            const data = JSON.parse(text);
                                            setTrivyReport(data);
                                            // Always switch to trivy view when uploading a trivy file
                                            setDataSource('trivy');
                                            setCurrentData(data);
                                            setDataLoaded(true);
                                            setScanMessage(
                                                'Trivy report uploaded successfully'
                                            );
                                        } catch (err) {
                                            setScanMessage(
                                                'Invalid Trivy JSON file'
                                            );
                                        }
                                    }
                                }}
                            />
                        </Button>

                        <Button
                            variant="outlined"
                            component="label"
                            color="secondary"
                            sx={{
                                py: 1.5,
                                px: 3,
                                borderRadius: '8px',
                                borderWidth: '2px',
                                fontWeight: 600,
                                transition: 'all 0.3s ease',
                                '&:hover': {
                                    transform: 'translateY(-3px)',
                                    boxShadow: 3,
                                    borderWidth: '2px',
                                },
                            }}
                            startIcon={<BugReportIcon />}
                        >
                            Upload Grype File
                            <input
                                type="file"
                                accept="application/json"
                                hidden
                                onChange={async (e) => {
                                    if (e.target.files && e.target.files[0]) {
                                        const file = e.target.files[0];
                                        const text = await file.text();
                                        try {
                                            const data = JSON.parse(text);
                                            setGrypeReport(data);
                                            // Always switch to grype view when uploading a grype file
                                            setDataSource('grype');
                                            setCurrentData(data);
                                            setDataLoaded(true);
                                            setScanMessage(
                                                'Grype report uploaded successfully'
                                            );
                                        } catch (err) {
                                            setScanMessage(
                                                'Invalid Grype JSON file'
                                            );
                                        }
                                    }
                                }}
                            />
                        </Button>

                        <Button
                            variant="contained"
                            color="info"
                            onClick={generateCombinedReport}
                            disabled={
                                isScanning || !trivyReport || !grypeReport
                            }
                            sx={{
                                flexGrow: 1,
                                py: 1.5,
                                borderRadius: '8px',
                                fontWeight: 600,
                                boxShadow: 2,
                                transition: 'all 0.3s ease',
                                background:
                                    'linear-gradient(45deg, #3f51b5 30%, #1a237e 90%)',
                                '&:hover': {
                                    transform: 'translateY(-3px)',
                                    boxShadow: 4,
                                },
                                '&.Mui-disabled': {
                                    background: '#e0e0e0',
                                },
                            }}
                            startIcon={<CompareArrowsIcon />}
                        >
                            Generate AI Combined Report
                        </Button>
                    </Box>
                    {scanMessage && (
                        <Alert
                            severity={
                                scanMessage.includes('Error') ? 'error' : 'info'
                            }
                            sx={{
                                mt: 2,
                                borderRadius: '8px',
                                boxShadow: '0 2px 10px rgba(0,0,0,0.08)',
                                '& .MuiAlert-icon': {
                                    fontSize: '1.5rem',
                                },
                            }}
                            variant="filled"
                        >
                            {scanMessage}
                        </Alert>
                    )}
                </Box>
            </Paper>
            {/* Data source selection */}
            <Paper
                elevation={3}
                sx={{
                    mb: 4,
                    p: 3,
                    display: 'inline-block',
                    borderRadius: '12px',
                    background: 'linear-gradient(145deg, #f0f0f0, #ffffff)',
                    boxShadow: '0 4px 20px rgba(0,0,0,0.08)',
                }}
            >
                <Typography
                    variant="h6"
                    sx={{ mb: 2, fontWeight: 600, color: '#1a237e' }}
                >
                    Select Data Source
                </Typography>
                <ButtonGroup
                    variant="contained"
                    size="large"
                    aria-label="data source selection"
                    sx={{ boxShadow: 2 }}
                >
                    <Button
                        startIcon={<SecurityIcon />}
                        onClick={() => changeDataSource('trivy')}
                        color={dataSource === 'trivy' ? 'primary' : 'inherit'}
                        sx={{
                            fontWeight: 'bold',
                            padding: '10px 20px',
                            bgcolor:
                                dataSource === 'trivy'
                                    ? undefined
                                    : 'rgba(0,0,0,0.05)',
                            color:
                                dataSource === 'trivy'
                                    ? undefined
                                    : 'text.primary',
                            transition: 'all 0.3s ease',
                            '&:hover': {
                                transform: 'translateY(-2px)',
                                boxShadow: 2,
                            },
                        }}
                    >
                        Trivy
                    </Button>
                    <Button
                        startIcon={<BugReportIcon />}
                        onClick={() => changeDataSource('grype')}
                        color={dataSource === 'grype' ? 'primary' : 'inherit'}
                        sx={{
                            fontWeight: 'bold',
                            padding: '10px 20px',
                            bgcolor:
                                dataSource === 'grype'
                                    ? undefined
                                    : 'rgba(0,0,0,0.05)',
                            color:
                                dataSource === 'grype'
                                    ? undefined
                                    : 'text.primary',
                            transition: 'all 0.3s ease',
                            '&:hover': {
                                transform: 'translateY(-2px)',
                                boxShadow: 2,
                            },
                        }}
                    >
                        Grype
                    </Button>
                    <Button
                        startIcon={<CompareArrowsIcon />}
                        onClick={() => {
                            if (trivyReport && grypeReport) {
                                if (combinedReport || isScanning) {
                                    // Allow switching to AI Combined if report exists OR is being generated
                                    changeDataSource('combined');
                                } else {
                                    // Do NOT auto-generate. Just show a message.
                                    setScanMessage(
                                        "Please click 'Generate AI Combined Report' to create the combined report."
                                    );
                                }
                            } else {
                                setScanMessage(
                                    'Run both scans or upload both reports first to enable combined report view.'
                                );
                            }
                        }}
                        color={
                            dataSource === 'combined' ? 'primary' : 'inherit'
                        }
                        disabled={!trivyReport || !grypeReport}
                        sx={{
                            fontWeight: 'bold',
                            padding: '10px 20px',
                            bgcolor:
                                dataSource === 'combined'
                                    ? undefined
                                    : 'rgba(0,0,0,0.05)',
                            color:
                                dataSource === 'combined'
                                    ? undefined
                                    : 'text.primary',
                            transition: 'all 0.3s ease',
                            '&:hover': {
                                transform: 'translateY(-2px)',
                                boxShadow: 2,
                            },
                        }}
                    >
                        AI Combined
                    </Button>
                </ButtonGroup>
            </Paper>{' '}
            <Typography
                variant="subtitle1"
                color="text.secondary"
                sx={{
                    mb: 3,
                    fontSize: '1.1rem',
                    p: 2,
                    backgroundColor: 'rgba(0,0,0,0.03)',
                    borderRadius: '8px',
                    display: 'inline-block',
                }}
            >
                Data Source:{' '}
                <strong style={{ color: '#1a237e' }}>
                    {dataSource.toUpperCase()}
                </strong>
            </Typography>{' '}
            {/* AI Combined loading widget */}
            {isScanning && dataSource === 'combined' && (
                <Alert
                    severity="info"
                    variant="filled"
                    sx={{
                        mb: 3,
                        display: 'flex',
                        alignItems: 'center',
                        gap: 2,
                        fontSize: '1.1rem',
                        borderRadius: '8px',
                        boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                    }}
                >
                    <Box>
                        <strong>Generating AI Combined Report...</strong>
                        <br />
                        This may take some time. Please sit back and relax while
                        we analyze your vulnerabilities!
                    </Box>
                </Alert>
            )}{' '}
            {/* Summary statistics */}
            {dataSource === 'combined' && isScanning ? (
                // Show skeletons while generating combined report
                <Box sx={{ mb: 4 }}>
                    <Typography
                        variant="h6"
                        sx={{ mb: 2, fontWeight: 600, color: '#333' }}
                    >
                        Vulnerability Summary
                    </Typography>
                    <Grid container spacing={3}>
                        {['critical', 'high', 'medium', 'low'].map(
                            (sev, idx) => (
                                <Grid item xs={12} md={3} key={sev}>
                                    <Paper
                                        elevation={4}
                                        sx={{
                                            p: 3,
                                            backgroundImage: `linear-gradient(135deg, ${getSeverityColor(
                                                sev
                                            )} 0%, ${getSeverityColor(
                                                sev
                                            )}AA 100%)`,
                                            color: 'white',
                                            borderRadius: '12px',
                                            transform: 'translateY(0)',
                                            transition:
                                                'transform 0.3s ease, box-shadow 0.3s ease',
                                        }}
                                    >
                                        <Box
                                            sx={{
                                                display: 'flex',
                                                alignItems: 'center',
                                                mb: 1,
                                            }}
                                        >
                                            {sev === 'critical' && (
                                                <ErrorIcon sx={{ mr: 1 }} />
                                            )}
                                            {sev === 'high' && (
                                                <PriorityHighIcon
                                                    sx={{ mr: 1 }}
                                                />
                                            )}
                                            {sev === 'medium' && (
                                                <WarningIcon sx={{ mr: 1 }} />
                                            )}
                                            {sev === 'low' && (
                                                <InfoIcon sx={{ mr: 1 }} />
                                            )}
                                            <Typography
                                                variant="h6"
                                                sx={{
                                                    fontWeight: 700,
                                                    textTransform: 'capitalize',
                                                }}
                                            >
                                                {sev}
                                            </Typography>
                                        </Box>
                                        <Box
                                            sx={{
                                                display: 'flex',
                                                alignItems: 'center',
                                                height: 48,
                                            }}
                                        >
                                            <span style={{ width: '100%' }}>
                                                <Skeleton
                                                    variant="text"
                                                    animation="wave"
                                                    height={40}
                                                    width={60}
                                                    sx={{
                                                        bgcolor:
                                                            'rgba(255,255,255,0.4)',
                                                        borderRadius: 2,
                                                    }}
                                                />
                                            </span>
                                        </Box>
                                    </Paper>
                                </Grid>
                            )
                        )}
                    </Grid>
                </Box>
            ) : (
                dataLoaded &&
                results.length > 0 && (
                    <Box sx={{ mb: 4 }}>
                        <Typography
                            variant="h6"
                            sx={{ mb: 2, fontWeight: 600, color: '#333' }}
                        >
                            Vulnerability Summary
                        </Typography>
                        <Grid container spacing={3}>
                            <Grid item xs={12} md={3}>
                                <Paper
                                    elevation={4}
                                    sx={{
                                        p: 3,
                                        backgroundImage: `linear-gradient(135deg, ${getSeverityColor(
                                            'critical'
                                        )} 0%, ${getSeverityColor(
                                            'critical'
                                        )}AA 100%)`,
                                        color: 'white',
                                        borderRadius: '12px',
                                        transform: 'translateY(0)',
                                        transition:
                                            'transform 0.3s ease, box-shadow 0.3s ease',
                                        '&:hover': {
                                            transform: 'translateY(-5px)',
                                            boxShadow:
                                                '0 12px 20px rgba(0,0,0,0.2)',
                                        },
                                    }}
                                >
                                    <Box
                                        sx={{
                                            display: 'flex',
                                            alignItems: 'center',
                                            mb: 1,
                                        }}
                                    >
                                        <ErrorIcon sx={{ mr: 1 }} />
                                        <Typography
                                            variant="h6"
                                            sx={{ fontWeight: 700 }}
                                        >
                                            Critical
                                        </Typography>
                                    </Box>
                                    <Typography
                                        variant="h3"
                                        sx={{ fontWeight: 700 }}
                                    >
                                        {countBySeverity('CRITICAL')}
                                    </Typography>
                                </Paper>
                            </Grid>
                            <Grid item xs={12} md={3}>
                                <Paper
                                    elevation={4}
                                    sx={{
                                        p: 3,
                                        backgroundImage: `linear-gradient(135deg, ${getSeverityColor(
                                            'high'
                                        )} 0%, ${getSeverityColor(
                                            'high'
                                        )}AA 100%)`,
                                        color: 'white',
                                        borderRadius: '12px',
                                        transform: 'translateY(0)',
                                        transition:
                                            'transform 0.3s ease, box-shadow 0.3s ease',
                                        '&:hover': {
                                            transform: 'translateY(-5px)',
                                            boxShadow:
                                                '0 12px 20px rgba(0,0,0,0.2)',
                                        },
                                    }}
                                >
                                    <Box
                                        sx={{
                                            display: 'flex',
                                            alignItems: 'center',
                                            mb: 1,
                                        }}
                                    >
                                        <PriorityHighIcon sx={{ mr: 1 }} />
                                        <Typography
                                            variant="h6"
                                            sx={{ fontWeight: 700 }}
                                        >
                                            High
                                        </Typography>
                                    </Box>
                                    <Typography
                                        variant="h3"
                                        sx={{ fontWeight: 700 }}
                                    >
                                        {countBySeverity('HIGH')}
                                    </Typography>
                                </Paper>
                            </Grid>
                            <Grid item xs={12} md={3}>
                                <Paper
                                    elevation={4}
                                    sx={{
                                        p: 3,
                                        backgroundImage: `linear-gradient(135deg, ${getSeverityColor(
                                            'medium'
                                        )} 0%, ${getSeverityColor(
                                            'medium'
                                        )}AA 100%)`,
                                        color: 'white',
                                        borderRadius: '12px',
                                        transform: 'translateY(0)',
                                        transition:
                                            'transform 0.3s ease, box-shadow 0.3s ease',
                                        '&:hover': {
                                            transform: 'translateY(-5px)',
                                            boxShadow:
                                                '0 12px 20px rgba(0,0,0,0.2)',
                                        },
                                    }}
                                >
                                    <Box
                                        sx={{
                                            display: 'flex',
                                            alignItems: 'center',
                                            mb: 1,
                                        }}
                                    >
                                        <WarningIcon sx={{ mr: 1 }} />
                                        <Typography
                                            variant="h6"
                                            sx={{ fontWeight: 700 }}
                                        >
                                            Medium
                                        </Typography>
                                    </Box>
                                    <Typography
                                        variant="h3"
                                        sx={{ fontWeight: 700 }}
                                    >
                                        {countBySeverity('MEDIUM')}
                                    </Typography>
                                </Paper>
                            </Grid>
                            <Grid item xs={12} md={3}>
                                <Paper
                                    elevation={4}
                                    sx={{
                                        p: 3,
                                        backgroundImage: `linear-gradient(135deg, ${getSeverityColor(
                                            'low'
                                        )} 0%, ${getSeverityColor(
                                            'low'
                                        )}AA 100%)`,
                                        color: 'white',
                                        borderRadius: '12px',
                                        transform: 'translateY(0)',
                                        transition:
                                            'transform 0.3s ease, box-shadow 0.3s ease',
                                        '&:hover': {
                                            transform: 'translateY(-5px)',
                                            boxShadow:
                                                '0 12px 20px rgba(0,0,0,0.2)',
                                        },
                                    }}
                                >
                                    <Box
                                        sx={{
                                            display: 'flex',
                                            alignItems: 'center',
                                            mb: 1,
                                        }}
                                    >
                                        <InfoIcon sx={{ mr: 1 }} />
                                        <Typography
                                            variant="h6"
                                            sx={{ fontWeight: 700 }}
                                        >
                                            Low
                                        </Typography>
                                    </Box>
                                    <Typography
                                        variant="h3"
                                        sx={{ fontWeight: 700 }}
                                    >
                                        {countBySeverity('LOW')}
                                    </Typography>
                                </Paper>
                            </Grid>
                        </Grid>{' '}
                    </Box>
                )
            )}
            {/* Controls */}
            {dataLoaded && results.length > 0 && (
                <Paper
                    elevation={2}
                    sx={{
                        mb: 4,
                        p: 3,
                        borderRadius: '12px',
                        background: 'linear-gradient(145deg, #ffffff, #f7f7f7)',
                    }}
                >
                    <Typography
                        variant="h6"
                        sx={{ mb: 2, fontWeight: 600, color: '#333' }}
                    >
                        Filter Options
                    </Typography>
                    <Box
                        sx={{
                            display: 'flex',
                            gap: 3,
                            alignItems: 'center',
                            flexWrap: 'wrap',
                        }}
                    >
                        <FormControl sx={{ minWidth: 220 }}>
                            <InputLabel id="severity-filter-label">
                                Filter by Severity
                            </InputLabel>
                            <Select
                                labelId="severity-filter-label"
                                value={filterSeverity}
                                onChange={(e) =>
                                    setFilterSeverity(e.target.value)
                                }
                                label="Filter by Severity"
                                sx={{
                                    borderRadius: '8px',
                                    '& .MuiOutlinedInput-notchedOutline': {
                                        borderColor: '#1a237e33',
                                    },
                                }}
                            >
                                <MenuItem value="ALL">All Severities</MenuItem>
                                <MenuItem value="CRITICAL">Critical</MenuItem>
                                <MenuItem value="HIGH">High</MenuItem>
                                <MenuItem value="MEDIUM">Medium</MenuItem>
                                <MenuItem value="LOW">Low</MenuItem>
                            </Select>
                        </FormControl>
                        <FormControl sx={{ minWidth: 220 }}>
                            <InputLabel id="sort-by-label">Sort By</InputLabel>
                            <Select
                                labelId="sort-by-label"
                                value={sortBy}
                                onChange={(e) => setSortBy(e.target.value)}
                                label="Sort By"
                                sx={{
                                    borderRadius: '8px',
                                    '& .MuiOutlinedInput-notchedOutline': {
                                        borderColor: '#1a237e33',
                                    },
                                }}
                            >
                                <MenuItem value="severity">Severity</MenuItem>
                                {dataSource === 'grype' && (
                                    <MenuItem value="risk">Risk Score</MenuItem>
                                )}
                                <MenuItem value="id">Vulnerability ID</MenuItem>
                                <MenuItem value="packageName">
                                    Package Name
                                </MenuItem>
                            </Select>
                        </FormControl>{' '}
                        <Badge
                            badgeContent={vulnerabilitiesToFix.length}
                            color="error"
                            sx={{
                                '& .MuiBadge-badge': {
                                    fontWeight: 'bold',
                                    fontSize: '0.9rem',
                                },
                            }}
                        >
                            <Button
                                variant="contained"
                                color="primary"
                                onClick={() => {
                                    const element =
                                        document.getElementById('fix-list');
                                    if (element)
                                        element.scrollIntoView({
                                            behavior: 'smooth',
                                        });
                                }}
                                disabled={vulnerabilitiesToFix.length === 0}
                                sx={{
                                    borderRadius: '8px',
                                    py: 1.2,
                                    px: 3,
                                    fontWeight: 600,
                                    background:
                                        vulnerabilitiesToFix.length > 0
                                            ? 'linear-gradient(45deg, #1a237e 30%, #3949ab 90%)'
                                            : undefined,
                                    boxShadow:
                                        vulnerabilitiesToFix.length > 0
                                            ? '0 3px 10px rgba(0,0,0,0.2)'
                                            : undefined,
                                    transition: 'all 0.3s ease',
                                    '&:hover': {
                                        transform: 'translateY(-2px)',
                                        boxShadow: '0 6px 15px rgba(0,0,0,0.2)',
                                    },
                                }}
                                startIcon={<SecurityIcon />}
                            >
                                View Fix List
                            </Button>
                        </Badge>
                        {/* Download Combined Report Button */}
                        {combinedReport && dataSource === 'combined' && (
                            <Button
                                variant="contained"
                                color="primary"
                                onClick={downloadCombinedReport}
                                sx={{
                                    ml: 'auto', // Push to the right end
                                    py: 1.2,
                                    px: 3,
                                    borderRadius: '8px',
                                    fontWeight: 600,
                                    boxShadow: 2,
                                    transition: 'all 0.3s ease',

                                    '&:hover': {
                                        transform: 'translateY(-2px)',
                                        boxShadow: '0 6px 15px rgba(0,0,0,0.2)',
                                    },
                                }}
                                startIcon={<FileDownloadIcon />}
                            >
                                Download Combined JSON
                            </Button>
                        )}
                    </Box>{' '}
                </Paper>
            )}{' '}
            {/* Results count and vulnerabilities list */}
            {dataLoaded && results.length > 0 ? (
                <>
                    <Typography variant="body2" sx={{ mb: 2 }}>
                        Showing {filteredResults.length} of {results.length}{' '}
                        vulnerabilities
                    </Typography>

                    {/* Display vulnerabilities by package */}
                    {Object.entries(vulnerabilitiesByPackage).map(
                        ([packageName, vulns], packageIndex) => (
                            <Card
                                key={packageIndex}
                                sx={{ mb: 2, boxShadow: 3 }}
                            >
                                <CardContent sx={{ pb: 0 }}>
                                    <Typography
                                        variant="h6"
                                        sx={{ fontWeight: 600 }}
                                    >
                                        {packageName}
                                        {vulns.length > 1 && (
                                            <Chip
                                                label={vulns.length}
                                                size="small"
                                                sx={{ ml: 1 }}
                                                color="primary"
                                            />
                                        )}
                                    </Typography>
                                    <Box
                                        sx={{
                                            mt: 1,
                                            display: 'flex',
                                            flexWrap: 'wrap',
                                            gap: 1,
                                        }}
                                    >
                                        {vulns.map((vuln, i) => {
                                            const props = getVulnerabilityProps(
                                                vuln,
                                                dataSource
                                            );
                                            return (
                                                <Chip
                                                    key={i}
                                                    icon={getSeverityIcon(
                                                        props.severity
                                                    )}
                                                    label={props.id}
                                                    sx={{
                                                        backgroundColor:
                                                            getSeverityColor(
                                                                props.severity
                                                            ),
                                                        color: 'white',
                                                        fontWeight: 'bold',
                                                    }}
                                                    onClick={() =>
                                                        toggleExpand(
                                                            packageIndex +
                                                                '-' +
                                                                i
                                                        )
                                                    }
                                                />
                                            );
                                        })}
                                    </Box>
                                </CardContent>

                                {vulns.map((vuln, i) => {
                                    const props = getVulnerabilityProps(
                                        vuln,
                                        dataSource
                                    );
                                    const isExpanded =
                                        expandedIndex ===
                                        packageIndex + '-' + i;

                                    return (
                                        <React.Fragment key={i}>
                                            <CardActions>
                                                <Button
                                                    startIcon={
                                                        isExpanded ? (
                                                            <ExpandLessIcon />
                                                        ) : (
                                                            <ExpandMoreIcon />
                                                        )
                                                    }
                                                    onClick={() =>
                                                        toggleExpand(
                                                            packageIndex +
                                                                '-' +
                                                                i
                                                        )
                                                    }
                                                    sx={{
                                                        textTransform: 'none',
                                                    }}
                                                >
                                                    {props.id} ({props.severity}
                                                    )
                                                </Button>
                                                <Box sx={{ ml: 'auto' }}>
                                                    {isInFixList(props.id) ? (
                                                        <Button
                                                            size="small"
                                                            variant="outlined"
                                                            color="error"
                                                            onClick={() =>
                                                                removeFromFixList(
                                                                    props.id
                                                                )
                                                            }
                                                        >
                                                            Remove from Fix List
                                                        </Button>
                                                    ) : (
                                                        <Button
                                                            size="small"
                                                            variant="outlined"
                                                            color="primary"
                                                            onClick={() =>
                                                                addToFixList(
                                                                    vuln
                                                                )
                                                            }
                                                        >
                                                            Add to Fix List
                                                        </Button>
                                                    )}
                                                </Box>
                                            </CardActions>

                                            <Collapse
                                                in={isExpanded}
                                                timeout="auto"
                                                unmountOnExit
                                            >
                                                <CardContent>
                                                    <TableContainer
                                                        component={Paper}
                                                        variant="outlined"
                                                        sx={{ mb: 2 }}
                                                    >
                                                        <Table size="small">
                                                            <TableBody>
                                                                <TableRow>
                                                                    <TableCell
                                                                        component="th"
                                                                        sx={{
                                                                            fontWeight:
                                                                                'bold',
                                                                            width: '30%',
                                                                        }}
                                                                    >
                                                                        Vulnerability
                                                                    </TableCell>
                                                                    <TableCell>
                                                                        {
                                                                            props.id
                                                                        }
                                                                    </TableCell>
                                                                </TableRow>
                                                                <TableRow>
                                                                    <TableCell
                                                                        component="th"
                                                                        sx={{
                                                                            fontWeight:
                                                                                'bold',
                                                                        }}
                                                                    >
                                                                        Package
                                                                    </TableCell>
                                                                    <TableCell>
                                                                        {
                                                                            props.packageName
                                                                        }{' '}
                                                                        {props.packageVersion &&
                                                                            `(${props.packageVersion})`}
                                                                    </TableCell>
                                                                </TableRow>
                                                                <TableRow>
                                                                    <TableCell
                                                                        component="th"
                                                                        sx={{
                                                                            fontWeight:
                                                                                'bold',
                                                                        }}
                                                                    >
                                                                        Severity
                                                                    </TableCell>
                                                                    <TableCell>
                                                                        <Chip
                                                                            label={
                                                                                props.severity
                                                                            }
                                                                            size="small"
                                                                            sx={{
                                                                                backgroundColor:
                                                                                    getSeverityColor(
                                                                                        props.severity
                                                                                    ),
                                                                                color: 'white',
                                                                                fontWeight:
                                                                                    'bold',
                                                                            }}
                                                                        />
                                                                    </TableCell>
                                                                </TableRow>
                                                                {dataSource ===
                                                                    'grype' &&
                                                                    props.risk !==
                                                                        undefined && (
                                                                        <TableRow>
                                                                            <TableCell
                                                                                component="th"
                                                                                sx={{
                                                                                    fontWeight:
                                                                                        'bold',
                                                                                }}
                                                                            >
                                                                                Risk
                                                                                Score
                                                                            </TableCell>
                                                                            <TableCell>
                                                                                {props.risk.toFixed(
                                                                                    6
                                                                                )}
                                                                            </TableCell>
                                                                        </TableRow>
                                                                    )}
                                                                <TableRow>
                                                                    <TableCell
                                                                        component="th"
                                                                        sx={{
                                                                            fontWeight:
                                                                                'bold',
                                                                        }}
                                                                    >
                                                                        Fixed
                                                                        Versions
                                                                    </TableCell>
                                                                    <TableCell>
                                                                        {props.fixVersions &&
                                                                        props
                                                                            .fixVersions
                                                                            .length >
                                                                            0
                                                                            ? props.fixVersions.join(
                                                                                  ', '
                                                                              )
                                                                            : 'No fix available'}
                                                                    </TableCell>
                                                                </TableRow>
                                                                <TableRow>
                                                                    <TableCell
                                                                        component="th"
                                                                        sx={{
                                                                            fontWeight:
                                                                                'bold',
                                                                        }}
                                                                    >
                                                                        Description
                                                                    </TableCell>
                                                                    <TableCell>
                                                                        {props.description ||
                                                                            'No description available'}
                                                                    </TableCell>
                                                                </TableRow>
                                                                <TableRow>
                                                                    <TableCell
                                                                        component="th"
                                                                        sx={{
                                                                            fontWeight:
                                                                                'bold',
                                                                        }}
                                                                    >
                                                                        Data
                                                                        Source
                                                                    </TableCell>
                                                                    <TableCell>
                                                                        {
                                                                            props.dataSource
                                                                        }
                                                                    </TableCell>
                                                                </TableRow>
                                                                <TableRow>
                                                                    <TableCell
                                                                        component="th"
                                                                        sx={{
                                                                            fontWeight:
                                                                                'bold',
                                                                        }}
                                                                    >
                                                                        epss
                                                                        score
                                                                    </TableCell>
                                                                    <TableCell>
                                                                        {props.epss_score ||
                                                                            'NA'}
                                                                    </TableCell>
                                                                </TableRow>
                                                                <TableRow>
                                                                    <TableCell
                                                                        component="th"
                                                                        sx={{
                                                                            fontWeight:
                                                                                'bold',
                                                                        }}
                                                                    >
                                                                        cvss
                                                                        score
                                                                    </TableCell>
                                                                    <TableCell>
                                                                        {props.cvss_score ||
                                                                            'NA'}
                                                                    </TableCell>
                                                                </TableRow>
                                                                <TableRow>
                                                                    <TableCell
                                                                        component="th"
                                                                        sx={{
                                                                            fontWeight:
                                                                                'bold',
                                                                        }}
                                                                    >
                                                                        Base
                                                                        Score
                                                                    </TableCell>
                                                                    <TableCell>
                                                                        {props.baseScore ||
                                                                            'NA'}
                                                                    </TableCell>
                                                                </TableRow>
                                                                <TableRow>
                                                                    <TableCell
                                                                        component="th"
                                                                        sx={{
                                                                            fontWeight:
                                                                                'bold',
                                                                        }}
                                                                    >
                                                                        Exploitability
                                                                        Score
                                                                    </TableCell>
                                                                    <TableCell>
                                                                        {props.exploitabilityScore ||
                                                                            'NA'}
                                                                    </TableCell>
                                                                </TableRow>
                                                                <TableRow>
                                                                    <TableCell
                                                                        component="th"
                                                                        sx={{
                                                                            fontWeight:
                                                                                'bold',
                                                                        }}
                                                                    >
                                                                        Impact
                                                                        Score
                                                                    </TableCell>
                                                                    <TableCell>
                                                                        {props.impactScore ||
                                                                            'NA'}
                                                                    </TableCell>
                                                                </TableRow>
                                                                <TableRow>
                                                                    <TableCell
                                                                        component="th"
                                                                        sx={{
                                                                            fontWeight:
                                                                                'bold',
                                                                        }}
                                                                    >
                                                                        V3
                                                                        Vector
                                                                    </TableCell>
                                                                    <TableCell>
                                                                        {props.V3Vector ||
                                                                            'NA'}
                                                                    </TableCell>
                                                                </TableRow>
                                                            </TableBody>
                                                        </Table>
                                                    </TableContainer>

                                                    {/* CVSS score if available */}
                                                    {props.cvss &&
                                                        Object.keys(props.cvss)
                                                            .length > 0 && (
                                                            <React.Fragment>
                                                                <Typography
                                                                    variant="subtitle1"
                                                                    gutterBottom
                                                                >
                                                                    CVSS Scores
                                                                </Typography>
                                                                <TableContainer
                                                                    component={
                                                                        Paper
                                                                    }
                                                                    variant="outlined"
                                                                    sx={{
                                                                        mb: 2,
                                                                    }}
                                                                >
                                                                    <Table size="small">
                                                                        <TableHead>
                                                                            <TableRow>
                                                                                <TableCell>
                                                                                    Source
                                                                                </TableCell>
                                                                                <TableCell>
                                                                                    Score
                                                                                </TableCell>
                                                                                <TableCell>
                                                                                    Vector
                                                                                </TableCell>
                                                                            </TableRow>
                                                                        </TableHead>
                                                                        <TableBody>
                                                                            {Object.entries(
                                                                                props.cvss
                                                                            ).map(
                                                                                ([
                                                                                    source,
                                                                                    data,
                                                                                ]) => (
                                                                                    <TableRow
                                                                                        key={
                                                                                            source
                                                                                        }
                                                                                    >
                                                                                        <TableCell>
                                                                                            {
                                                                                                source
                                                                                            }
                                                                                        </TableCell>
                                                                                        <TableCell>
                                                                                            {data.V3Score ||
                                                                                                'N/A'}
                                                                                        </TableCell>
                                                                                        <TableCell>
                                                                                            {data.V3Vector ||
                                                                                                'N/A'}
                                                                                        </TableCell>
                                                                                    </TableRow>
                                                                                )
                                                                            )}
                                                                        </TableBody>
                                                                    </Table>
                                                                </TableContainer>
                                                            </React.Fragment>
                                                        )}

                                                    {/* References if available */}
                                                    {props.references &&
                                                        props.references
                                                            .length > 0 && (
                                                            <React.Fragment>
                                                                <Typography
                                                                    variant="subtitle1"
                                                                    gutterBottom
                                                                >
                                                                    References
                                                                </Typography>
                                                                <Box
                                                                    sx={{
                                                                        maxHeight:
                                                                            '200px',
                                                                        overflow:
                                                                            'auto',
                                                                        mb: 2,
                                                                    }}
                                                                >
                                                                    <ul
                                                                        style={{
                                                                            paddingLeft:
                                                                                '20px',
                                                                        }}
                                                                    >
                                                                        {props.references.map(
                                                                            (
                                                                                ref,
                                                                                i
                                                                            ) => (
                                                                                <li
                                                                                    key={
                                                                                        i
                                                                                    }
                                                                                >
                                                                                    <Link
                                                                                        href={
                                                                                            ref
                                                                                        }
                                                                                        target="_blank"
                                                                                        rel="noopener noreferrer"
                                                                                        sx={{
                                                                                            wordBreak:
                                                                                                'break-all',
                                                                                        }}
                                                                                    >
                                                                                        {
                                                                                            ref
                                                                                        }
                                                                                    </Link>
                                                                                </li>
                                                                            )
                                                                        )}
                                                                    </ul>
                                                                </Box>

                                                                {/* AI Suggestion from Combined Report */}
                                                                {dataSource ===
                                                                    'combined' &&
                                                                    props.aiSuggestion && (
                                                                        <React.Fragment>
                                                                            <Typography
                                                                                variant="subtitle1"
                                                                                sx={{
                                                                                    fontWeight:
                                                                                        'bold',
                                                                                    mt: 2,
                                                                                    mb: 1,
                                                                                    color: 'primary.main',
                                                                                }}
                                                                            >
                                                                                AI
                                                                                Recommendation
                                                                            </Typography>
                                                                            <Paper
                                                                                variant="outlined"
                                                                                sx={{
                                                                                    p: 2,
                                                                                    backgroundColor:
                                                                                        'rgba(25, 118, 210, 0.04)',
                                                                                    mb: 2,
                                                                                }}
                                                                            >
                                                                                <Typography variant="body2">
                                                                                    {
                                                                                        props.aiSuggestion
                                                                                    }
                                                                                </Typography>
                                                                            </Paper>

                                                                            {props.priority && (
                                                                                <Box
                                                                                    sx={{
                                                                                        display:
                                                                                            'flex',
                                                                                        alignItems:
                                                                                            'center',
                                                                                        mb: 2,
                                                                                    }}
                                                                                >
                                                                                    <Typography
                                                                                        variant="body2"
                                                                                        sx={{
                                                                                            mr: 1,
                                                                                        }}
                                                                                    >
                                                                                        Recommended
                                                                                        Priority:
                                                                                    </Typography>
                                                                                    <Chip
                                                                                        label={
                                                                                            props.priority
                                                                                        }
                                                                                        size="small"
                                                                                        color={
                                                                                            props.priority ===
                                                                                            'High'
                                                                                                ? 'error'
                                                                                                : props.priority ===
                                                                                                  'Medium'
                                                                                                ? 'warning'
                                                                                                : 'info'
                                                                                        }
                                                                                    />
                                                                                </Box>
                                                                            )}
                                                                        </React.Fragment>
                                                                    )}
                                                            </React.Fragment>
                                                        )}
                                                </CardContent>
                                            </Collapse>
                                        </React.Fragment>
                                    );
                                })}
                            </Card>
                        )
                    )}
                </>
            ) : (
                // Only show 'No Vulnerability Data' if NOT loading the combined report
                !(isScanning && dataSource === 'combined') && (
                    <Paper
                        elevation={3}
                        sx={{
                            p: 5,
                            textAlign: 'center',
                            backgroundColor: '#f8f9fa',
                            borderRadius: '12px',
                            boxShadow: '0 8px 30px rgba(0,0,0,0.08)',
                        }}
                    >
                        <Box sx={{ mb: 3 }}>
                            <SecurityIcon
                                sx={{
                                    fontSize: 80,
                                    opacity: 0.7,
                                    color: 'primary.main',
                                    mb: 2,
                                }}
                            />
                            <Typography
                                variant="h4"
                                gutterBottom
                                sx={{ fontWeight: 600, color: '#1a237e' }}
                            >
                                No Vulnerability Data
                            </Typography>
                            <Typography
                                variant="body1"
                                sx={{
                                    mb: 3,
                                    maxWidth: '600px',
                                    mx: 'auto',
                                    color: '#555',
                                }}
                            >
                                Please upload a Trivy or Grype JSON report file
                                using the buttons above to analyze your
                                vulnerabilities.
                            </Typography>
                            <Box
                                sx={{
                                    display: 'inline-flex',
                                    background:
                                        'linear-gradient(45deg, #f5f5f5 30%, #e0e0e0 90%)',
                                    p: 2,
                                    borderRadius: '8px',
                                    boxShadow: 'inset 0 0 5px rgba(0,0,0,0.1)',
                                }}
                            >
                                <Typography
                                    variant="body2"
                                    sx={{ fontStyle: 'italic', color: '#666' }}
                                >
                                    Start by clicking on one of the "Upload
                                    File" buttons to begin your security
                                    analysis
                                </Typography>
                            </Box>
                        </Box>
                    </Paper>
                )
            )}{' '}
            {/* Fix List Section */}
            {vulnerabilitiesToFix.length > 0 && (
                <Box id="fix-list" sx={{ mt: 5 }}>
                    <Paper
                        elevation={3}
                        sx={{
                            p: 4,
                            borderRadius: '12px',
                            background:
                                'linear-gradient(145deg, #ffffff, #f8f8f8)',
                            border: '1px solid #e0e0e0',
                        }}
                    >
                        <Box
                            sx={{
                                display: 'flex',
                                alignItems: 'center',
                                mb: 3,
                            }}
                        >
                            <SecurityIcon
                                sx={{ color: '#1a237e', fontSize: 36, mr: 2 }}
                            />
                            <Typography
                                variant="h4"
                                sx={{
                                    fontWeight: 700,
                                    color: '#1a237e',
                                    letterSpacing: '0.5px',
                                }}
                            >
                                Fix Priority List
                            </Typography>
                        </Box>

                        <TableContainer
                            sx={{
                                boxShadow: '0 4px 20px rgba(0,0,0,0.08)',
                                borderRadius: '8px',
                                overflow: 'hidden',
                            }}
                        >
                            <Table>
                                <TableHead>
                                    <TableRow
                                        sx={{
                                            background:
                                                'linear-gradient(90deg, #1a237e 0%, #3949ab 100%)',
                                        }}
                                    >
                                        <TableCell
                                            sx={{
                                                color: 'white',
                                                fontWeight: 'bold',
                                            }}
                                        >
                                            Vulnerability ID
                                        </TableCell>
                                        <TableCell
                                            sx={{
                                                color: 'white',
                                                fontWeight: 'bold',
                                            }}
                                        >
                                            Package
                                        </TableCell>
                                        <TableCell
                                            sx={{
                                                color: 'white',
                                                fontWeight: 'bold',
                                            }}
                                        >
                                            Severity
                                        </TableCell>
                                        <TableCell
                                            sx={{
                                                color: 'white',
                                                fontWeight: 'bold',
                                            }}
                                        >
                                            Fixed Version
                                        </TableCell>
                                        <TableCell
                                            sx={{
                                                color: 'white',
                                                fontWeight: 'bold',
                                            }}
                                        >
                                            Action
                                        </TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {vulnerabilitiesToFix
                                        .sort((a, b) => {
                                            const severityOrder = {
                                                CRITICAL: 4,
                                                HIGH: 3,
                                                MEDIUM: 2,
                                                LOW: 1,
                                                UNKNOWN: 0,
                                            };
                                            const severityA =
                                                severityOrder[
                                                    (
                                                        a.severity || a.Severity
                                                    )?.toUpperCase()
                                                ] || 0;
                                            const severityB =
                                                severityOrder[
                                                    (
                                                        b.severity || b.Severity
                                                    )?.toUpperCase()
                                                ] || 0;
                                            return severityB - severityA;
                                        })
                                        .map((vuln, index) => (
                                            <TableRow
                                                key={index}
                                                sx={{
                                                    '&:nth-of-type(odd)': {
                                                        backgroundColor:
                                                            'rgba(0, 0, 0, 0.02)',
                                                    },
                                                    '&:hover': {
                                                        backgroundColor:
                                                            'rgba(25, 118, 210, 0.08)',
                                                    },
                                                    transition:
                                                        'background-color 0.2s',
                                                }}
                                            >
                                                <TableCell
                                                    sx={{ fontWeight: 500 }}
                                                >
                                                    {vuln.id}
                                                </TableCell>
                                                <TableCell>
                                                    {vuln.packageName}{' '}
                                                    {vuln.packageVersion && (
                                                        <Typography
                                                            component="span"
                                                            sx={{
                                                                color: '#666',
                                                                fontSize:
                                                                    '0.85rem',
                                                                fontStyle:
                                                                    'italic',
                                                            }}
                                                        >
                                                            (
                                                            {
                                                                vuln.packageVersion
                                                            }
                                                            )
                                                        </Typography>
                                                    )}
                                                </TableCell>
                                                <TableCell>
                                                    {' '}
                                                    <Chip
                                                        label={
                                                            vuln.severity ||
                                                            vuln.Severity
                                                        }
                                                        size="small"
                                                        sx={{
                                                            backgroundColor:
                                                                getSeverityColor(
                                                                    vuln.severity ||
                                                                        vuln.Severity
                                                                ),
                                                            color: 'white',
                                                            fontWeight: 'bold',
                                                            px: 1,
                                                        }}
                                                    />
                                                </TableCell>
                                                <TableCell>
                                                    {vuln.fixVersions &&
                                                    vuln.fixVersions.length >
                                                        0 ? (
                                                        <Typography
                                                            sx={{
                                                                color: '#2e7d32',
                                                                fontWeight: 500,
                                                            }}
                                                        >
                                                            {vuln.fixVersions.join(
                                                                ', '
                                                            )}
                                                        </Typography>
                                                    ) : (
                                                        <Typography
                                                            sx={{
                                                                color: '#d32f2f',
                                                                fontStyle:
                                                                    'italic',
                                                            }}
                                                        >
                                                            No fix available
                                                        </Typography>
                                                    )}
                                                </TableCell>
                                                <TableCell>
                                                    <Button
                                                        size="small"
                                                        variant="contained"
                                                        color="error"
                                                        onClick={() =>
                                                            removeFromFixList(
                                                                vuln.id
                                                            )
                                                        }
                                                        startIcon={
                                                            <span>✕</span>
                                                        }
                                                        sx={{
                                                            borderRadius: '6px',
                                                            boxShadow: 2,
                                                            '&:hover': {
                                                                boxShadow: 4,
                                                            },
                                                        }}
                                                    >
                                                        Remove
                                                    </Button>
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                </TableBody>
                            </Table>
                        </TableContainer>
                    </Paper>
                </Box>
            )}
        </Container>
    );
}
