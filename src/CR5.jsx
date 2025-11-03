import React, { useState, useRef } from "react";
import {
  Box,
  Button,
  Card,
  CardContent,
  Container,
  Typography,
  CircularProgress,
  Snackbar,
  Alert,
  Paper,
  Divider,
  Chip,
  Stack,
  ToggleButtonGroup,
  ToggleButton,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from "@mui/material";
import SendIcon from "@mui/icons-material/Send";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import CodeIcon from "@mui/icons-material/Code";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import SortIcon from "@mui/icons-material/Sort";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ArrowUpwardIcon from "@mui/icons-material/ArrowUpward";
import ArrowDownwardIcon from "@mui/icons-material/ArrowDownward";
import AssignmentIcon from "@mui/icons-material/Assignment";
import ShieldIcon from "@mui/icons-material/Shield";
import FilterListIcon from "@mui/icons-material/FilterList";
import ReactMarkdown from "markdown-to-jsx";

function CR5() {
  const [jsonData, setJsonData] = useState(null);
  const [fileName, setFileName] = useState("");
  const [results, setResults] = useState([]);
  const [sortedResults, setSortedResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [sortCycle, setSortCycle] = useState(0); // 0: none, 1: high to low, 2: low to high
  const fileInputRef = useRef(null);

  // Priority ranking for sorting
  const priorityRank = {
    critical: 1,
    high: 2,
    medium: 3,
    low: 4,
    unknown: 5,
  };
  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setFileName(file.name);

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const content = e.target.result;
        const parsed = JSON.parse(content);
        setJsonData(parsed);
        setError(null);
      } catch (err) {
        setError("Invalid JSON file: " + err.message);
        setJsonData(null);
      }
    };
    reader.onerror = () => {
      setError("Error reading the file");
    };
    reader.readAsText(file);
  };

  const handleSubmit = async () => {
    try {
      if (!jsonData) {
        throw new Error("Please upload a JSON file first");
      }

      setLoading(true);
      setError(null);

      const response = await fetch(
        "https://bgsw-gendigitalhackathon-server-001-dwe6eydrgnbscvbv.eastus-01.azurewebsites.net/api/cr5",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(jsonData),
        }
      );

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }
      const data = await response.json();
      setResults(data);
      setSortedResults(data);
      // Reset sort cycle when new data arrives
      setSortCycle(0);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };
  const cycleSorting = () => {
    // Cycle between 0: none, 1: high to low, 2: low to high
    const nextCycle = (sortCycle + 1) % 3;
    setSortCycle(nextCycle);

    if (nextCycle === 0) {
      // No sorting - original order
      setSortedResults([...results]);
    } else {
      // Sort by priority
      const sorted = [...results].sort((a, b) => {
        const priorityA = a.priority?.toLowerCase() || "unknown";
        const priorityB = b.priority?.toLowerCase() || "unknown";

        const rankA = priorityRank[priorityA] || priorityRank["unknown"];
        const rankB = priorityRank[priorityB] || priorityRank["unknown"];

        // nextCycle 1: high to low (desc), 2: low to high (asc)
        return nextCycle === 1 ? rankA - rankB : rankB - rankA;
      });

      setSortedResults(sorted);
    }
  };

  const getPriorityColor = (priority) => {
    const normalizedPriority = priority?.toLowerCase();
    if (!normalizedPriority) return "default";

    if (
      normalizedPriority.includes("high") ||
      normalizedPriority.includes("critical")
    ) {
      return "error";
    } else if (normalizedPriority.includes("medium")) {
      return "warning";
    } else if (normalizedPriority.includes("low")) {
      return "success";
    } else {
      return "default";
    }
  };
  return (
    <Container maxWidth="md">
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          mb: 3,
          background: "linear-gradient(90deg, #1a237e 0%, #3949ab 100%)",
          borderRadius: "8px",
          p: 3,
          boxShadow: 3,
        }}
      >
        <SecurityIcon sx={{ fontSize: 42, color: "white", mr: 2 }} />
        <Typography
          variant="h3"
          sx={{
            fontWeight: 700,
            color: "white",
            letterSpacing: "0.5px",
            textShadow: "1px 1px 2px rgba(0,0,0,0.3)",
          }}
        >
          Vulnerability Attack Simulation
        </Typography>
      </Box>
      <Paper
        elevation={3}
        sx={{
          p: 3,
          mb: 4,
          background: "linear-gradient(to right, #f5f7fa, #e9f0f6)",
        }}
      >
        <Typography variant="h6" gutterBottom>
          Upload JSON File
        </Typography>

        <input
          type="file"
          accept=".json"
          onChange={handleFileUpload}
          style={{ display: "none" }}
          ref={fileInputRef}
          id="json-file-upload"
        />

        <Box
          sx={{
            border: "2px dashed #ccc",
            borderRadius: 2,
            p: 3,
            mb: 3,
            backgroundColor: "white",
            textAlign: "center",
            cursor: "pointer",
            transition: "all 0.3s",
            "&:hover": {
              borderColor: "primary.main",
              bgcolor: "rgba(25, 118, 210, 0.04)",
            },
          }}
          onClick={() => fileInputRef.current.click()}
        >
          <CloudUploadIcon
            sx={{ fontSize: 48, color: "primary.main", mb: 1 }}
          />
          <Typography variant="h6" gutterBottom>
            {fileName
              ? `File selected: ${fileName}`
              : "Click to upload JSON file"}
          </Typography>
          {!fileName && (
            <Typography variant="body2" color="text.secondary">
              or drag and drop file here
            </Typography>
          )}
          {jsonData && (
            <Alert severity="success" sx={{ mt: 2 }}>
              JSON file loaded successfully!
            </Alert>
          )}
        </Box>

        <Stack direction="row" spacing={2} justifyContent="flex-end">
          <Button
            variant="outlined"
            startIcon={<UploadFileIcon />}
            onClick={() => fileInputRef.current.click()}
          >
            Select File
          </Button>
          <Button
            variant="contained"
            color="primary"
            endIcon={<SendIcon />}
            onClick={handleSubmit}
            disabled={loading || !jsonData}
          >
            {loading ? "Sending..." : "Send Request"}
          </Button>
        </Stack>
      </Paper>
      {loading && (
        <Box sx={{ display: "flex", justifyContent: "center", my: 4 }}>
          <CircularProgress />
          <Typography sx={{ ml: 2 }}>Processing request...</Typography>
        </Box>
      )}{" "}
      {results.length > 0 && (
        <Box sx={{ mb: 4 }}>
          {" "}
          <Box
            sx={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              mb: 2,
            }}
          >
            <Typography variant="h6">
              <BugReportIcon sx={{ mr: 1, verticalAlign: "middle" }} />
              Attack Simulation Results ({results.length})
            </Typography>

            <Button
              variant="outlined"
              size="small"
              onClick={cycleSorting}
              startIcon={
                sortCycle === 0 ? (
                  <FilterListIcon />
                ) : sortCycle === 1 ? (
                  <ArrowDownwardIcon />
                ) : (
                  <ArrowUpwardIcon />
                )
              }
              color={sortCycle === 0 ? "inherit" : "primary"}
              sx={{ textTransform: "none" }}
            >
              {sortCycle === 0
                ? "Sort by Priority"
                : sortCycle === 1
                ? "Priority: High to Low"
                : "Priority: Low to High"}
            </Button>
          </Box>
          <Divider sx={{ mb: 2 }} />
          {sortedResults.map((result, index) => (
            <Card
              key={index}
              sx={{
                mb: 2,
                border: "1px solid #e0e0e0",
                boxShadow: 2,
                "&:hover": {
                  boxShadow: 4,
                },
              }}
            >
              <CardContent>
                <Box
                  sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    mb: 2,
                  }}
                >
                  <Typography variant="subtitle1" fontWeight="bold">
                    {result.vulnerability_id || `Vulnerability #${index + 1}`}
                  </Typography>
                  <Chip
                    label={result.priority || "Unknown"}
                    size="small"
                    color={getPriorityColor(result.priority)}
                    icon={<SecurityIcon />}
                  />
                </Box>{" "}
                <Divider sx={{ mb: 2 }} />
                {result.attack_simulation ? (
                  <Accordion
                    elevation={0}
                    sx={{
                      "&:before": { display: "none" },
                      bgcolor: "transparent",
                    }}
                  >
                    <AccordionSummary
                      expandIcon={<ExpandMoreIcon />}
                      aria-controls="simulation-content"
                      id="simulation-header"
                      sx={{ pl: 0 }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center" }}>
                        <AssignmentIcon sx={{ mr: 1, color: "primary.main" }} />
                        <Typography variant="subtitle1" fontWeight="medium">
                          Attack Simulation Details
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails sx={{ px: 0 }}>
                      <Paper
                        elevation={1}
                        sx={{
                          p: 2,
                          bgcolor: "#f9f9f9",
                          borderLeft: "4px solid",
                          borderColor: "primary.main",
                        }}
                      >
                        <Box sx={{ mb: 2 }}>
                          <ReactMarkdown
                            options={{
                              overrides: {
                                h3: {
                                  component: (props) => (
                                    <Typography
                                      variant="h6"
                                      color="primary.main"
                                      gutterBottom
                                      {...props}
                                    />
                                  ),
                                },
                                h4: {
                                  component: (props) => (
                                    <Typography
                                      variant="subtitle1"
                                      fontWeight="bold"
                                      gutterBottom
                                      {...props}
                                    />
                                  ),
                                },
                                p: {
                                  component: (props) => (
                                    <Typography
                                      variant="body2"
                                      paragraph
                                      {...props}
                                    />
                                  ),
                                },
                                ul: {
                                  component: (props) => (
                                    <Box
                                      component="ul"
                                      sx={{ pl: 2 }}
                                      {...props}
                                    />
                                  ),
                                },
                                li: {
                                  component: (props) => (
                                    <Typography
                                      component="li"
                                      variant="body2"
                                      {...props}
                                    />
                                  ),
                                },
                              },
                            }}
                          >
                            {result.attack_simulation}
                          </ReactMarkdown>
                        </Box>

                        {result.attack_simulation.includes(
                          "Mitigation Strategy"
                        ) && (
                          <Box
                            sx={{ mt: 3, pt: 2, borderTop: "1px dashed #ccc" }}
                          >
                            <Box
                              sx={{
                                display: "flex",
                                alignItems: "center",
                                mb: 1,
                              }}
                            >
                              <ShieldIcon
                                sx={{ mr: 1, color: "success.main" }}
                              />
                              <Typography
                                variant="subtitle1"
                                fontWeight="medium"
                                color="success.main"
                              >
                                Mitigation Recommendations
                              </Typography>
                            </Box>
                          </Box>
                        )}
                      </Paper>
                    </AccordionDetails>
                  </Accordion>
                ) : (
                  <Typography variant="body1" color="text.secondary">
                    No attack simulation available
                  </Typography>
                )}
              </CardContent>
            </Card>
          ))}
        </Box>
      )}
      <Snackbar
        open={!!error}
        autoHideDuration={6000}
        onClose={() => setError(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      >
        <Alert severity="error" sx={{ width: "100%" }}>
          {error}
        </Alert>
      </Snackbar>
    </Container>
  );
}

export default CR5;
