import React, { useState, useEffect } from "react";
import {
  Container,
  Typography,
  Box,
  Grid,
  Paper,
  Chip,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Checkbox,
  ListItemText,
  OutlinedInput,
  Card,
  CardContent,
  Button,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TableContainer,
  Table,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  TableSortLabel,
  TablePagination,
  Drawer,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import InfoIcon from "@mui/icons-material/Info";
import CloseIcon from "@mui/icons-material/Close";
import FileDownloadIcon from "@mui/icons-material/FileDownload";
import SecurityIcon from "@mui/icons-material/Security";

const CR2 = () => {
  // State for filters
  const [filters, setFilters] = useState({
    priority: [],
    reachability: [],
    businessRelevance: [],
    searchTerm: "",
  });

  // State for table
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [orderBy, setOrderBy] = useState("priority");
  const [order, setOrder] = useState("asc");
  // State for selected CVE
  const [selectedCve, setSelectedCve] = useState(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  // State for uploaded AI combined JSON
  const [aiCombinedData, setAiCombinedData] = useState(null);
  const [aiUploadMessage, setAiUploadMessage] = useState("");
  // CVSS Metrics
  const [attackVector, setAttackVector] = useState("");
  const [attackComplexity, setAttackComplexity] = useState("");
  const [privilegesRequired, setPrivilegesRequired] = useState("");
  const [userInteraction, setUserInteraction] = useState("");
  const [scope, setScope] = useState("");
  const [confidentialityImpact, setConfidentialityImpact] = useState("");
  const [integrityImpact, setIntegrityImpact] = useState("");
  const [availabilityImpact, setAvailabilityImpact] = useState("");
  const [apiResponseData, setApiResponseData] = useState(null);
  const handleSendToApi = async () => {
    if (!aiCombinedData || !attackVector || !attackComplexity || !privilegesRequired || 
        !userInteraction || !scope || !confidentialityImpact || !integrityImpact || !availabilityImpact) {
      setAiUploadMessage(
        "Please upload a valid AI Combined JSON and select all CVSS metric values."
      );
      return;
    }
    setAiUploadMessage(
      "Sending data to AI analysis service... This may take a few minutes."
    );
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 600000); // 10 min timeout
      const payload = {
        cr1_response: aiCombinedData,
        attack_vector: attackVector,
        attack_complexity: attackComplexity,
        privileges_required: privilegesRequired,
        user_interaction: userInteraction,
        scope: scope,
        confidentiality_impact: confidentialityImpact,
        integrity_impact: integrityImpact,
        availability_impact: availabilityImpact,
      };
      const response = await fetch(
        "https://bgsw-gendigitalhackathon-server-001-dwe6eydrgnbscvbv.eastus-01.azurewebsites.net/api/cr2",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: controller.signal,
        }
      );
      clearTimeout(timeoutId);
      const responseData = await response.json().catch(() => null);
      if (
        typeof responseData === "string" &&
        responseData.includes("<!DOCTYPE HTML>") &&
        responseData.includes("Error response")
      ) {
        setAiUploadMessage(
          "AI service returned an HTML error response: Service unavailable (503)"
        );
        setApiResponseData(null);
        return;
      }
      if (response.ok && responseData) {
        setAiUploadMessage("AI analysis completed successfully.");
        setApiResponseData(responseData);
      } else if (response.status === 503) {
        setAiUploadMessage("AI service is busy (503). Please try again later.");
        setApiResponseData(null);
      } else {
        setAiUploadMessage(
          `AI service error (${response.status}). Please try again later.`
        );
        setApiResponseData(null);
      }
    } catch (error) {
      if (error.name === "AbortError") {
        setAiUploadMessage(
          "Request timed out. The AI service may be experiencing high load. Please try again later."
        );
      } else {
        setAiUploadMessage(`AI service error: ${error.message}`);
      }
      setApiResponseData(null);
    }
  };

  // Helper to get data source (API or fallback)
  const getDataSource = () => {
    if (apiResponseData && Array.isArray(apiResponseData))
      return apiResponseData;
    return [];
  };

  // Filtered data
  const filteredData = getDataSource().filter((item) => {
    // Filter by priority if any selected
    if (
      filters.priority.length > 0 &&
      !filters.priority.includes(item.priority)
    ) {
      return false;
    }

    // Filter by reachability if any selected
    if (
      filters.reachability.length > 0 &&
      !filters.reachability.includes(item.reachability)
    ) {
      return false;
    }

    // Filter by business relevance if any selected
    if (
      filters.businessRelevance.length > 0 &&
      !filters.businessRelevance.includes(item.business_relevance)
    ) {
      return false;
    }

    // Search term (CVE ID or justification)
    if (filters.searchTerm) {
      const searchLower = filters.searchTerm.toLowerCase();
      return (
        item.VulnerabilityID.toLowerCase().includes(searchLower) ||
        item.justification.toLowerCase().includes(searchLower)
      );
    }

    return true;
  });
  // Sort data
  const sortedData = [...filteredData].sort((a, b) => {
    const isAsc = order === "asc";

    if (orderBy === "priority") {
      const priorityValues = { High: 3, Medium: 2, Low: 1 };
      return isAsc
        ? priorityValues[a.priority] - priorityValues[b.priority]
        : priorityValues[b.priority] - priorityValues[a.priority];
    }
    
    // Numeric sorting for scores
    if (orderBy === "baseScore" || orderBy === "AI_Score") {
      const aValue = parseFloat(a[orderBy]) || 0;
      const bValue = parseFloat(b[orderBy]) || 0;
      return isAsc ? aValue - bValue : bValue - aValue;
    }

    // Default string comparison for other fields
    return isAsc
      ? a[orderBy] < b[orderBy]
        ? -1
        : 1
      : a[orderBy] > b[orderBy]
      ? -1
      : 1;
  });

  // Current page data
  const currentPageData = sortedData.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Priority counts for summary cards
  const priorityCounts = {
    High: getDataSource().filter((item) => item.priority === "High").length,
    Medium: getDataSource().filter((item) => item.priority === "Medium").length,
    Low: getDataSource().filter((item) => item.priority === "Low").length,
  };

  // Unique values for filter options
  const uniqueValues = {
    priority: [...new Set(getDataSource().map((item) => item.priority))],
    reachability: [
      ...new Set(getDataSource().map((item) => item.reachability)),
    ],
    businessRelevance: [
      ...new Set(getDataSource().map((item) => item.business_relevance)),
    ],
  };

  // Handle sort request
  const handleRequestSort = (property) => {
    const isAsc = orderBy === property && order === "asc";
    setOrder(isAsc ? "desc" : "asc");
    setOrderBy(property);
  };

  // Handle filter changes
  const handleFilterChange = (filterType, value) => {
    setFilters((prev) => ({
      ...prev,
      [filterType]: value,
    }));
    setPage(0); // Reset to first page when filtering
  };

  // Handle search input
  const handleSearchChange = (event) => {
    setFilters((prev) => ({
      ...prev,
      searchTerm: event.target.value,
    }));
    setPage(0); // Reset to first page when searching
  };

  // Handle CVE selection for details view
  const handleCveSelect = (cve) => {
    setSelectedCve(cve);
    setDetailsOpen(true);
  }; // Export to JSON directly from API data
  const exportToJson = () => {
    // Use filtered data to preserve any filters the user has applied
    const blob = new Blob([JSON.stringify(filteredData, null, 2)], {
      type: "application/json;charset=utf-8;",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", "cve_prioritization.json");
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Get priority color
  const getPriorityColor = (priority) => {
    switch (priority) {
      case "High":
        return "#f44336"; // Red
      case "Medium":
        return "#ff9800"; // Amber
      case "Low":
        return "#4caf50"; // Green
      default:
        return "#9e9e9e"; // Grey
    }
  };

  // Priority emoji
  const getPriorityEmoji = (priority) => {
    switch (priority) {
      case "High":
        return "🔴";
      case "Medium":
        return "🟡";
      case "Low":
        return "🟢";
      default:
        return "⚪";
    }
  };

  return (
    <Container maxWidth="xl" sx={{ py: 4 }}>
      {" "}
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
          Vulnerability Risk Dashboard
        </Typography>
      </Box>
      {/* AI Combined JSON Upload and Analyze Section */}
      <Paper
        elevation={3}
        sx={{
          mb: 4,
          p: 4,
          borderRadius: "12px",
          background: "linear-gradient(145deg, #ffffff, #f9f9f9)",
          boxShadow: "0 8px 30px rgba(0,0,0,0.12)",
        }}
      >
        <Typography variant="h6" sx={{ mb: 3, fontWeight: 600, color: "#333" }}>
          Upload & Analyze AI Combined Report
        </Typography>
        <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
          <Box
            sx={{
              display: "flex",
              gap: 3,
              flexWrap: "wrap",
              justifyContent: "flex-start",
            }}
          >
            <Button
              variant="outlined"
              component="label"
              color="info"
              sx={{
                py: 1.5,
                px: 3,
                borderRadius: "8px",
                borderWidth: "2px",
                fontWeight: 600,
                transition: "all 0.3s ease",
                background: "linear-gradient(90deg, #e3f2fd 0%, #bbdefb 100%)",
                color: "#1565c0",
                "&:hover": {
                  transform: "translateY(-3px)",
                  boxShadow: 3,
                  borderWidth: "2px",
                  background:
                    "linear-gradient(90deg, #bbdefb 0%, #e3f2fd 100%)",
                },
              }}
            >
              Upload AI Combined JSON
              <input
                type="file"
                accept="application/json"
                hidden
                onChange={async (e) => {
                  if (e.target.files && e.target.files[0]) {
                    const file = e.target.files[0];
                    try {
                      const text = await file.text();
                      const data = JSON.parse(text);
                      setAiCombinedData(data);
                      setAiUploadMessage(
                        "AI Combined JSON uploaded successfully"
                      );
                    } catch (err) {
                      setAiUploadMessage("Invalid JSON file");
                    }
                  }
                }}
              />
            </Button>            <FormControl sx={{ minWidth: 180 }} size="small">
              <InputLabel>Attack Vector (AV)</InputLabel>
              <Select
                value={attackVector}
                label="Attack Vector (AV)"
                onChange={(e) => setAttackVector(e.target.value)}
              >
                <MenuItem value="Network">Network</MenuItem>
                <MenuItem value="Adjacent">Adjacent</MenuItem>
                <MenuItem value="Local">Local</MenuItem>
                <MenuItem value="Physical">Physical</MenuItem>
              </Select>
            </FormControl>
            <FormControl sx={{ minWidth: 180 }} size="small">
              <InputLabel>Attack Complexity (AC)</InputLabel>
              <Select
                value={attackComplexity}
                label="Attack Complexity (AC)"
                onChange={(e) => setAttackComplexity(e.target.value)}
              >
                <MenuItem value="Low">Low</MenuItem>
                <MenuItem value="High">High</MenuItem>
              </Select>
            </FormControl>
            <FormControl sx={{ minWidth: 180 }} size="small">
              <InputLabel>Privileges Required (PR)</InputLabel>
              <Select
                value={privilegesRequired}
                label="Privileges Required (PR)"
                onChange={(e) => setPrivilegesRequired(e.target.value)}
              >
                <MenuItem value="None">None</MenuItem>
                <MenuItem value="Low">Low</MenuItem>
                <MenuItem value="High">High</MenuItem>
              </Select>
            </FormControl>
            <FormControl sx={{ minWidth: 180 }} size="small">
              <InputLabel>User Interaction (UI)</InputLabel>
              <Select
                value={userInteraction}
                label="User Interaction (UI)"
                onChange={(e) => setUserInteraction(e.target.value)}
              >
                <MenuItem value="None">None</MenuItem>
                <MenuItem value="Required">Required</MenuItem>
              </Select>
            </FormControl>
            <FormControl sx={{ minWidth: 180 }} size="small">
              <InputLabel>Scope (S)</InputLabel>
              <Select
                value={scope}
                label="Scope (S)"
                onChange={(e) => setScope(e.target.value)}
              >
                <MenuItem value="Unchanged">Unchanged</MenuItem>
                <MenuItem value="Changed">Changed</MenuItem>
              </Select>
            </FormControl>
            <FormControl sx={{ minWidth: 180 }} size="small">
              <InputLabel>Confidentiality Impact (C)</InputLabel>
              <Select
                value={confidentialityImpact}
                label="Confidentiality Impact (C)"
                onChange={(e) => setConfidentialityImpact(e.target.value)}
              >
                <MenuItem value="None">None</MenuItem>
                <MenuItem value="Low">Low</MenuItem>
                <MenuItem value="High">High</MenuItem>
              </Select>
            </FormControl>
            <FormControl sx={{ minWidth: 180 }} size="small">
              <InputLabel>Integrity Impact (I)</InputLabel>
              <Select
                value={integrityImpact}
                label="Integrity Impact (I)"
                onChange={(e) => setIntegrityImpact(e.target.value)}
              >
                <MenuItem value="None">None</MenuItem>
                <MenuItem value="Low">Low</MenuItem>
                <MenuItem value="High">High</MenuItem>
              </Select>
            </FormControl>
            <FormControl sx={{ minWidth: 180 }} size="small">
              <InputLabel>Availability Impact (A)</InputLabel>
              <Select
                value={availabilityImpact}
                label="Availability Impact (A)"
                onChange={(e) => setAvailabilityImpact(e.target.value)}
              >
                <MenuItem value="None">None</MenuItem>
                <MenuItem value="Low">Low</MenuItem>
                <MenuItem value="High">High</MenuItem>
              </Select>
            </FormControl>            <Button
              variant="contained"
              color="primary"
              disabled={
                !aiCombinedData || !attackVector || !attackComplexity || !privilegesRequired || 
                !userInteraction || !scope || !confidentialityImpact || !integrityImpact || !availabilityImpact
              }
              onClick={handleSendToApi}
              sx={{
                fontWeight: 600,
                borderRadius: "8px",
                px: 3,
                py: 1.2,
                boxShadow: 2,
              }}
            >
              Analyze with AI
            </Button>
          </Box>
          {aiUploadMessage && (
            <Box sx={{ width: "100%" }}>
              <Paper
                elevation={3}
                sx={{
                  mt: 2,
                  p: 2,
                  borderRadius: "8px",
                  background:
                    "linear-gradient(90deg, #e3f2fd 0%, #bbdefb 100%)", // light blue like Trivy upload
                  color: "#1565c0",
                  fontWeight: 600,
                  boxShadow: "0 2px 10px rgba(0,0,0,0.08)",
                  display: "flex",
                  alignItems: "center",
                  gap: 2,
                }}
              >
                <span style={{ fontSize: 22, marginRight: 8 }}>ℹ️</span>
                {aiUploadMessage}
              </Paper>
            </Box>
          )}
        </Box>
      </Paper>
      {/* Priority Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {Object.entries(priorityCounts).map(([priority, count]) => {
          let bgGradient, borderColor, textColor, shadow;
          if (priority === "High") {
            bgGradient = "linear-gradient(135deg, #e53935 0%, #ff5252 100%)";
            borderColor = "#b71c1c";
            textColor = "#fff";
            shadow = "0 6px 24px 0 rgba(229,57,53,0.18)";
          } else if (priority === "Medium") {
            bgGradient = "linear-gradient(135deg, #fbc02d 0%, #ffd54f 100%)";
            borderColor = "#f9a825";
            textColor = "#4e2600";
            shadow = "0 6px 24px 0 rgba(251,192,45,0.14)";
          } else if (priority === "Low") {
            bgGradient = "linear-gradient(135deg, #43a047 0%, #a5d6a7 100%)";
            borderColor = "#2e7d32";
            textColor = "#003d1f";
            shadow = "0 6px 24px 0 rgba(67,160,71,0.13)";
          } else {
            bgGradient = "linear-gradient(135deg, #ececec 0%, #f5f5f5 100%)";
            borderColor = "#bdbdbd";
            textColor = "#333";
            shadow = "0 6px 20px rgba(0,0,0,0.10)";
          }
          return (
            <Grid item xs={12} sm={4} key={priority}>
              <Card
                sx={{
                  background: bgGradient,
                  borderRadius: "16px",
                  boxShadow: shadow,
                  color: textColor,
                  border: `2px solid ${borderColor}`,
                  minHeight: 120,
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "center",
                  alignItems: "center",
                  transition: "transform 0.15s",
                  "&:hover": {
                    transform: "scale(1.025)",
                    boxShadow: "0 12px 36px 0 rgba(44,62,80,0.13)",
                  },
                }}
              >
                <CardContent
                  sx={{
                    width: "100%",
                    textAlign: "center",
                    p: 2,
                  }}
                >
                  <Typography
                    variant="subtitle1"
                    sx={{
                      fontWeight: 700,
                      letterSpacing: 1,
                      mb: 1,
                      textTransform: "uppercase",
                    }}
                  >
                    {priority} Priority
                  </Typography>
                  <Typography
                    variant="h2"
                    sx={{
                      fontWeight: 800,
                      fontSize: "2.8rem",
                      lineHeight: 1,
                    }}
                  >
                    {count}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          );
        })}
      </Grid>
      {/* Filters Section */}
      <Paper
        sx={{
          p: 2,
          mb: 3,
          borderRadius: "12px",
          background: "linear-gradient(145deg, #ffffff, #f9f9f9)",
          boxShadow: "0 8px 30px rgba(0,0,0,0.12)",
        }}
      >
        <Typography
          variant="h6"
          component="div"
          sx={{ mb: 2, fontWeight: 600, color: "#333" }}
        >
          Filters
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6} md={4}>
            <FormControl fullWidth>
              <InputLabel>Priority</InputLabel>
              <Select
                multiple
                value={filters.priority}
                onChange={(e) => handleFilterChange("priority", e.target.value)}
                input={<OutlinedInput label="Priority" />}
                renderValue={(selected) => selected.join(", ")}
                sx={{ minWidth: "200px" }}
              >
                {uniqueValues.priority.map((name) => (
                  <MenuItem key={name} value={name}>
                    <Checkbox checked={filters.priority.indexOf(name) > -1} />
                    <ListItemText
                      primary={name}
                      secondary={
                        <span
                          style={{
                            color: getPriorityColor(name),
                          }}
                        >
                          {getPriorityEmoji(name)}
                        </span>
                      }
                    />
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} sm={6} md={4}>
            <FormControl fullWidth>
              <InputLabel>Reachability</InputLabel>
              <Select
                multiple
                value={filters.reachability}
                onChange={(e) =>
                  handleFilterChange("reachability", e.target.value)
                }
                input={<OutlinedInput label="Reachability" />}
                renderValue={(selected) => selected.join(", ")}
                sx={{ minWidth: "200px" }}
              >
                {uniqueValues.reachability.map((name) => (
                  <MenuItem key={name} value={name}>
                    <Checkbox
                      checked={filters.reachability.indexOf(name) > -1}
                    />
                    <ListItemText primary={name} />
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} sm={6} md={4}>
            <FormControl fullWidth>
              <InputLabel>Business Relevance</InputLabel>
              <Select
                multiple
                value={filters.businessRelevance}
                onChange={(e) =>
                  handleFilterChange("businessRelevance", e.target.value)
                }
                input={<OutlinedInput label="Business Relevance" />}
                renderValue={(selected) => selected.join(", ")}
                sx={{ minWidth: "200px" }}
              >
                {uniqueValues.businessRelevance.map((name) => (
                  <MenuItem key={name} value={name}>
                    <Checkbox
                      checked={filters.businessRelevance.indexOf(name) > -1}
                    />
                    <ListItemText primary={name} />
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} sm={6} md={4}>
            <TextField
              fullWidth
              label="Search CVE or keywords"
              variant="outlined"
              value={filters.searchTerm}
              onChange={handleSearchChange}
              InputProps={{
                endAdornment: <SearchIcon color="action" />,
              }}
            />
          </Grid>
        </Grid>
        <Box
          sx={{
            mt: 2,
            display: "flex",
            justifyContent: "space-between",
          }}
        >
          <Button
            variant="outlined"
            color="secondary"
            sx={{
              borderRadius: "8px",
              fontWeight: 600,
              px: 3,
              py: 1.2,
            }}
            onClick={() =>
              setFilters({
                priority: [],
                reachability: [],
                businessRelevance: [],
                searchTerm: "",
              })
            }
          >
            Clear Filters
          </Button>{" "}
          <Button
            variant="contained"
            color="primary"
            startIcon={<FileDownloadIcon />}
            sx={{
              borderRadius: "8px",
              fontWeight: 600,
              px: 3,
              py: 1.2,
              boxShadow: 2,
            }}
            onClick={exportToJson}
          >
            Export to JSON
          </Button>
        </Box>
      </Paper>
      {/* Results Table */}
      <Paper
        sx={{
          width: "100%",
          mb: 2,
          borderRadius: "12px",
          background: "linear-gradient(145deg, #ffffff, #f9f9f9)",
          boxShadow: "0 8px 30px rgba(0,0,0,0.12)",
        }}
      >
        <TableContainer>
          <Table size="medium">
            <TableHead>              <TableRow>
                <TableCell>
                  <TableSortLabel
                    active={orderBy === "VulnerabilityID"}
                    direction={orderBy === "VulnerabilityID" ? order : "asc"}
                    onClick={() => handleRequestSort("VulnerabilityID")}
                  >
                    CVE ID
                  </TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel
                    active={orderBy === "priority"}
                    direction={orderBy === "priority" ? order : "asc"}
                    onClick={() => handleRequestSort("priority")}
                  >
                    Priority
                  </TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel
                    active={orderBy === "baseScore"}
                    direction={orderBy === "baseScore" ? order : "asc"}
                    onClick={() => handleRequestSort("baseScore")}
                  >
                    Base Score
                  </TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel
                    active={orderBy === "AI_Score"}
                    direction={orderBy === "AI_Score" ? order : "asc"}
                    onClick={() => handleRequestSort("AI_Score")}
                  >
                    AI Score
                  </TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel
                    active={orderBy === "impact"}
                    direction={orderBy === "impact" ? order : "asc"}
                    onClick={() => handleRequestSort("impact")}
                  >
                    Impact
                  </TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel
                    active={orderBy === "reachability"}
                    direction={orderBy === "reachability" ? order : "asc"}
                    onClick={() => handleRequestSort("reachability")}
                  >
                    Reachability
                  </TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel
                    active={orderBy === "business_relevance"}
                    direction={orderBy === "business_relevance" ? order : "asc"}
                    onClick={() => handleRequestSort("business_relevance")}
                  >
                    Business Relevance
                  </TableSortLabel>
                </TableCell>
                <TableCell>Details</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {currentPageData.map((row) => (                <TableRow
                  key={row.VulnerabilityID}
                  hover
                  onClick={() => handleCveSelect(row)}
                  sx={{ cursor: "pointer" }}
                >
                  <TableCell component="th" scope="row">
                    {row.VulnerabilityID}
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={row.priority}
                      sx={{
                        bgcolor: getPriorityColor(row.priority),
                        color: "white",
                      }}
                    />
                  </TableCell>
                  <TableCell>{row.baseScore !== undefined ? row.baseScore.toFixed(1) : "N/A"}</TableCell>
                  <TableCell>{row.AI_Score !== undefined ? row.AI_Score.toFixed(1) : "N/A"}</TableCell>
                  <TableCell>{row.impact}</TableCell>
                  <TableCell>{row.reachability}</TableCell>
                  <TableCell>{row.business_relevance}</TableCell>
                  <TableCell>
                    <IconButton
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleCveSelect(row);
                      }}
                    >
                      <InfoIcon />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        <TablePagination
          rowsPerPageOptions={[5, 10, 25]}
          component="div"
          count={sortedData.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={(e, newPage) => setPage(newPage)}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
          sx={{ borderRadius: "0 0 12px 12px" }}
        />
      </Paper>
      {/* CVE Details Drawer */}
      <Drawer
        anchor="right"
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        sx={{
          "& .MuiDrawer-paper": {
            width: { xs: "100%", sm: "50%", md: "40%" },
            padding: 2,
          },
        }}
      >
        {selectedCve && (
          <Box sx={{ p: 2 }}>
            <Box
              sx={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                mb: 2,
              }}
            >
              <Typography variant="h5" component="h2">
                {selectedCve.VulnerabilityID}
              </Typography>
              <IconButton onClick={() => setDetailsOpen(false)}>
                <CloseIcon />
              </IconButton>
            </Box>            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={6} sm={4}>
                <Paper variant="outlined" sx={{ p: 1 }}>
                  <Typography variant="body2" color="text.secondary">
                    Priority
                  </Typography>
                  <Chip
                    label={selectedCve.priority}
                    sx={{
                      bgcolor: getPriorityColor(selectedCve.priority),
                      color: "white",
                      mt: 1,
                    }}
                    size="small"
                  />
                </Paper>
              </Grid>

              <Grid item xs={6} sm={4}>
                <Paper variant="outlined" sx={{ p: 1 }}>
                  <Typography variant="body2" color="text.secondary">
                    Base Score
                  </Typography>
                  <Typography variant="body1" sx={{ mt: 1, fontWeight: 'bold' }}>
                    {selectedCve.baseScore !== undefined ? selectedCve.baseScore.toFixed(1) : "N/A"}
                  </Typography>
                </Paper>
              </Grid>

              <Grid item xs={6} sm={4}>
                <Paper variant="outlined" sx={{ p: 1 }}>
                  <Typography variant="body2" color="text.secondary">
                    AI Score
                  </Typography>
                  <Typography variant="body1" sx={{ mt: 1, fontWeight: 'bold' }}>
                    {selectedCve.AI_Score !== undefined ? selectedCve.AI_Score.toFixed(1) : "N/A"}
                  </Typography>
                </Paper>
              </Grid>

              <Grid item xs={6} sm={4}>
                <Paper variant="outlined" sx={{ p: 1 }}>
                  <Typography variant="body2" color="text.secondary">
                    Impact
                  </Typography>
                  <Typography variant="body1" sx={{ mt: 1 }}>
                    {selectedCve.impact}
                  </Typography>
                </Paper>
              </Grid>

              <Grid item xs={6} sm={4}>
                <Paper variant="outlined" sx={{ p: 1 }}>
                  <Typography variant="body2" color="text.secondary">
                    Reachability
                  </Typography>
                  <Typography variant="body1" sx={{ mt: 1 }}>
                    {selectedCve.reachability}
                  </Typography>
                </Paper>
              </Grid>

              <Grid item xs={6} sm={4}>
                <Paper variant="outlined" sx={{ p: 1 }}>
                  <Typography variant="body2" color="text.secondary">
                    Business Relevance
                  </Typography>
                  <Typography variant="body1" sx={{ mt: 1 }}>
                    {selectedCve.business_relevance}
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Box sx={{ mt: 2 }}>
              <Typography variant="h6" gutterBottom>
                Justification
              </Typography>
              <Paper variant="outlined" sx={{ p: 2, bgcolor: "#f5f5f5" }}>
                <Typography variant="body1">
                  {selectedCve.justification}
                </Typography>
              </Paper>
            </Box>

            <Box sx={{ mt: 3 }}>
              <Button
                variant="outlined"
                fullWidth
                href={`https://nvd.nist.gov/vuln/detail/${
                  selectedCve.VulnerabilityID.split("_")[0]
                }`}
                target="_blank"
                rel="noopener noreferrer"
              >
                View in NVD Database
              </Button>
            </Box>
          </Box>
        )}
      </Drawer>
    </Container>
  );
};

export default CR2;
