// app.js
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const path = require('path');
const axios = require('axios'); // For NVD API calls

// Import models
const User = require('./models/User');
const Product = require('./models/Product');
const Vulnerability = require('./models/Vulnerability');
const ApiKey = require('./models/ApiKey');

const app = express();

// --- Helper Function ---
// Splits a date range into chunks, each no longer than maxDays
function chunkDateRange(startDateStr, endDateStr, maxDays = 120) {
  const startDate = new Date(startDateStr);
  const endDate = new Date(endDateStr);
  const chunks = [];
  let currentStart = startDate;
  while (currentStart < endDate) {
    let currentEnd = new Date(currentStart.getTime() + maxDays * 24 * 60 * 60 * 1000 - 1);
    if (currentEnd > endDate) {
      currentEnd = endDate;
    }
    chunks.push([new Date(currentStart), new Date(currentEnd)]);
    currentStart = new Date(currentEnd.getTime() + 1);
  }
  return chunks;
}

// Global progress variable for the update process
let updateProgress = 0;

// Global update log to store last update info
let lastUpdateLog = null;

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/vulnVigilance', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {
  console.log("Connected to MongoDB");

  // Ensure default admin user exists
  User.findOne({ username: 'admin' })
    .then(user => {
      if (!user) {
        const adminUser = new User({ username: 'admin', password: 'admin' });
        return adminUser.save();
      }
    })
    .then(() => {
      console.log("Default admin user ensured (username: admin, password: admin)");
    })
    .catch(err => {
      console.error("Error ensuring default admin user:", err);
    });
})
.catch(err => {
  console.error("MongoDB connection error:", err);
});

// Middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: 'vulnSecret',
  resave: false,
  saveUninitialized: true
}));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));

// Authentication middleware
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  } else {
    res.redirect('/login');
  }
}

// Root route
app.get('/', (req, res) => {
  if (req.session.user) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

// --- Login Routes ---
app.get('/login', (req, res) => {
  res.render('login', { error: req.query.error });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  // NOTE: In production, use hashed passwords.
  const user = await User.findOne({ username, password });
  if (user) {
    req.session.user = user;
    res.redirect('/dashboard');
  } else {
    res.redirect('/login?error=Invalid credentials');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// --- Dashboard Route ---
app.get('/dashboard', isAuthenticated, async (req, res) => {
  const totalVulnerabilities = await Vulnerability.countDocuments({});
  const totalProducts = await Product.countDocuments({});
  const statusCounts = await Vulnerability.aggregate([
    { $group: { _id: "$status", count: { $sum: 1 } } }
  ]);
  const latestVulns = await Vulnerability.find({}).sort({ createdAt: -1 }).limit(20);
  res.render('dashboard', {
    totalVulnerabilities,
    totalProducts,
    statusCounts,
    latestVulns
  });
});

// --- Vulnerabilities Route with Search ---
app.get('/vulnerabilities', isAuthenticated, async (req, res) => {
  const searchTerm = req.query.search || '';
  // Base filter: only show vulnerabilities with non-zero CVSS Score
  let baseQuery = { cvssScore: { $ne: 0 } };
  if (searchTerm) {
    baseQuery = {
      $and: [
        { cvssScore: { $ne: 0 } },
        {
          $or: [
            { name: { $regex: searchTerm, $options: 'i' } },
            { description: { $regex: searchTerm, $options: 'i' } },
            { product: { $regex: searchTerm, $options: 'i' } }
          ]
        }
      ]
    };
  }
  const vulnerabilities = await Vulnerability.find(baseQuery);
  res.render('vulnerabilities', { vulnerabilities, searchTerm });
});

// --- Product Management Routes ---
app.get('/products', isAuthenticated, async (req, res) => {
  const products = await Product.find({});
  res.render('products', { products });
});

app.post('/products/add', isAuthenticated, async (req, res) => {
  const { name, version, category } = req.body;
  const newProduct = new Product({ name, version, category });
  await newProduct.save();
  res.redirect('/products');
});

// --- API Management Routes ---
app.get('/api-management', isAuthenticated, async (req, res) => {
  const apiKeys = await ApiKey.find({});
  res.render('api-management', { apiKeys });
});

app.post('/api-management/add', isAuthenticated, async (req, res) => {
  const { apiName, apiKey } = req.body;
  const newApiKey = new ApiKey({ apiName, apiKey });
  await newApiKey.save();
  res.redirect('/api-management');
});

// --- User Management Routes ---
app.get('/settings', isAuthenticated, async (req, res) => {
  const users = await User.find({});
  res.render('settings', { users });
});

app.post('/settings/add-user', isAuthenticated, async (req, res) => {
  const { username, password } = req.body;
  const newUser = new User({ username, password });
  await newUser.save();
  res.redirect('/settings');
});

app.post('/settings/delete-user/:id', isAuthenticated, async (req, res) => {
  const { id } = req.params;
  await User.findByIdAndDelete(id);
  res.redirect('/settings');
});

// --- Update DB Routes ---
// Render the update-db page (which shows the calendar, progress bar, and last update log)
app.get('/update-db', isAuthenticated, (req, res) => {
  res.render('update-db', { lastUpdateLog });
});

// Start update process using selected date range
app.post('/update-db/start', isAuthenticated, async (req, res) => {
  const { startDate, endDate } = req.body;
  if (!startDate || !endDate) {
    return res.status(400).json({ error: "Please provide both startDate and endDate" });
  }
  const diffDays = (new Date(endDate) - new Date(startDate)) / (1000 * 60 * 60 * 24);
  if (diffDays > 120) {
    return res.status(400).json({ error: "Date range cannot exceed 120 days." });
  }
  updateProgress = 0;
  updateDatabase(startDate, endDate);
  res.json({ status: "started", startDate, endDate });
});

// Return current update progress
app.get('/update-db/progress', isAuthenticated, (req, res) => {
  res.json({ progress: updateProgress });
});

// --- Update Database Function ---
// Clears previous vulnerabilities and downloads new ones using the chosen date range.
// It filters out items with vulnStatus "Awaiting Analysis", and it parses product and version.
async function updateDatabase(startDate, endDate) {
  try {
    // Clear previous vulnerabilities
    await Vulnerability.deleteMany({});

    // Retrieve the NVD API key (if set)
    const nvdKeyDoc = await ApiKey.findOne({ apiName: "NVD" });
    const nvdApiKey = nvdKeyDoc ? nvdKeyDoc.apiKey : null;

    // Split the selected date range into chunks (max 120 days each)
    const dateRanges = chunkDateRange(startDate, endDate, 120);

    // Build headers; include apiKey if available
    const headers = {};
    if (nvdApiKey) {
      headers.apiKey = nvdApiKey;
    }

    let allItems = [];
    // Fetch vulnerabilities from each chunk
    for (const [chunkStart, chunkEnd] of dateRanges) {
      const params = {
        pubStartDate: chunkStart.toISOString(),
        pubEndDate: chunkEnd.toISOString(),
        resultsPerPage: 100
      };
      console.log(`Fetching NVD data from ${params.pubStartDate} to ${params.pubEndDate}`);
      const response = await axios.get("https://services.nvd.nist.gov/rest/json/cves/2.0", { params, headers });
      const items = response.data.vulnerabilities || [];
      allItems = allItems.concat(items);
    }

    // Filter out vulnerabilities with vulnStatus "Awaiting Analysis"
    allItems = allItems.filter(item => item?.cve?.vulnStatus !== "Awaiting Analysis");

    // Sort the remaining items by published date descending
    allItems.sort((a, b) => new Date(b.cve.published) - new Date(a.cve.published));

    const total = allItems.length;
    for (let i = 0; i < total; i++) {
      const item = allItems[i];
      const cveId = item?.cve?.id || "UNKNOWN";

      // Description (prefer English)
      let description = "No description provided";
      const descObj = item?.cve?.descriptions?.find(d => d.lang === "en");
      if (descObj && descObj.value) {
        description = descObj.value;
      }

      // Severity & CVSS Score
      let severity = "unknown";
      let cvssScore = 0;
      const metrics = item?.cve?.metrics || {};
      if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
        severity = metrics.cvssMetricV31[0].cvssData?.baseSeverity || severity;
        cvssScore = metrics.cvssMetricV31[0].cvssData?.baseScore || cvssScore;
      } else if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
        severity = metrics.cvssMetricV2[0].cvssData?.baseSeverity || severity;
        cvssScore = metrics.cvssMetricV2[0].cvssData?.baseScore || cvssScore;
      }

      // Product & Affected Version:
      // Primary: parse from configurations criteria
      let product = "Unknown";
      let affectedVersion = "N/A";
      const configs = item?.cve?.configurations || [];
      if (configs.length > 0) {
        const nodes = configs[0].nodes || [];
        if (nodes.length > 0) {
          const cpeMatches = nodes[0].cpeMatch || [];
          if (cpeMatches.length > 0) {
            const cpe = cpeMatches[0].criteria; // e.g. "cpe:2.3:a:cmseasy:cmseasy:7.7.7.9:*:*:*:*:*:*:*"
            const parts = cpe.split(':');
            if (parts.length >= 6) {
              product = parts[4] || product;
              affectedVersion = parts[5] || affectedVersion;
            }
          }
        }
      }
      // Fallback: parse from description if product is still Unknown
      if (product === "Unknown") {
        // Example pattern: "found in Zenvia Movidesk up to 25.01.22"
        const match = description.match(/found in\s+([\w\s]+)\s+up to\s+([\w\.]+)/i);
        if (match) {
          product = match[1].trim();
          affectedVersion = match[2].trim();
        }
      }

      await Vulnerability.findOneAndUpdate(
        { name: cveId },
        {
          name: cveId,
          description,
          product,
          affectedVersion,
          severity,
          cvssScore,
          status: "open"
        },
        { upsert: true }
      );

      updateProgress = Math.round(((i + 1) / total) * 100);
    }

    updateProgress = 100;
    // Update lastUpdateLog with timestamp and timeframe used
    lastUpdateLog = {
      timestamp: new Date().toISOString(),
      startDate,
      endDate,
      totalItems: total
    };
    console.log("Update complete!");
  } catch (error) {
    console.error("Error updating DB:", error);
  }
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
