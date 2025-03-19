// app.js
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const path = require('path');
const axios = require('axios'); // For NVD API calls
const Parser = require('rss-parser'); // For parsing RSS feeds
const parser = new Parser();

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
mongoose.connect('mongodb://localhost:27017/ReconDefenderIQ', {
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
app.get('/dashboard', async (req, res) => {
  try {
      // Fetch total counts
      const totalVulnerabilities = await Vulnerability.countDocuments();
      const totalProducts = await Product.countDocuments();

      // Fetch latest vulnerabilities
      const latestVulns = await Vulnerability.find().sort({ createdAt: -1 }).limit(5);

      // Fetch vulnerability status counts
      const statusCounts = await Vulnerability.aggregate([
          { $group: { _id: "$status", count: { $sum: 1 } } }
      ]);

      // Fetch product category counts
      const categoryCounts = await Product.aggregate([
          { $group: { _id: "$category", count: { $sum: 1 } } }
      ]);

      res.render('dashboard', {
          totalVulnerabilities,
          totalProducts,
          latestVulns,
          statusCounts,
          categoryCounts
      });

  } catch (error) {
      console.error('Error fetching dashboard data:', error);
      res.status(500).send('Internal Server Error');
  }
});

// --- All Vulnerabilities Route ---
app.get('/all-vulnerabilities', isAuthenticated, async (req, res) => {
  const searchTerm = req.query.search || '';
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
  res.render('all-vulnerabilities', { vulnerabilities, searchTerm });
});

// --- Your Vulnerabilities Route ---
app.get('/your-vulnerabilities', isAuthenticated, async (req, res) => {
  const searchTerm = req.query.search || '';

  // Fetch product names from the Product Management
  const products = await Product.find({});
  const productNames = products.map(p => p.name.toLowerCase());

  // Build a regex combining all product names
  const regexString = productNames.join('|'); // e.g. "farmacia|windows|ubuntu"

  // Base query: vulnerabilities whose product is in productNames or description contains them
  let baseQuery = {
    $or: [
      { product: { $in: productNames } },
      { description: { $regex: regexString, $options: 'i' } }
    ]
  };

  if (searchTerm) {
    const searchRegex = { $regex: searchTerm, $options: 'i' };
    baseQuery = {
      $and: [
        baseQuery,
        {
          $or: [
            { name: searchRegex },
            { description: searchRegex },
            { product: searchRegex }
          ]
        }
      ]
    };
  }

  const vulnerabilities = await Vulnerability.find(baseQuery);
  res.render('your-vulnerabilities', { vulnerabilities, searchTerm });
});

// --- POST route for updating vulnerability status ---
app.post('/vulnerabilities/update-status/:id', isAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    await Vulnerability.findByIdAndUpdate(id, { status });
    // Use recommended redirect method instead of 'back'
    res.redirect(req.get("Referrer") || "/");
  } catch (error) {
    console.error('Error updating vulnerability status:', error);
    res.redirect(req.get("Referrer") || "/");
  }
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
// GET: Render API management page with all keys and the dedicated NVD key.
app.get('/api-management', isAuthenticated, async (req, res) => {
  const apiKeys = await ApiKey.find({});
  const nvdApiKey = await ApiKey.findOne({ apiName: 'NVD' });
  res.render('api-management', { apiKeys, nvdApiKey });
});

app.post('/api-management/add', isAuthenticated, async (req, res) => {
  const { apiName, apiKey } = req.body;
  const newApiKey = new ApiKey({ apiName, apiKey });
  await newApiKey.save();
  res.redirect('/api-management');
});

app.post('/api-management/update-nvd', isAuthenticated, async (req, res) => {
  const { apiKey } = req.body;
  let nvdKey = await ApiKey.findOne({ apiName: 'NVD' });
  if (nvdKey) {
    nvdKey.apiKey = apiKey;
    await nvdKey.save();
  } else {
    nvdKey = new ApiKey({ apiName: 'NVD', apiKey });
    await nvdKey.save();
  }
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
app.get('/update-db', isAuthenticated, (req, res) => {
  res.render('update-db', { lastUpdateLog });
});

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

app.get('/update-db/progress', isAuthenticated, (req, res) => {
  res.json({ progress: updateProgress });
});

// --- Threat News Route ---
app.get('/threat-news', isAuthenticated, async (req, res) => {
  try {
    const searchTerm = req.query.search || '';
    // List of RSS feed URLs:
    const feedUrls = [
      'https://www.darkreading.com/rss.xml',
      'https://feeds.feedburner.com/TheHackersNews',
      'https://www.wired.com/feed/category/security/latest/rss',
      'https://blog.rapid7.com/tag/emergent-threat-response/rss/',
      'https://blog.rapid7.com/tag/research/rss/',
      'https://blog.rapid7.com/tag/detection-and-response/rss/',
      'https://blog.rapid7.com/tag/vulnerability-management/rss/',
      'https://blog.rapid7.com/tag/cloud-security/rss/',
      'https://blog.rapid7.com/rss/'
    ];
    // Fetch all feeds in parallel
    const feeds = await Promise.all(feedUrls.map(url => parser.parseURL(url)));
    let combinedItems = [];
    feeds.forEach(feed => {
      if (feed.items) {
        combinedItems = combinedItems.concat(feed.items);
      }
    });
    // Sort by publication date descending
    combinedItems.sort((a, b) => new Date(b.pubDate) - new Date(a.pubDate));
    // Filter by search term if provided
    if (searchTerm) {
      const lowerSearch = searchTerm.toLowerCase();
      combinedItems = combinedItems.filter(item =>
        (item.title && item.title.toLowerCase().includes(lowerSearch)) ||
        (item.contentSnippet && item.contentSnippet.toLowerCase().includes(lowerSearch)) ||
        (item.content && item.content.toLowerCase().includes(lowerSearch))
      );
    }
    res.render('threat-news', { feed: { items: combinedItems }, error: null, searchTerm });
  } catch (err) {
    console.error("Error fetching RSS feeds:", err);
    res.render('threat-news', { feed: null, error: 'Unable to load news at this time.', searchTerm: '' });
  }
});

// --- Update Database Function ---
async function updateDatabase(startDate, endDate) {
  try {
    // Clear previous vulnerabilities
    await Vulnerability.deleteMany({});

    // Retrieve the NVD API key (if any)
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
    // Fetch vulnerabilities in chunks
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

    // Sort by published date descending
    allItems.sort((a, b) => new Date(b.cve.published) - new Date(a.cve.published));

    const total = allItems.length;
    for (let i = 0; i < total; i++) {
      const item = allItems[i];
      const cveId = item?.cve?.id || "UNKNOWN";

      // Parse description (prefer English)
      let description = "No description provided";
      const descObj = item?.cve?.descriptions?.find(d => d.lang === "en");
      if (descObj && descObj.value) {
        description = descObj.value;
      }

      // Parse severity and CVSS Score
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

      // Parse product and affected version:
      // Primary: from configurations criteria if available
      let product = "Unknown";
      let affectedVersion = "N/A";
      const configs = item?.cve?.configurations || [];
      if (configs.length > 0) {
        const nodes = configs[0].nodes || [];
        if (nodes.length > 0) {
          const cpeMatches = nodes[0].cpeMatch || [];
          if (cpeMatches.length > 0) {
            const cpe = cpeMatches[0].criteria; // e.g., "cpe:2.3:a:cmseasy:cmseasy:7.7.7.9:*:*:*:*:*:*:*"
            const parts = cpe.split(':');
            if (parts.length >= 6) {
              product = parts[4] || product;
              affectedVersion = parts[5] || affectedVersion;
            }
          }
        }
      }
      // Fallback: parse from description if product is still "Unknown"
      if (product === "Unknown") {
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
    // Update lastUpdateLog with timestamp and date range used
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
