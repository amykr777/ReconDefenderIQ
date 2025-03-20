# ReconDefenderIQ

**ReconDefenderIQ** is a vulnerability vigilance and threat intelligence platform designed to help you track product vulnerabilities and stay up-to-date on the latest security news. It aggregates vulnerabilities from the [NVD (National Vulnerability Database)](https://nvd.nist.gov/) and displays threat news from various RSS feeds (Dark Reading, The Hacker News, Wired Security, Rapid7, etc.).

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [API Key Setup](#api-key-setup)
  - [NVD API Key](#nvd-api-key)
- [Project Structure](#project-structure)
- [Additional Notes](#additional-notes)

---

## Features

1. **User Management**  
   - Create, list, and delete users.  
   - Simple login system (credentials stored in MongoDB).

2. **Product Management**  
   - Add products with name, version, and category.  
   - Useful for specifying which products you want to monitor for vulnerabilities.

3. **Vulnerability Monitoring**  
   - Pulls vulnerabilities from the [NVD API](https://nvd.nist.gov/).  
   - Filters out vulnerabilities with `vulnStatus: "Awaiting Analysis"`.  
   - Parses product/version from CPE strings or from descriptions as a fallback.  
   - Lets you search vulnerabilities by name, product, or description.

4. **Threat News**  
   - Aggregates security news from multiple RSS feeds:
     - Dark Reading  
     - The Hacker News  
     - Wired Security  
     - Rapid7 (various feeds)  
   - Displays a combined, sortable table of news items with custom search.  

5. **API Management**  
   - Dedicated field to store your **NVD API Key**.  
   - Manage other API keys (if needed).

6. **Update DB**  
   - Lets you choose a date range (up to 120 days) to fetch vulnerabilities from NVD.  
   - Clears old vulnerabilities before each update.  
   - Shows a progress bar while updating.  
   - Logs the last update timestamp, date range, and total vulnerabilities retrieved.

---

## Prerequisites

- **Node.js** (v14 or above recommended)  
- **npm** (comes with Node.js)  
- **MongoDB** (running locally or remotely)  
- **rss-parser** (installed via `npm install rss-parser`)  
- **Internet Access** (to fetch NVD data and RSS feeds)

---

## Installation

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/your-username/ReconDefenderIQ.git
   cd ReconDefenderIQ
   ```

2. **Install Dependencies**  
   ```bash
   npm install
   ```

3. **Configure MongoDB**  
   - Ensure your MongoDB server is running on `mongodb://localhost:27017`.  
   - If using a different connection string or database name, edit the line in `app.js`:
     ```js
     mongoose.connect('mongodb://localhost:27017/ReconDefenderIQ', { ... });
     ```

4. **Run the Application**  
   ```bash
   npm start
   ```
   The server starts on port `3000` by default.

5. **Access the Web Interface**  
   - Go to [http://localhost:3000](http://localhost:3000) in your browser.  
   - Log in using the default admin credentials if no user is found (admin / admin).

---

## Usage

1. **Login**  
   - Navigate to [http://localhost:3000/login](http://localhost:3000/login).  
   - Use the admin credentials (`admin / admin`) or create a new user from `/settings`.

2. **Dashboard**  
   - Shows a quick overview of total vulnerabilities, products, vulnerability statuses, and the latest 20 vulnerabilities.

3. **Vulnerabilities**  
   - Displays a table of vulnerabilities (CVEs) fetched from the NVD.  
   - Search by name, description, or product.  
   - Only vulnerabilities with a non-zero CVSS score are shown.

4. **Product Management**  
   - Add or view products you wish to monitor.  
   - Name, version, and category fields are supported.

5. **API Management**  
   - **Dedicated NVD Key Field**: Enter your NVD API key and click “Save.”  
   - Other API Keys: Add any additional keys (if needed) by specifying a name and key.

6. **User Management**  
   - Create or remove users.  
   - Basic password storage (plaintext by default—use hashing in production).

7. **Threat News**  
   - Combines multiple RSS feeds (Dark Reading, Hacker News, Wired, Rapid7, etc.).  
   - Shows them in a searchable, sortable table.  
   - Searching filters news items by title or snippet.

8. **Update DB**  
   - Choose a date range (max 120 days) and start the update to fetch vulnerabilities from the NVD.  
   - A progress bar shows the update status.  
   - Clears old vulnerabilities before each update.

---

## API Key Setup

### NVD API Key

1. **Register for an NVD API Key**  
   - Go to [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).  
   - Copy your key once you receive it.

2. **Add the Key in ReconDefenderIQ**  
   - Log in and go to **API Management**.  
   - Under **NVD API Key**, paste your key in the input box.  
   - Click **Save**.  
   - The system will store it in MongoDB.  
   - This key is used when fetching vulnerabilities from NVD.

3. **Other API Keys**  
   - If you need additional keys for other services, add them in the “Other API Keys” section by specifying a name and the key.

---

## Project Structure

```
ReconDefenderIQ/
├── app.js
├── package.json
├── models/
│   ├── ApiKey.js
│   ├── Product.js
│   ├── User.js
│   └── Vulnerability.js
├── views/
│   ├── login.ejs
│   ├── dashboard.ejs
│   ├── vulnerabilities.ejs
│   ├── products.ejs
│   ├── api-management.ejs
│   ├── settings.ejs
│   ├── update-db.ejs
│   ├── threat-news.ejs
│   └── partials/
│       └── sidebar.ejs
├── public/
│   ├── css/
│   │   └── styles.css
│   └── js/
│       └── (client scripts if any)
└── (other files)
```

- **app.js**: Main server file (Express, routes, database connections).  
- **models/**: Mongoose models for `User`, `Vulnerability`, `Product`, `ApiKey`.  
- **views/**: EJS templates for each page (login, dashboard, vulnerabilities, etc.).  
- **public/**: Static files (CSS, client JS, images).  

---

## Additional Notes

- **Security**:  
  - By default, passwords are stored in plaintext. Use a library like [bcrypt](https://www.npmjs.com/package/bcrypt) to hash them in production.  
  - The NVD API key is stored in MongoDB as plain text. Consider encryption or environment variables if required.  
- **RSS Feeds**:  
  - The threat news aggregator uses multiple feeds. If any feed is temporarily unavailable, you may see fewer items or an error message.  
- **Date Range**:  
  - The Update DB function enforces a 120‑day max range to comply with NVD’s API constraints.  
- **Production**:  
  - Use a process manager (like PM2) and a secure environment.  
  - Configure environment variables for sensitive credentials and production DB connections.
