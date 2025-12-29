# MongoDB Setup Guide

## Quick Start

### Option 1: Local MongoDB Installation

#### Windows
1. Download MongoDB Community Server from [mongodb.com](https://www.mongodb.com/try/download/community)
2. Install with default settings
3. MongoDB service should start automatically

**To manually start MongoDB:**
```powershell
# Start MongoDB service
net start MongoDB

# Or run mongod directly
mongod --dbpath C:\data\db
```

#### Check if MongoDB is running:
```powershell
# Check MongoDB service status
sc query MongoDB

# Or try connecting
mongosh
```

---

### Option 2: MongoDB Atlas (Cloud - Free Tier)

1. Go to [mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas)
2. Create a free account
3. Create a free cluster (M0)
4. Get your connection string:
   - Click "Connect" → "Connect your application"
   - Copy the connection string
   - Replace `<password>` with your password

**Connection string format:**
```
mongodb+srv://<username>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority
```

**Update in test script:**
```python
# In test_mongodb_connection.py, update line 12:
MONGO_URI = "mongodb+srv://your_username:your_password@cluster0.xxxxx.mongodb.net/"
```

---

## Install Python MongoDB Driver

```bash
# Basic installation
pip install pymongo

# With MongoDB Atlas support
pip install 'pymongo[srv]'
```

---

## Run the Test Script

```bash
# Navigate to project directory
cd "c:\Users\Lalit sharma\Downloads\repo_08_12-main\repo_08_12-main"

# Run the test
python test_mongodb_connection.py
```

---

## Expected Output

If successful, you should see:
```
✅ Successfully connected to MongoDB!
✅ Document inserted with ID: ...
✅ Document retrieved successfully
✅ ALL TESTS PASSED! MongoDB is working correctly!
```

---

## Troubleshooting

### Error: "Failed to connect to MongoDB"

**Solution 1 - MongoDB not running:**
```powershell
# Start MongoDB service
net start MongoDB
```

**Solution 2 - Wrong port:**
Check if MongoDB is running on port 27017:
```powershell
netstat -ano | findstr :27017
```

**Solution 3 - Firewall:**
Allow MongoDB through Windows Firewall (port 27017)

---

### Error: "pymongo is not installed"

```bash
pip install pymongo
```

---

### Error: "ServerSelectionTimeoutError"

**For Local MongoDB:**
- Ensure MongoDB service is running
- Check if port 27017 is available

**For MongoDB Atlas:**
- Check your username/password
- Verify network access in Atlas (add your IP to whitelist)
- Ensure correct connection string

---

## MongoDB GUI Tools (Optional)

**MongoDB Compass** (Official GUI):
- Download from [mongodb.com/products/compass](https://www.mongodb.com/products/compass)
- Great for visualizing data

**Studio 3T** (Free version available):
- Download from [studio3t.com](https://studio3t.com/)
- More features for development

---

## Next Steps

Once MongoDB connection test passes:
1. ✅ MongoDB is ready to use
2. You can start implementing the plugin architecture
3. Create the database schema as per the design document

---

## Configuration for Your Application

After successful test, update your application config:

```python
# config.py or .env
MONGO_URI = "mongodb://localhost:27017/"  # or your Atlas URI
MONGO_DB_NAME = "redteam"
```

Use in your app:
```python
from pymongo import MongoClient

client = MongoClient(MONGO_URI)
db = client[MONGO_DB_NAME]
collection = db.test_results
```
