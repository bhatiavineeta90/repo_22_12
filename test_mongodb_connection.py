"""
MongoDB Connection Test Script
Tests MongoDB connection and basic CRUD operations.
"""

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from datetime import datetime
import sys

# MongoDB Configuration
# Option 1: Local MongoDB
MONGO_URI = "mongodb://localhost:27017/"

# Option 2: MongoDB Atlas (Cloud) - Uncomment and update with your credentials
# MONGO_URI = "mongodb+srv://<username>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority"

DATABASE_NAME = "redteam_test"
COLLECTION_NAME = "test_collection"


def test_mongodb_connection():
    """Test MongoDB connection and basic operations."""
    
    print("=" * 60)
    print("MongoDB Connection Test")
    print("=" * 60)
    print(f"\nConnecting to: {MONGO_URI}")
    print(f"Database: {DATABASE_NAME}")
    print(f"Collection: {COLLECTION_NAME}\n")
    
    try:
        # Step 1: Connect to MongoDB
        print("📡 Step 1: Attempting to connect to MongoDB...")
        client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=5000  # 5 second timeout
        )
        
        # Verify connection by pinging the server
        client.admin.command('ping')
        print("✅ Successfully connected to MongoDB!")
        
        # Get server info
        server_info = client.server_info()
        print(f"   MongoDB Version: {server_info.get('version', 'Unknown')}")
        print(f"   Server Time: {datetime.now()}\n")
        
        # Step 2: Access database and collection
        print("📁 Step 2: Accessing database and collection...")
        db = client[DATABASE_NAME]
        collection = db[COLLECTION_NAME]
        print(f"✅ Database '{DATABASE_NAME}' accessed")
        print(f"✅ Collection '{COLLECTION_NAME}' accessed\n")
        
        # Step 3: Insert a test document (CREATE)
        print("➕ Step 3: Testing INSERT operation...")
        test_document = {
            "test_id": "test_001",
            "message": "Hello MongoDB!",
            "timestamp": datetime.utcnow(),
            "test_data": {
                "framework": "Red Team Testing",
                "llm_provider": "gemini",
                "attack_type": "linear_jailbreaking"
            }
        }
        
        insert_result = collection.insert_one(test_document)
        print(f"✅ Document inserted with ID: {insert_result.inserted_id}\n")
        
        # Step 4: Read the document (READ)
        print("🔍 Step 4: Testing READ operation...")
        found_document = collection.find_one({"test_id": "test_001"})
        if found_document:
            print("✅ Document retrieved successfully:")
            print(f"   ID: {found_document['_id']}")
            print(f"   Message: {found_document['message']}")
            print(f"   Timestamp: {found_document['timestamp']}")
            print(f"   Test Data: {found_document['test_data']}\n")
        else:
            print("❌ Document not found!\n")
            return False
        
        # Step 5: Update the document (UPDATE)
        print("✏️  Step 5: Testing UPDATE operation...")
        update_result = collection.update_one(
            {"test_id": "test_001"},
            {"$set": {"message": "MongoDB connection test successful!", "updated": True}}
        )
        print(f"✅ Documents matched: {update_result.matched_count}")
        print(f"✅ Documents modified: {update_result.modified_count}\n")
        
        # Verify update
        updated_document = collection.find_one({"test_id": "test_001"})
        print(f"   Updated message: {updated_document['message']}\n")
        
        # Step 6: Count documents
        print("🔢 Step 6: Testing COUNT operation...")
        doc_count = collection.count_documents({})
        print(f"✅ Total documents in collection: {doc_count}\n")
        
        # Step 7: Query with filter
        print("🔎 Step 7: Testing QUERY with filter...")
        query_result = collection.find({"test_data.llm_provider": "gemini"})
        query_count = collection.count_documents({"test_data.llm_provider": "gemini"})
        print(f"✅ Found {query_count} documents with llm_provider='gemini'\n")
        
        # Step 8: Delete the test document (DELETE)
        print("🗑️  Step 8: Testing DELETE operation...")
        delete_result = collection.delete_one({"test_id": "test_001"})
        print(f"✅ Documents deleted: {delete_result.deleted_count}\n")
        
        # Step 9: List all databases
        print("📚 Step 9: Listing all databases...")
        databases = client.list_database_names()
        print(f"✅ Available databases: {', '.join(databases)}\n")
        
        # Step 10: List all collections in our database
        print("📋 Step 10: Listing all collections in '{}'...".format(DATABASE_NAME))
        collections = db.list_collection_names()
        if collections:
            print(f"✅ Collections: {', '.join(collections)}\n")
        else:
            print("✅ No collections yet (this is expected for a new database)\n")
        
        # Clean up - drop the test collection
        print("🧹 Cleanup: Dropping test collection...")
        db.drop_collection(COLLECTION_NAME)
        print("✅ Test collection dropped\n")
        
        # Close connection
        client.close()
        print("🔌 Connection closed")
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED! MongoDB is working correctly!")
        print("=" * 60)
        
        return True
        
    except ConnectionFailure as e:
        print(f"\n❌ ERROR: Failed to connect to MongoDB")
        print(f"   Error: {e}")
        print(f"\n💡 Troubleshooting tips:")
        print(f"   1. Make sure MongoDB is running (run 'mongod' in terminal)")
        print(f"   2. Check if MongoDB is running on port 27017")
        print(f"   3. Verify the connection URI: {MONGO_URI}")
        print(f"   4. If using MongoDB Atlas, check your network IP whitelist")
        return False
        
    except ServerSelectionTimeoutError as e:
        print(f"\n❌ ERROR: Could not connect to MongoDB server (timeout)")
        print(f"   Error: {e}")
        print(f"\n💡 Troubleshooting tips:")
        print(f"   1. Check if MongoDB service is running")
        print(f"   2. Verify the connection string")
        print(f"   3. Check firewall settings")
        return False
        
    except Exception as e:
        print(f"\n❌ ERROR: An unexpected error occurred")
        print(f"   Error: {e}")
        print(f"   Error type: {type(e).__name__}")
        return False


def check_pymongo_installed():
    """Check if pymongo is installed."""
    try:
        import pymongo
        print(f"✅ pymongo version {pymongo.__version__} is installed\n")
        return True
    except ImportError:
        print("❌ ERROR: pymongo is not installed!")
        print("\n💡 To install pymongo, run:")
        print("   pip install pymongo")
        print("\nOr for additional features:")
        print("   pip install 'pymongo[srv]'  # For MongoDB Atlas support")
        return False


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("MongoDB Connection Test Script")
    print("=" * 60 + "\n")
    
    # Check if pymongo is installed
    if not check_pymongo_installed():
        sys.exit(1)
    
    # Run the test
    success = test_mongodb_connection()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)
