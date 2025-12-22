# test_azure_connection.py
"""
Quick test script to verify Azure OpenAI connection and configuration.
Run this to diagnose connection issues with Azure OpenAI.
"""

import os
import sys

# Load configuration from config module
from config import get as config_get

def check_env_variables():
    """Check if all required environment variables are set."""
    print("=" * 60)
    print("🔍 CHECKING ENVIRONMENT VARIABLES")
    print("=" * 60)
    
    required_vars = {
        "azure_openai.api_key": config_get("azure_openai", "api_key"),
        "azure_openai.endpoint": config_get("azure_openai", "endpoint"),
        "azure_openai.deployment": config_get("azure_openai", "deployment"),
    }
    
    optional_vars = {
        "azure_openai.api_version": config_get("azure_openai", "api_version", "2024-08-01-preview"),
        "azure_openai.model_name": config_get("azure_openai", "model_name"),
    }
    
    all_valid = True
    
    for var_name, var_value in required_vars.items():
        if not var_value:
            print(f"❌ {var_name}: NOT SET (REQUIRED)")
            all_valid = False
        elif "your-" in var_value.lower() or var_value == "":
            print(f"⚠️  {var_name}: PLACEHOLDER VALUE DETECTED")
            print(f"   Current value: {var_value[:50]}...")
            all_valid = False
        else:
            # Mask sensitive values
            masked = var_value[:8] + "..." + var_value[-4:] if len(var_value) > 15 else "****"
            print(f"✅ {var_name}: {masked}")
    
    print("\nOptional Variables:")
    for var_name, var_value in optional_vars.items():
        if var_value:
            print(f"   {var_name}: {var_value}")
        else:
            print(f"   {var_name}: Not set (using default)")
    
    return all_valid


def test_azure_connection():
    """Test the actual connection to Azure OpenAI."""
    print("\n" + "=" * 60)
    print("🔌 TESTING AZURE OPENAI CONNECTION")
    print("=" * 60)
    
    try:
        from openai import AzureOpenAI
        
        endpoint = config_get("azure_openai", "endpoint")
        api_key = config_get("azure_openai", "api_key")
        deployment = config_get("azure_openai", "deployment")
        api_version = config_get("azure_openai", "api_version", "2024-08-01-preview")
        
        if not all([endpoint, api_key, deployment]):
            print("❌ Missing required environment variables. Cannot test connection.")
            return False
        
        print(f"📡 Connecting to: {endpoint}")
        print(f"📦 Deployment: {deployment}")
        print(f"📋 API Version: {api_version}")
        
        client = AzureOpenAI(
            azure_endpoint=endpoint.strip(),
            api_key=api_key.strip(),
            api_version=api_version
        )
        
        print("\n⏳ Sending test request...")
        
        response = client.chat.completions.create(
            model=deployment,
            messages=[{"role": "user", "content": "Say 'Hello' in one word."}],
            max_tokens=10
        )
        
        result = response.choices[0].message.content
        print(f"\n✅ CONNECTION SUCCESSFUL!")
        print(f"   Response: {result}")
        print(f"   Model: {response.model}")
        print(f"   Usage: {response.usage.total_tokens} tokens")
        
        return True
        
    except Exception as e:
        error_type = type(e).__name__
        error_msg = str(e)
        
        print(f"\n❌ CONNECTION FAILED!")
        print(f"   Error Type: {error_type}")
        print(f"   Error Message: {error_msg}")
        
        # Provide helpful suggestions based on error
        if "401" in error_msg or "Unauthorized" in error_msg:
            print("\n💡 SUGGESTION: Your API key appears to be invalid or expired.")
            print("   - Check that AZURE_OPENAI_API_KEY is correct")
            print("   - Verify the key hasn't been revoked in Azure Portal")
        elif "404" in error_msg or "NotFound" in error_msg:
            print("\n💡 SUGGESTION: Deployment or endpoint not found.")
            print("   - Verify AZURE_OPENAI_DEPLOYMENT name is correct")
            print("   - Check that the deployment exists and is active")
        elif "Connection" in error_msg or "DNS" in error_msg:
            print("\n💡 SUGGESTION: Cannot reach Azure endpoint.")
            print("   - Check your internet connection")
            print("   - Verify AZURE_OPENAI_ENDPOINT URL is correct")
            print("   - URL should be: https://<your-resource>.openai.azure.com/")
        elif "quota" in error_msg.lower() or "rate" in error_msg.lower():
            print("\n💡 SUGGESTION: Rate limit or quota exceeded.")
            print("   - Wait a few minutes and try again")
            print("   - Check your Azure quota limits")
        
        return False


def test_model_factory():
    """Test the model factory with Azure OpenAI."""
    print("\n" + "=" * 60)
    print("🏭 TESTING MODEL FACTORY INTEGRATION")
    print("=" * 60)
    
    try:
        from models.model_factory import get_model
        
        print("⏳ Creating AzureOpenAIModel via factory...")
        model = get_model("azure_openai")
        
        print(f"✅ Model created: {model}")
        print(f"   Model name: {model.get_model_name()}")
        
        print("\n⏳ Testing generate() method...")
        response = model.generate("What is 2+2? Answer with just the number.")
        
        print(f"✅ Generate successful!")
        print(f"   Response: {response}")
        
        return True
        
    except Exception as e:
        print(f"❌ Model factory test failed: {e}")
        return False


def main():
    print("\n" + "=" * 60)
    print("🧪 AZURE OPENAI CONNECTION TEST")
    print("=" * 60)
    
    # Step 1: Check environment variables
    env_ok = check_env_variables()
    
    if not env_ok:
        print("\n" + "=" * 60)
        print("⚠️  CONFIGURATION ISSUES DETECTED")
        print("=" * 60)
        print("\nPlease update your config/config.ini file with valid Azure OpenAI credentials:")
        print("""
[azure_openai]
api_key = <your-actual-api-key>
endpoint = https://<your-resource-name>.openai.azure.com/
deployment = <your-deployment-name>
api_version = 2024-08-01-preview
        """)
        
        proceed = input("\nDo you still want to try connecting? (y/n): ").strip().lower()
        if proceed != 'y':
            print("Exiting...")
            return
    
    # Step 2: Test direct connection
    connection_ok = test_azure_connection()
    
    # Step 3: Test model factory (only if connection works)
    if connection_ok:
        factory_ok = test_model_factory()
    else:
        factory_ok = False
        print("\n⏭️  Skipping model factory test due to connection failure.")
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    print(f"   Environment Variables: {'✅ OK' if env_ok else '❌ ISSUES'}")
    print(f"   Azure Connection:      {'✅ OK' if connection_ok else '❌ FAILED'}")
    print(f"   Model Factory:         {'✅ OK' if factory_ok else '❌ FAILED'}")
    
    if connection_ok and factory_ok:
        print("\n🎉 All tests passed! Azure OpenAI is working correctly.")
    else:
        print("\n⚠️  Some tests failed. Please fix the issues above.")


if __name__ == "__main__":
    main()
