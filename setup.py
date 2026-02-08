# setup.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ethical Hacking Learning Environment Setup
Windows 11 | Python 3.10.10
Author: Your Mentor
"""

import sys
import subprocess
import os

def check_python_version():
    """Check if Python version is 3.10.10"""
    print("🔍 Checking Python version...")
    if sys.version_info.major == 3 and sys.version_info.minor == 10:
        print("✅ Python 3.10.10 compatible!")
        return True
    else:
        print(f"⚠️  You have Python {sys.version_info.major}.{sys.version_info.minor}")
        print("   This course is designed for Python 3.10.10")
        print("   Download from: https://www.python.org/downloads/")
        return False

def install_requirements():
    """Install required packages"""
    print("\n📦 Installing requirements...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ All packages installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Installation failed: {e}")
        return False
    return True

def create_project_structure():
    """Create project directory structure"""
    print("\n📁 Creating project structure...")
    
    directories = [
        'modules',
        'tools',
        'labs',
        'data',
        'reports',
        'logs'
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"   Created: {directory}/")
    
    # Create sample lab files
    with open('labs/README.md', 'w') as f:
        f.write("# Ethical Hacking Labs\n\nStart with lab1.py")
    
    print("✅ Project structure created!")

def main():
    print("=" * 50)
    print("ETHICAL HACKING LEARNING ENVIRONMENT SETUP")
    print("=" * 50)
    
    if not check_python_version():
        return
    
    print("\n🚀 Starting setup process...")
    
    # Create directories first
    create_project_structure()
    
    # Install packages
    install_requirements()
    
    print("\n" + "=" * 50)
    print("🎉 SETUP COMPLETE!")
    print("\nNext steps:")
    print("1. python basic_scanner.py")
    print("2. python network_scanner.py")
    print("3. python password_checker.py")
    print("=" * 50)

if __name__ == "__main__":
    main()