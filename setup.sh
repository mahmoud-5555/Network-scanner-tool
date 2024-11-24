# This setup script is intended to be run on a fresh Ubuntu 18.04 LTS installation.
# It will install all necessary dependencies and set up the environment for the project.
# Please note that this script assumes that you are running it as a non-root user.
# If you are running it as root, you will need to remove the sudo commands.
echo "Starting setup script..."
# Update the package index
echo "Updating package index..."
sudo apt-get update
# install python3 if not already installed
if ! [ -x "$(command -v python3)" ]; then
  echo "Installing python3..."
  sudo apt-get install python3
else
  echo "Python3 is already installed."
fi
# install pip3 if not already installed
if ! [ -x "$(command -v pip3)" ]; then
  echo "Installing pip3..."
  sudo apt-get install python3-pip
else
  echo "Pip3 is already installed."
fi
# install virtualenv if not already installed
if ! [ -x "$(command -v virtualenv)" ]; then
  echo "Installing virtualenv..."
  sudo apt-get install virtualenv
else
  echo "Virtualenv is already installed."
fi
# create a virtual environment
echo "Creating a virtual environment..."
virtualenv venv
# activate the virtual environment
echo "Activating the virtual environment..."
source venv/bin/activate
# install the required python packages
echo "Installing the required python packages..."
pip3 install -r requirements.txt
# install the required system packages
echo "Installing the required system packages..."
sudo apt-get install libsm6 libxext6 libxrender-dev
