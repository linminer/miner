sudo apt update
sudo apt upgrade
sudo add-apt-repository ppa:graphics-drivers
sudo apt install docker
sudo apt install ./cuda-repo-ubuntu1604-9-1-local_9.1.85-1_amd64.deb
sudo apt-key add /var/cuda-repo-9-1-local/7fa2af80.pub
sudo apt install ./cuda-repo-ubuntu1604-9-1-local_9.1.85-1_amd64.deb
sudo apt install libcurl4-gnutls-dev 
