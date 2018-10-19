make WITH_TINYDTLS=1 WITH_COAPSERVER=1 all
sudo service 6lbr stop
sudo make install
sudo systemctl daemon-reload
sudo service 6lbr start
