make WITH_TINYDTLS=1 WITH_COAPSERVER=1 WITH_DTLS_COAP all
sudo service 6lbr stop
sudo make install
sudo systemctl daemon-reload
sudo service 6lbr start
