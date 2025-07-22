1. Run server :
- Go to the /server folder
- run :
´´´
./server -port=9000 (It can happen that the port for vless/vmess are blocking -> Just change the initial port)
´´´
</br>


2. Copy past the server-credentials.json file to the /client folder (erase previous credentials folder if already exist)
</br>


3. Run the client :
- In the /client folder
- run :
´´´
./client -test-all -host=127.0.0.1 -port=9000 -credentials=server-credentials.json
´´´
NOTE : The port must be the port of the server 
