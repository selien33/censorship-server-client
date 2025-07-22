## 1. Run the Server

- Navigate to the `/server` folder  
- Run the following command:

```bash
./server -port=9000
```

*Note: If the port is blocked (commonly by VLESS/VMess), simply change the port number.*

---

## 2. Prepare the Client

- Copy the `server-credentials.json` file into the `/client` folder  
- If a `credentials` folder already exists, delete or replace it

---

## 3. Run the Client

- Navigate to the `/client` folder  
- Run the following command:

```bash
./client -test-all -host=127.0.0.1 -port=9000 -credentials=server-credentials.json
```

*Note : Make sure the port matches the one used when starting the server.*
