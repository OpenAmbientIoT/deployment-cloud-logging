# Websocket server for logging and control

This is a simple websocket server that can be used to log messages and control a process. It is written in Python and uses the `websockets` library.

## Running the server using Docker

The server can be run using Docker. The following command will build the Docker image and run the server:

```bash
docker build -t websocket-server .
docker run -p 8081:8081 websocket-servers
```

