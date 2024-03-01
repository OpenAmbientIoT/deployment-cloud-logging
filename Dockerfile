# Use the official Node.js 16 image as a parent image
FROM node:16

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json (if available) to the container
COPY package*.json ./

# Install any dependencies
RUN npm install

# Copy the rest of your application's code to the container
COPY src/ ./

# Expose the port your app runs on
EXPOSE 8081

# Define the command to run your app, assuming server.js is in the src/ directory
CMD [ "node", "server.js" ]

