FROM node:20-bullseye-slim

WORKDIR /app/ml-engine

COPY ml-engine/package*.json ./
RUN npm install

COPY ml-engine/ ./

EXPOSE 5000

CMD ["npm", "start"]
