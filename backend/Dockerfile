FROM node:20-bullseye-slim

WORKDIR /app/backend

COPY backend/package*.json ./
RUN npm install

COPY backend/ ./
COPY ml-engine ../ml-engine

EXPOSE 3000

CMD ["npm", "start"]
