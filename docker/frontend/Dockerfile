# docker/frontend/Dockerfile
FROM node:20-alpine AS frontend-build

WORKDIR /app/frontend-admin

COPY frontend-admin/package*.json ./

RUN npm install

COPY frontend-admin ./

CMD ["npm", "run", "build"]
