FROM node:24-alpine

WORKDIR /app

COPY package*.json ./

RUN npm ci

EXPOSE 3000

ENV REACT_APP_API_URL=http://localhost:8000
ENV NODE_ENV=development
ENV WATCHPACK_POLLING=true

CMD ["npm", "start"]
