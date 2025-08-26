FROM golang:1.24

WORKDIR /app
COPY . .
RUN go mod tidy
# Instala o air para hot reload
RUN go install github.com/cosmtrek/air@v1.40.4
EXPOSE 8080
CMD ["air"]
