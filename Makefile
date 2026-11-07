.PHONY: build test vet fmt run image doctor

# Build the engine into bin/aos.
build:
	go build -o bin/aos ./cmd

# Run every test against a throwaway Postgres in Docker.
# It never connects to any other database. See scripts/test.sh.
test:
	./scripts/test.sh -count=1

vet:
	go vet ./...

fmt:
	gofmt -w .

# Run the API. Needs AOS_DATABASE_URL and AOS_MASTER_KEY.
run: build
	bin/aos serve

# Build the container image.
image:
	docker build -t aos:local .

# Check configuration, database, schema and keys.
doctor: build
	bin/aos doctor
