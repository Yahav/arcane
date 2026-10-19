import 'settings.just'

set working-directory := '..'

[default]
[private]
list:
    @{{ just_executable() }} --justfile {{ justfile() }} --list lint

all: js go proto

# Frontend, Playwright tests, and email templates
js: frontend tests email

# Type check and lint the frontend
frontend:
    vp -C frontend run check
    vp -C frontend run lint

# Type check Playwright tests
tests:
    vp -C tests run check

# Type check email templates
email:
    vp -C email-templates run check

# Backend, CLI, and types modules
go: backend cli types

backend:
    cd backend && golangci-lint run --allow-parallel-runners -c ../.golangci.yml ./...

cli:
    cd cli && golangci-lint run --allow-parallel-runners -c ../.golangci.yml ./...

types:
    cd types && golangci-lint run --allow-parallel-runners -c ../.golangci.yml ./...

# Edge tunnel protobuf definitions
proto:
    cd {{ edge_proto_dir }} && go run github.com/bufbuild/buf/cmd/buf@latest lint
