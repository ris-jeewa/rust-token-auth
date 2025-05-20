# Rust RBAC Authentication Service

A secure web service built with Rust that implements Role-Based Access Control (RBAC) with JWT authentication.

## Features

- JWT-based authentication
- Role-Based Access Control (RBAC) using Casbin
- PostgreSQL database integration
- Secure password hashing with bcrypt
- RESTful API endpoints
- Axum web framework

## Prerequisites

- Rust (latest stable version)
- PostgreSQL
- Cargo (Rust's package manager)

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
DATABASE_URL=postgres://username:password@localhost:5432/dbname
JWT_SECRET=your_jwt_secret_key
RUST_LOG=debug
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd sample-project2
```

2. Install dependencies:
```bash
cargo build
```

3. Set up the database:
```bash
psql -U your_username -d your_database -f schema.sql
```

4. Run the application:
```bash
cargo run
```

The server will start at `http://localhost:3000`

## API Endpoints

- `POST /register` - Register a new user
- `POST /login` - Login and get JWT token
- `GET /protected` - Protected resource (requires authentication)
- `GET /` - Home endpoint

## RBAC Configuration

The RBAC system is configured using two main files:

1. `rbac_model.conf` - Defines the RBAC model
2. `rbac_policy.csv` - Defines roles and permissions

## License

MIT 