# DropSphere Server

DropSphere backend API built with Express and MongoDB native driver.

Main server file: `index.js`

## What It Does

- Handles user auth (local email/password + Firebase token login).
- Serves product catalog with pagination, filtering, sorting, and search.
- Supports product reviews and auto-updates product rating/review count.
- Handles order creation, order history, and admin order status updates.
- Integrates Stripe checkout and payment intent endpoints.
- Secures API with JWT auth, CORS, rate limiting, sanitization, and Helmet.

## Setup

```bash
npm install
cp .env.example .env
npm run dev
```

## Environment Variables

| Name | Description |
| --- | --- |
| `MONGODB_URI` or `MONGO_URI` | MongoDB connection string. |
| `JWT_SECRET` | Secret used to sign and verify JWT tokens. |
| `STRIPE_SECRET_KEY` | Stripe secret key for checkout/session/payment intent APIs. |
| `CLIENT_URL` | Frontend URL used for Stripe success/cancel redirects. |
| `CORS_ORIGIN` | Allowed frontend origin(s), comma-separated. |
| `PORT` | Local server port (default `5020`). |
| `FIREBASE_PROJECT_ID` | Firebase project ID for admin token verification. |
| `FIREBASE_CLIENT_EMAIL` | Firebase service account client email. |
| `FIREBASE_PRIVATE_KEY` | Firebase service account private key. |
| `FIREBASE_SERVICE_ACCOUNT` | Optional full service-account JSON string. |

## Firebase Setup

1. Open Firebase Console -> Project Settings -> Service Accounts.
2. Generate a new private key.
3. Put values in `.env` using either:
   - `FIREBASE_PROJECT_ID`, `FIREBASE_CLIENT_EMAIL`, `FIREBASE_PRIVATE_KEY`, or
   - `FIREBASE_SERVICE_ACCOUNT` JSON.

## Product Query API

### `GET /api/products`

Supported query params:

- `page` (number, default: `1`)
- `limit` (number, default: `12`, max: `100`)
- `category` (string)
- `sort` = `featured | newest | price-low | price-high | rating`
- `maxPrice` (number)
- `minRating` (number) - `rating` is also accepted as alias
- `q` or `search` (string) for text search

Response shape:

```json
{
  "items": [],
  "page": 1,
  "pages": 1,
  "total": 0,
  "limit": 12
}
```

Featured sort logic is server-defined to stay consistent:

- `orders DESC`
- `views DESC`
- `rating DESC`
- `createdAt DESC`

### `GET /api/products/categories`

Returns distinct categories:

```json
["Clothing", "Electronics"]
```

## API Endpoints

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/api/health` | No | API health + DB connectivity check. |
| POST | `/api/auth/register` | No | Register local user and return JWT. |
| POST | `/api/auth/login` | No | Login local user and return JWT. |
| POST | `/api/auth/firebase` | No | Login/signup via Firebase ID token. |
| GET | `/api/auth/me` | Bearer | Return authenticated user. |
| GET | `/api/products` | No | Paginated products with filter/sort/search. |
| GET | `/api/products/categories` | No | Distinct product categories. |
| GET | `/api/products/:id` | No | Product details + reviews. |
| GET | `/api/products/:id/reviews` | No | Product reviews only. |
| POST | `/api/products` | Admin | Create product. |
| PUT | `/api/products/:id` | Admin | Update product. |
| DELETE | `/api/products/:id` | Admin | Delete product and its reviews. |
| POST | `/api/products/:id/reviews` | Bearer | Add review and refresh rating. |
| POST | `/api/payments/create-checkout-session` | Bearer | Create Stripe checkout session. |
| GET | `/api/payments/verify-session` | No | Verify Stripe checkout session. |
| POST | `/api/orders/create-payment-intent` | Bearer | Create Stripe payment intent. |
| POST | `/api/orders` | Bearer | Create order for authenticated user. |
| GET | `/api/orders/my` | Bearer | Get current user's orders. |
| GET | `/api/orders` | Admin | Get all orders. |
| PUT | `/api/orders/:id/status` | Admin | Update order status. |
| GET | `/api/users/profile` | Bearer | Get current profile. |
| PUT | `/api/users/profile` | Bearer | Update current profile. |
| GET | `/api/users/all` | Admin | List all users (without passwords). |

## Database Indexes

On startup, the server ensures product indexes for faster queries:

- `category`
- `price`
- `rating`
- `createdAt`
- compound featured index: `orders`, `views`, `rating`, `createdAt`
- text index on `name`, `description`, `tags`

## Deploy to Vercel

```bash
vercel
```
# dropsphere-server
