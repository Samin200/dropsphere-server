// 1. IMPORTS
import "express-async-errors";
import dotenv from "dotenv";
import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import cors from "cors";
import morgan from "morgan";
import helmet from "helmet";
import mongoSanitize from "express-mongo-sanitize";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Stripe from "stripe";
import { body, query, validationResult } from "express-validator";
import admin from "firebase-admin";

dotenv.config();

const mongoUri = process.env.MONGODB_URI || process.env.MONGO_URI || "";

if (!mongoUri) {
  console.warn("[WARN] Missing MONGODB_URI (or MONGO_URI) in environment variables.");
}
if (!process.env.JWT_SECRET) {
  console.warn("[WARN] Missing JWT_SECRET in environment variables.");
}
if (!process.env.STRIPE_SECRET_KEY) {
  console.warn("[WARN] Missing STRIPE_SECRET_KEY in environment variables.");
}

const PORT = process.env.PORT || 5020;
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

// 4. FIREBASE ADMIN INIT
let firebaseReady = false;

try {
  let serviceAccount = null;

  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  } else if (
    process.env.FIREBASE_PROJECT_ID &&
    process.env.FIREBASE_CLIENT_EMAIL &&
    process.env.FIREBASE_PRIVATE_KEY
  ) {
    serviceAccount = {
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    };
  }

  if (serviceAccount) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    firebaseReady = true;
  } else {
    console.warn(
      "[WARN] Firebase Admin credentials missing. Firebase auth route will be unavailable."
    );
  }
} catch (error) {
  console.warn("[WARN] Firebase Admin initialization failed:", error.message);
}

const client = new MongoClient(mongoUri, {
  serverApi: { version: "1", strict: true, deprecationErrors: true },
});

let usersCollection;
let productsCollection;
let ordersCollection;
let reviewsCollection;
let dbConnected = false;
let dbConnecting = false;

async function ensureProductIndexes() {
  try {
    await Promise.allSettled([
      productsCollection.createIndex({ category: 1 }),
      productsCollection.createIndex({ price: 1 }),
      productsCollection.createIndex({ rating: -1 }),
      productsCollection.createIndex({ createdAt: -1 }),
      productsCollection.createIndex({ orders: -1, views: -1, rating: -1, createdAt: -1 }),
      productsCollection.createIndex({ name: "text", description: "text", tags: "text" }),
    ]);
  } catch (error) {
    console.warn("[DB] Failed to ensure product indexes:", error.message);
  }
}

async function ensureDB() {
  if (dbConnected) return true;
  if (dbConnecting) {
    while (dbConnecting) await new Promise(r => setTimeout(r, 100));
    return dbConnected;
  }
  dbConnecting = true;
  try {
    await client.connect();
    const db = client.db("dropsphere");
    usersCollection = db.collection("users");
    productsCollection = db.collection("products");
    ordersCollection = db.collection("orders");
    reviewsCollection = db.collection("reviews");
    await ensureProductIndexes();
    dbConnected = true;
    console.log("MongoDB Connected Successfully");
    return true;
  } catch (error) {
    console.warn("[WARN] MongoDB connection failed:", error.message);
    return false;
  } finally {
    dbConnecting = false;
  }
}

async function dbGuard(req, res, next) {
  const connected = await ensureDB();
  if (!connected) {
    return res.status(503).json({ error: "Database not available. Please try again later." });
  }
  next();
}

// 7. EXPRESS APP SETUP
const app = express();
app.set("trust proxy", 1);

app.use(helmet());

const allowedOrigins = [
  "https://drop-sphere.vercel.app",
  "http://localhost:5173",
  "http://localhost:5174",
  process.env.CLIENT_URL,
  process.env.CORS_ORIGIN,
]
  .filter(Boolean)
  .flatMap((origin) => String(origin).split(","))
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.use(express.json());
app.use(mongoSanitize());
app.use(morgan("dev"));

// 8. RATE LIMITER
const createLimiter = (max) => {
  if (process.env.NODE_ENV === "development") {
    return (req, res, next) => next();
  }

  return rateLimit({
    windowMs: 15 * 60 * 1000,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests, please try again later." },
  });
};

const authLimiter = createLimiter(50);
const apiLimiter = createLimiter(200);

app.use("/api", apiLimiter);
app.use("/api/auth", authLimiter);

// 9. HELPERS
function generateToken(id, role) {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, { expiresIn: "7d" });
}

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res
      .status(400)
      .json({ message: "Validation error", errors: errors.array() });
  }
  next();
}

// 10. AUTH MIDDLEWARE
async function protect(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await usersCollection.findOne({ _id: new ObjectId(decoded.id) }, { projection: { password: 0 } });

    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ message: "Forbidden: admin only" });
  }
  next();
}

// 11. ROUTES

// ── HEALTH ───────────────────────────────────────────────────
app.get('/api/health', dbGuard, (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    db: dbConnected ? 'connected' : 'disconnected'
  });
});

// ── AUTH ROUTES ──────────────────────────────────────────────
app.post(
  "/api/auth/register",
  dbGuard,
  [
    body("name").isLength({ min: 2, max: 50 }),
    body("email").isEmail(),
    body("password").isLength({ min: 6 }),
  ],
  validate,
  async (req, res) => {
    const { name, email, password } = req.body;

    const existing = await usersCollection.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({ message: "Email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await usersCollection.insertOne({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      authProvider: "local",
      role: "user",
      address: "",
      avatar: "",
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const user = await usersCollection.findOne({ _id: result.insertedId });
    const token = generateToken(result.insertedId.toString(), user.role);
    const safeUser = { ...user, password: undefined };
    delete safeUser.password;

    res.status(201).json({ user: safeUser, token });
  }
);

app.post(
  "/api/auth/login",
  dbGuard,
  [body("email").isEmail(), body("password").isString().isLength({ min: 1 })],
  validate,
  async (req, res) => {
    const { email, password } = req.body;
    const user = await usersCollection.findOne({ email: email.toLowerCase() });

    if (!user || !user.password) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = generateToken(user._id.toString(), user.role);
    const safeUser = { ...user };
    delete safeUser.password;

    res.json({ user: safeUser, token });
  }
);

app.post(
  "/api/auth/firebase",
  dbGuard,
  [body("idToken").isString().isLength({ min: 1 })],
  validate,
  async (req, res) => {
    if (!firebaseReady) {
      return res
        .status(503)
        .json({ message: "Firebase authentication is not configured" });
    }

    const { idToken } = req.body;
    const decoded = await admin.auth().verifyIdToken(idToken);

    if (!decoded.email) {
      return res.status(400).json({ message: "Firebase token missing email" });
    }

    let user = await usersCollection.findOne({ email: decoded.email.toLowerCase() });

    if (!user) {
      const result = await usersCollection.insertOne({
        name: decoded.name || "Firebase User",
        email: decoded.email.toLowerCase(),
        password: "",
        authProvider: "firebase",
        avatar: decoded.picture || "",
        role: "user",
        address: "",
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      user = await usersCollection.findOne({ _id: result.insertedId });
    } else if (user.authProvider !== "firebase") {
      await usersCollection.updateOne(
        { _id: user._id },
        { $set: { authProvider: "firebase", avatar: decoded.picture || user.avatar, updatedAt: new Date() } }
      );
      user = await usersCollection.findOne({ _id: user._id });
    }

    const token = generateToken(user._id.toString(), user.role);
    const safeUser = { ...user };
    delete safeUser.password;

    res.json({ user: safeUser, token });
  }
);

app.get("/api/auth/me", dbGuard, protect, (req, res) => {
  res.json(req.user);
});

// ── PRODUCT ROUTES ───────────────────────────────────────────
function buildProductSort(sortKey) {
  switch (sortKey) {
    case "featured":
      return { orders: -1, views: -1, rating: -1, createdAt: -1 };
    case "price-low":
      return { price: 1, createdAt: -1 };
    case "price-high":
      return { price: -1, createdAt: -1 };
    case "rating":
      return { rating: -1, reviewsCount: -1, createdAt: -1 };
    case "newest":
    default:
      return { createdAt: -1 };
  }
}

app.get(
  "/api/products",
  dbGuard,
  [
    query("page").optional().isInt({ min: 1 }),
    query("limit").optional().isInt({ min: 1, max: 100 }),
    query("sort").optional().isIn(["featured", "newest", "price-low", "price-high", "rating"]),
    query("maxPrice").optional().isFloat({ min: 0 }),
    query("minRating").optional().isFloat({ min: 0, max: 5 }),
    query("rating").optional().isFloat({ min: 0, max: 5 }),
    query("q").optional().isString(),
    query("search").optional().isString(),
  ],
  validate,
  async (req, res) => {
    console.log("[TRACE] /api/products query:", req.query);
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 12;
    const sort = String(req.query.sort || "newest");
    const maxPrice = Number(req.query.maxPrice);
    const minRating = Number(req.query.minRating ?? req.query.rating);
    const search = String(req.query.q || req.query.search || "").trim();
    const { category } = req.query;

    const filters = {};

    if (category) {
      filters.category = category;
    }

    if (Number.isFinite(maxPrice)) {
      filters.price = { ...(filters.price || {}), $lte: maxPrice };
    }

    if (Number.isFinite(minRating)) {
      filters.rating = { $gte: minRating };
    }

    if (search) {
      filters.$text = { $search: search };
    }

    let total;
    let items;

    try {
      total = await productsCollection.countDocuments(filters);
      const pages = Math.ceil(total / limit) || 1;
      items = await productsCollection
        .find(filters)
        .sort(search ? { score: { $meta: "textScore" }, ...buildProductSort(sort) } : buildProductSort(sort))
        .skip((page - 1) * limit)
        .limit(limit)
        .toArray();

      return res.json({ items, page, pages, total, limit });
    } catch (error) {
      if (!search) throw error;
      const escapedSearch = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const regex = new RegExp(escapedSearch, "i");
      delete filters.$text;
      filters.$or = [{ name: regex }, { description: regex }, { tags: regex }];
      total = await productsCollection.countDocuments(filters);
      const pages = Math.ceil(total / limit) || 1;
      items = await productsCollection
        .find(filters)
        .sort(buildProductSort(sort))
        .skip((page - 1) * limit)
        .limit(limit)
        .toArray();

      return res.json({ items, page, pages, total, limit });
    }
  }
);

app.get("/api/products/categories", dbGuard, async (req, res) => {
  const categories = await productsCollection.distinct("category", {
    category: { $exists: true, $type: "string", $ne: "" },
  });
  res.json(categories.sort((a, b) => a.localeCompare(b)));
});

app.get("/api/products/:id", dbGuard, async (req, res) => {
  const { id } = req.params;

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({
      error: "Invalid product ID. This product does not exist in the database.",
    });
  }

  const product = await productsCollection.findOneAndUpdate(
    { _id: new ObjectId(id) },
    { $inc: { views: 1 } },
    { returnDocument: "after" }
  );

  if (!product) {
    return res.status(404).json({ message: "Product not found" });
  }

  const reviews = await reviewsCollection.find({ product: new ObjectId(id) }).toArray();

  const userIds = [...new Set(reviews.map(r => r.user))];
  const users = await usersCollection.find({ _id: { $in: userIds.map(id => new ObjectId(id)) } }).toArray();
  const userMap = {};
  users.forEach(u => { userMap[u._id.toString()] = { name: u.name, avatar: u.avatar }; });

  const reviewsWithUsers = reviews.map(r => ({
    ...r,
    user: userMap[r.user.toString()] || { name: "Unknown", avatar: "" }
  })).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  res.json({ product, reviews: reviewsWithUsers });
});

app.get("/api/products/:id/reviews", dbGuard, async (req, res) => {
  const { id } = req.params;

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({
      error: "Invalid product ID. This product does not exist in the database.",
    });
  }

  const reviews = await reviewsCollection.find({ product: new ObjectId(id) }).toArray();

  const userIds = [...new Set(reviews.map(r => r.user))];
  const users = await usersCollection.find({ _id: { $in: userIds.map(id => new ObjectId(id)) } }).toArray();
  const userMap = {};
  users.forEach(u => { userMap[u._id.toString()] = { name: u.name, avatar: u.avatar }; });

  const reviewsWithUsers = reviews.map(r => ({
    ...r,
    user: userMap[r.user.toString()] || { name: "Unknown", avatar: "" }
  })).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  res.json(reviewsWithUsers);
});

app.post("/api/products", dbGuard, protect, adminOnly, async (req, res) => {
  const result = await productsCollection.insertOne({
    ...req.body,
    stock: req.body.stock || 0,
    rating: 0,
    reviewsCount: 0,
    views: 0,
    orders: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  const product = await productsCollection.findOne({ _id: result.insertedId });
  res.status(201).json(product);
});

app.put("/api/products/:id", dbGuard, protect, adminOnly, async (req, res) => {
  const result = await productsCollection.findOneAndUpdate(
    { _id: new ObjectId(req.params.id) },
    { $set: { ...req.body, updatedAt: new Date() } },
    { returnDocument: "after" }
  );

  if (!result) {
    return res.status(404).json({ message: "Product not found" });
  }

  res.json(result);
});

app.delete("/api/products/:id", dbGuard, protect, adminOnly, async (req, res) => {
  const product = await productsCollection.findOneAndDelete({ _id: new ObjectId(req.params.id) });

  if (!product) {
    return res.status(404).json({ message: "Product not found" });
  }

  await reviewsCollection.deleteMany({ product: new ObjectId(req.params.id) });

  res.json({ message: "Product deleted" });
});

app.post(
  "/api/products/:id/reviews",
  dbGuard,
  protect,
  [
    body("rating").isInt({ min: 1, max: 5 }),
    body("comment").isString().isLength({ min: 1 }),
  ],
  validate,
  async (req, res) => {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        error: "Invalid product ID. This product does not exist in the database.",
      });
    }

    const { rating, comment } = req.body;

    const product = await productsCollection.findOne({ _id: new ObjectId(id) });
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    const result = await reviewsCollection.insertOne({
      user: req.user._id,
      product: new ObjectId(id),
      rating,
      comment,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const reviews = await reviewsCollection.find({ product: new ObjectId(id) }).toArray();
    const totalRating = reviews.reduce((sum, item) => sum + item.rating, 0);

    await productsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { rating: reviews.length ? totalRating / reviews.length : 0, reviewsCount: reviews.length } }
    );

    const review = await reviewsCollection.findOne({ _id: result.insertedId });
    res.status(201).json(review);
  }
);

// ── ORDER ROUTES ─────────────────────────────────────────────
app.post("/api/payments/create-checkout-session", dbGuard, protect, async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY || !stripe) {
    return res.status(503).json({
      error: "Payments are not configured. Add STRIPE_SECRET_KEY to server/.env",
    });
  }

  const { cart = [], email = "" } = req.body || {};

  if (!Array.isArray(cart) || cart.length === 0) {
    return res.status(400).json({ error: "Cart is empty." });
  }

  const line_items = cart
    .map((item) => {
      const amountCents = Math.round(Number(item.price) * 100);
      const quantity = Math.max(1, Number(item.quantity) || 1);

      if (!Number.isFinite(amountCents) || amountCents < 50) {
        return null;
      }

      return {
        price_data: {
          currency: "usd",
          product_data: {
            name: item.name || "DropSphere product",
            images: item.image ? [item.image] : undefined,
          },
          unit_amount: amountCents,
        },
        quantity,
      };
    })
    .filter(Boolean);

  if (!line_items.length) {
    return res.status(400).json({ error: "Invalid cart items." });
  }

  const clientUrl = process.env.CLIENT_URL || "http://localhost:5173";
  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    line_items,
    customer_email: email || undefined,
    success_url: `${clientUrl}/order-success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${clientUrl}/checkout?canceled=1`,
  });

  res.json({ url: session.url });
});

app.get("/api/payments/verify-session", dbGuard, async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY || !stripe) {
    return res.status(503).json({
      error: "Payments are not configured. Add STRIPE_SECRET_KEY to server/.env",
    });
  }

  const sessionId = String(req.query.session_id || "").trim();
  if (!sessionId) {
    return res.status(400).json({ error: "Missing session_id query parameter." });
  }

  const session = await stripe.checkout.sessions.retrieve(sessionId);
  if (!session) {
    return res.status(404).json({ error: "Checkout session not found." });
  }

  const paymentStatus = session.payment_status || "unpaid";
  if (paymentStatus !== "paid") {
    return res.status(400).json({
      success: false,
      error: "Payment is not completed.",
      paymentStatus,
    });
  }

  res.json({
    success: true,
    sessionId: session.id,
    customerEmail: session.customer_details?.email || session.customer_email || "",
    amountTotal: session.amount_total || 0,
    currency: session.currency || "usd",
    paymentStatus,
  });
});

app.post(
  "/api/orders/create-payment-intent",
  dbGuard,
  protect,
  [body("amount").isFloat({ min: 1 })],
  validate,
  async (req, res) => {
    const { amount } = req.body;
    const normalizedAmount = Math.round(Number(amount));
    const currency = "usd";

    if (!process.env.STRIPE_SECRET_KEY || !stripe) {
      return res
        .status(503)
        .json({ error: "Payment processing not configured." });
    }

    if (!Number.isFinite(normalizedAmount) || normalizedAmount < 50) {
      return res.status(400).json({ error: "Invalid order amount." });
    }

    const paymentIntent = await stripe.paymentIntents.create({
      amount: normalizedAmount,
      currency,
      automatic_payment_methods: { enabled: true },
    });

    res.json({ clientSecret: paymentIntent.client_secret });
  }
);

app.post("/api/orders", dbGuard, protect, async (req, res) => {
  const incomingProducts = Array.isArray(req.body?.products) ? req.body.products : [];

  if (!incomingProducts.length) {
    return res.status(400).json({ error: "Order must include at least one product." });
  }

  const normalizedProducts = incomingProducts
    .map((item) => {
      const rawId = String(item?.product || item?.productId || "").trim();
      const hasObjectId = ObjectId.isValid(rawId);
      const quantity = Number(item?.quantity || 0);
      const price = Number(item?.price || 0);

      if (!Number.isFinite(quantity) || quantity < 1 || !Number.isFinite(price) || price <= 0) {
        return null;
      }

      return {
        product: hasObjectId ? new ObjectId(rawId) : undefined,
        productId: rawId,
        title: String(item?.title || item?.name || "Product"),
        image: String(item?.image || ""),
        category: String(item?.category || ""),
        quantity,
        price,
      };
    })
    .filter(Boolean);

  if (!normalizedProducts.length) {
    return res.status(400).json({ error: "Order items are invalid." });
  }

  const orderData = {
    ...req.body,
    products: normalizedProducts,
    user: req.user._id,
    status: req.body.status || "Pending",
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const result = await ordersCollection.insertOne(orderData);
  const order = await ordersCollection.findOne({ _id: result.insertedId });
  res.status(201).json(order);
});

app.get("/api/orders/my", dbGuard, protect, async (req, res) => {
  const orders = await ordersCollection.find({ user: req.user._id }).toArray();

  const productIds = [];
  orders.forEach(o => {
    o.products.forEach(p => {
      if (p.product) productIds.push(p.product);
    });
  });

  let productMap = {};
  if (productIds.length > 0) {
    const products = await productsCollection.find({ _id: { $in: [...new Set(productIds)] } }).toArray();
    productMap = {};
    products.forEach(p => { productMap[p._id.toString()] = p; });
  }

  const ordersWithProducts = orders.map(o => ({
    ...o,
    products: o.products.map(p => ({
      ...p,
      product: p.product ? productMap[p.product.toString()] || null : null
    }))
  })).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  res.json(ordersWithProducts);
});

app.get("/api/orders", dbGuard, protect, adminOnly, async (req, res) => {
  const orders = await ordersCollection.find({}).toArray();

  const userIds = [...new Set(orders.map(o => o.user))];
  const users = await usersCollection.find({ _id: { $in: userIds.map(id => new ObjectId(id)) } }).toArray();
  const userMap = {};
  users.forEach(u => { userMap[u._id.toString()] = { name: u.name, email: u.email, role: u.role }; });

  const productIds = [];
  orders.forEach(o => {
    o.products.forEach(p => {
      if (p.product) productIds.push(p.product);
    });
  });

  let productMap = {};
  if (productIds.length > 0) {
    const products = await productsCollection.find({ _id: { $in: [...new Set(productIds)] } }).toArray();
    productMap = {};
    products.forEach(p => { productMap[p._id.toString()] = p; });
  }

  const ordersWithRefs = orders.map(o => ({
    ...o,
    user: userMap[o.user.toString()] || null,
    products: o.products.map(p => ({
      ...p,
      product: p.product ? productMap[p.product.toString()] || null : null
    }))
  })).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  res.json(ordersWithRefs);
});

app.put(
  "/api/orders/:id/status",
  dbGuard,
  protect,
  adminOnly,
  [body("status").isIn(["Pending", "Shipped", "Delivered"])],
  validate,
  async (req, res) => {
    const order = await ordersCollection.findOneAndUpdate(
      { _id: new ObjectId(req.params.id) },
      { $set: { status: req.body.status, updatedAt: new Date() } },
      { returnDocument: "after" }
    );

    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    const user = await usersCollection.findOne({ _id: order.user }, { projection: { password: 0 } });

    const productIds = order.products.filter(p => p.product).map(p => p.product);
    let productMap = {};
    if (productIds.length > 0) {
      const products = await productsCollection.find({ _id: { $in: productIds } }).toArray();
      productMap = {};
      products.forEach(p => { productMap[p._id.toString()] = p; });
    }

    const orderWithRefs = {
      ...order,
      user: user || null,
      products: order.products.map(p => ({
        ...p,
        product: p.product ? productMap[p.product.toString()] || null : null
      }))
    };

    res.json(orderWithRefs);
  }
);

// ── USER ROUTES ──────────────────────────────────────────────
app.get("/api/users/profile", dbGuard, protect, (req, res) => {
  res.json(req.user);
});

app.put(
  "/api/users/profile",
  dbGuard,
  protect,
  [
    body("name").optional().isLength({ min: 2, max: 50 }),
    body("address").optional().isString(),
  ],
  validate,
  async (req, res) => {
    const updates = {};
    if (typeof req.body.name === "string") {
      updates.name = req.body.name;
    }
    if (typeof req.body.address === "string") {
      updates.address = req.body.address;
    }

    const user = await usersCollection.findOneAndUpdate(
      { _id: req.user._id },
      { $set: { ...updates, updatedAt: new Date() } },
      { returnDocument: "after", projection: { password: 0 } }
    );

    res.json(user);
  }
);

app.get("/api/users/all", dbGuard, protect, adminOnly, async (req, res) => {
  const users = await usersCollection.find({}, { projection: { password: 0 } }).toArray();
  res.json(users.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
});

// 12. GLOBAL ERROR HANDLER
app.use((err, req, res, next) => {
  res
    .status(err.status || 500)
    .json({ message: err.message || "Server error" });
});

// 13. START
if (process.env.VERCEL) {
  await ensureDB();
} else {
  ensureDB().finally(() => {
    console.log("[TRACE] Starting local API server...");
    app.listen(PORT, () => {
      console.log(`DropSphere API running on port ${PORT}`);
    });
  });
}

export default app;
