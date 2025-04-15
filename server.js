
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const app = express();
app.use(express.json());

const allowedOrigins = [
    'https://createqr.d1nfh4ldjnk0ad.amplifyapp.com',
    'http://localhost:3000',
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    }
}));

if (!process.env.MONGO_URI || !process.env.JWT_SECRET) {
    console.error("❌ Missing MONGO_URI or JWT_SECRET in .env file.");
    process.exit(1);
}



mongoose
    .connect(process.env.MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log("✅ MongoDB Connected"))
    .catch((err) => {
        console.error("❌ MongoDB connection error:", err);
        process.exit(1);
    });

const UserSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
});
const QRSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "users", required: true },
    type: { type: String, required: true },
    data: { type: mongoose.Schema.Types.Mixed, required: true },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model("users", UserSchema);
const QRCode = mongoose.model("qrcodes", QRSchema);

// Middleware to verify JWT
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Access Denied" });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ message: "Invalid Token" });
    }
};


app.get("/", async (req, res) => {

    res.send("Welcome to backend server of QRCODE");

})

// Signup
app.post("/signup", async (req, res) => {
    const { firstName, lastName, email, password } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ firstName, lastName, email, password: hashedPassword });
        await newUser.save();

        const token = jwt.sign({ userId: newUser._id, email }, process.env.JWT_SECRET, { expiresIn: "24h" });
        res.status(201).json({ message: "User registered successfully", token });
    } catch (error) {
        res.status(500).json({ message: "Error registering user", error: error.message });
    }
});

// Login
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found." });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Invalid credentials." });

        const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "24h" });
        res.status(200).json({ message: "Login successful!", token });
    } catch (error) {
        res.status(500).json({ message: "Error during login." });
    }
});

// Save QR Code
app.post("/create-qr", authenticate, async (req, res) => {
    try {
        const { type, data } = req.body;

        if (!type || !data) {
            return res.status(400).json({ message: "Type and data are required" });
        }

        const newQR = new QRCode({
            userId: req.user.userId,
            type,
            data,
        });

        await newQR.save();
        res.status(201).json({ message: "QR Code saved successfully", qr: newQR });
    } catch (error) {
        res.status(500).json({ message: "Failed to save QR Code", error: error.message });
    }
});

// Get all QR codes by user
app.get("/my-qrcodes", authenticate, async (req, res) => {
    try {
        const qrcodes = await QRCode.find({ userId: req.user.userId }).sort({ createdAt: -1 });
        res.status(200).json({ qrcodes });
    } catch (error) {
        res.status(500).json({ message: "Error fetching QR codes", error: error.message });
    }
});


//DONATE

app.post('/create-checkout-session', async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: 'usd',
                        product_data: {
                            name: 'Support Our Project',
                            description: 'Donate and support our work!',
                        },
                        unit_amount: 500, // $5.00 (amount in cents)
                    },
                    quantity: 1,
                },
            ],
            mode: 'payment',
            success_url: `${COMMON_VARIABLES.FRONT_END}/payment-success`,
            cancel_url: `${COMMON_VARIABLES.FRONT_END}/payment-cancel`,
        });

        res.json({ url: session.url });
    } catch (err) {
        console.error("Stripe session error:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
