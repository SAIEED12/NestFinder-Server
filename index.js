const dns = require("node:dns");
dns.setServers(["8.8.8.8", "8.8.4.4"]);

const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { jwtVerify, createRemoteJWKSet } = require("jose-cjs");
dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());
const port = process.env.PORT || 5000;

const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const JWKS = createRemoteJWKSet(
  new URL(`${process.env.CLIENT_URL}/api/auth/jwks`),
);

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const { payload } = await jwtVerify(token, JWKS);
    req.user = payload;
    next();
  } catch (error) {
    console.log(error);
    return res.status(401).json({ message: "Unauthorized" });
  }
};

const tenantVerify = async (req, res, next) => {
  const user = req.user;
  if (user.role !== "tenant") {
    return res.status(403).json({ message: "Forbidden" });
  }
  next();
};

const ownerVerify = async (req, res, next) => {
  const user = req.user;
  if (user.role !== "owner") {
    return res.status(403).json({ message: "Forbidden" });
  }
  next();
};

const adminVerify = async (req, res, next) => {
  const user = req.user;
  if (user.role !== "admin") {
    return res.status(403).json({ message: "Forbidden" });
  }
  next();
};

async function run() {
  try {
    await client.connect();
    const db = client.db("nestFinder");
    const propertiesCollection = db.collection("properties");
    const bookingsCollection = db.collection("bookings");

    // Featured Properties
    app.get("/api/properties/featured", async (req, res) => {
      try {
        const query = { status: "Approved" };
        const featuredProperties = await db.collection("properties").find(query).limit(6).toArray();
        res.status(200).send(featuredProperties);
      } catch (error) {
        res.status(500).send({ message: "Error loading featured items", error });
      }
    });

    // Get All Properties
    app.get("/all-properties", async (req, res) => {
      try {
        const { search, propertyType, sort } = req.query;
        const query = { status: "Approved" };

        if (search && search !== "undefined") {
          query.location = { $regex: search, $options: "i" };
        }

        if (propertyType && propertyType !== "all") {
          query.propertyType = propertyType.toLowerCase();
        }

        const sortQuery = {};
        if (sort === "low-to-high") {
          sortQuery.rent = 1;
        } else if (sort === "high-to-low") {
          sortQuery.rent = -1;
        }

        const result = await propertiesCollection
          .find(query)
          .collation({ locale: "en", numericOrdering: true })
          .sort(sortQuery)
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // Details Page
    app.get("/all-properties/:id", async (req, res) => {
      const { id } = req.params;
      const result = await propertiesCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    // Owner Add Property
    app.post("/owner/properties", verifyToken, ownerVerify, async (req, res) => {
      const data = req.body;
      const result = await propertiesCollection.insertOne({
        ...data,
        userId: req.user.id,
      });
      res.send(result);
    });

    // Booking API
    app.post("/api/bookings", async (req, res) => {
      try {
        const booking = req.body;
        if (!booking.propertyId || !booking.tenantId || !booking.moveInDate) {
          return res.status(400).json({ success: false, message: "Missing required booking fields" });
        }

        const tempId = new ObjectId().toString();
        const newBooking = {
          propertyId: new ObjectId(booking.propertyId),
          tenantId: booking.tenantId,
          tenantName: booking.tenantName || "",
          tenantEmail: booking.tenantEmail || "",
          contactNumber: booking.contactNumber || "",
          moveInDate: new Date(booking.moveInDate),
          additionalNotes: booking.additionalNotes || "",
          rentAmount: Number(booking.rentAmount),
          bookingStatus: "Pending",
          paymentStatus: "Pending",
          tempId: tempId,
          stripeSessionId: null,
          propertyTitle: booking.title || "", // 💡 Normalized field name consistency
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await bookingsCollection.insertOne(newBooking);
        res.status(201).json({ success: true, bookingId: result.insertedId, tempId: tempId, booking: newBooking });
      } catch (error) {
        res.status(500).json({ success: false, message: "Failed to create booking", error: error.message });
      }
    });

    // Stripe Fulfillment
    app.patch("/api/bookings/fulfill", async (req, res) => {
      try {
        const { stripeSessionId, tempId, paymentIntentId } = req.body;
        if (!stripeSessionId && !tempId) {
          return res.status(400).json({ success: false, message: "Missing session identifiers" });
        }

        const query = { $or: [{ tempId: tempId }, { stripeSessionId: stripeSessionId }] };
        const update = {
          $set: {
            paymentStatus: "Paid",
            stripeSessionId: stripeSessionId,
            paymentIntentId: paymentIntentId || "",
            updatedAt: new Date()
          }
        };

        const result = await bookingsCollection.updateOne(query, update);
        if (result.matchedCount === 0) {
          return res.status(404).json({ success: false, message: "Booking not found" });
        }
        res.json({ success: true, message: "Payment confirmed successfully." });
      } catch (error) {
        res.status(500).json({ success: false, message: "Internal Server Error" });
      }
    });

    // Owner Approve/Reject Booking (De-duplicated)
    app.patch("/api/bookings/:id/status", verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const { status, rejectionReason } = req.body;

        if (!["Approved", "Rejected"].includes(status)) {
          return res.status(400).json({ error: "Invalid status. Only Approved/Rejected allowed." });
        }

        const existingBooking = await bookingsCollection.findOne({ _id: new ObjectId(id) });
        if (!existingBooking) return res.status(404).json({ error: "Booking not found" });

        if (status === "Approved" && existingBooking.paymentStatus !== "Paid") {
          return res.status(400).json({ error: "Cannot approve booking. Payment not completed yet." });
        }

        const updateData = { bookingStatus: status, updatedAt: new Date() };
        if (status === "Rejected" && rejectionReason) updateData.rejectionReason = rejectionReason;

        const result = await bookingsCollection.updateOne({ _id: new ObjectId(id) }, { $set: updateData });
        res.json({ success: true, message: `Booking ${status} successfully` });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Update with Stripe Session ID
    app.patch("/api/bookings/:id/stripe-session", async (req, res) => {
      try {
        const { id } = req.params;
        const { stripeSessionId } = req.body;
        const result = await bookingsCollection.updateOne({ _id: new ObjectId(id) }, { $set: { stripeSessionId, updatedAt: new Date() } });
        res.json({ success: true, message: "Stripe session ID updated" });
      } catch (error) {
        res.status(500).json({ success: false, message: "Internal Server Error" });
      }
    });

    // Get Tenant Bookings
    app.get("/api/bookings/tenant/:userId", async (req, res) => {
      try {
        const { userId } = req.params;
        const bookings = await bookingsCollection.find({ tenantId: userId }).sort({ createdAt: -1 }).toArray();

        const bookingsWithDetails = await Promise.all(
          bookings.map(async (booking) => {
            const property = await propertiesCollection.findOne({ _id: booking.propertyId });
            return {
              ...booking,
              property: property || null,
              _id: booking._id.toString(),
              propertyId: booking.propertyId.toString(),
            };
          })
        );
        res.json(bookingsWithDetails);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Get Owner Booking Requests
    app.get("/api/bookings/owner/:ownerId", verifyToken, ownerVerify, async (req, res) => {
      try {
        const { ownerId } = req.params;
        const properties = await propertiesCollection.find({ userId: ownerId }).toArray();
        const propertyIds = properties.map(p => p._id);

        const bookings = await bookingsCollection.find({ propertyId: { $in: propertyIds } }).sort({ createdAt: -1 }).toArray();

        const bookingsWithDetails = await Promise.all(
          bookings.map(async (booking) => {
            const property = await propertiesCollection.findOne({ _id: booking.propertyId });
            return {
              ...booking,
              property: property || null,
              _id: booking._id.toString(),
              propertyId: booking.propertyId.toString(),
            };
          })
        );
        res.json(bookingsWithDetails);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Owner Properties View List
    app.get("/owner/properties", verifyToken, ownerVerify, async (req, res) => {
      const { page = 1, limit = 10 } = req.query;
      const skip = (Number(page) - 1) * Number(limit);
      const result = await propertiesCollection.find({ userId: req.user.id }).skip(skip).limit(Number(limit)).toArray();
      const totalData = await propertiesCollection.countDocuments({ userId: req.user.id });
      const totalPage = Math.ceil(totalData / Number(limit));
      res.send({ data: result, page: Number(page), totalPage });
    });

    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Keep connection active
  }
}
run().catch(console.dir);

app.get("/", (req, res) => { res.send("Hello World!"); });
app.listen(port, () => { console.log(`Example app listening on port ${port}`); });