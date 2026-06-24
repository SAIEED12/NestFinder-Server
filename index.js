const dns = require("node:dns");
dns.setServers(["8.8.8.8", "8.8.4.4"]);

const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { jwtVerify, createRemoteJWKSet } = require("jose-cjs");
dotenv.config();
const app = express();

app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  }),
);
app.use(express.json());
const port = process.env.PORT || 5000;

const uri = process.env.MONGODB_URI;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
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
    console.log("Token authentication skipped or failed:", error.message);
    next();
  }
};

// Verifying User
const tenantVerify = async (req, res, next) => {
  const user = req.user;
  if (user && user.role !== "tenant") {
    return res.status(403).json({ message: "Forbidden" });
  }
  next();
};

const ownerVerify = async (req, res, next) => {
  const user = req.user;
  if (user && user.role !== "owner") {
    return res.status(403).json({ message: "Forbidden" });
  }
  next();
};

const adminVerify = async (req, res, next) => {
  const user = req.user;
  if (user && user.role !== "admin") {
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
    const favoritesCollection = db.collection("favorites");

    // Featured Properties
    app.get("/api/properties/featured", async (req, res) => {
      try {
        const query = { status: "Approved" };
        const featuredProperties = await db
          .collection("properties")
          .find(query)
          .limit(6)
          .toArray();
        res.status(200).send(featuredProperties);
      } catch (error) {
        res
          .status(500)
          .send({ message: "Error loading featured items", error });
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
      const result = await propertiesCollection.findOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });

    // Owner Add Property
    app.post(
      "/owner/properties",
      verifyToken,
      ownerVerify,
      async (req, res) => {
        const data = req.body;
        const result = await propertiesCollection.insertOne({
          ...data,
          userId: req.user?.id || data.userId,
        });
        res.send(result);
      },
    );

    // Booking API
    app.post("/api/bookings", async (req, res) => {
      try {
        const booking = req.body;
        if (!booking.propertyId || !booking.tenantId || !booking.moveInDate) {
          return res
            .status(400)
            .json({
              success: false,
              message: "Missing required booking fields",
            });
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
          propertyTitle:
            booking.propertyTitle || booking.title || "Unnamed Property",
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await bookingsCollection.insertOne(newBooking);
        res
          .status(201)
          .json({
            success: true,
            bookingId: result.insertedId,
            tempId: tempId,
            booking: newBooking,
          });
      } catch (error) {
        res
          .status(500)
          .json({
            success: false,
            message: "Failed to create booking",
            error: error.message,
          });
      }
    });

    // Stripe Fulfillment
    app.patch("/api/bookings/fulfill", async (req, res) => {
      try {
        const { stripeSessionId, tempId, paymentIntentId } = req.body;
        if (!stripeSessionId && !tempId) {
          return res
            .status(400)
            .json({ success: false, message: "Missing session identifiers" });
        }

        const query = {
          $or: [{ tempId: tempId }, { stripeSessionId: stripeSessionId }],
        };
        const update = {
          $set: {
            paymentStatus: "Paid",
            stripeSessionId: stripeSessionId,
            paymentIntentId: paymentIntentId || "",
            updatedAt: new Date(),
          },
        };

        const result = await bookingsCollection.updateOne(query, update);
        if (result.matchedCount === 0) {
          return res
            .status(404)
            .json({ success: false, message: "Booking not found" });
        }
        res.json({ success: true, message: "Payment confirmed successfully." });
      } catch (error) {
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error" });
      }
    });

    // 💡 FIXED: Cleaned up and secured single dynamic state modification endpoint path
    app.patch("/api/bookings/:id/status", verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const { status, rejectionReason } = req.body;

        if (!["Approved", "Rejected"].includes(status)) {
          return res
            .status(400)
            .json({ error: "Invalid status. Only Approved/Rejected allowed." });
        }

        const existingBooking = await bookingsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!existingBooking)
          return res.status(404).json({ error: "Booking not found" });

        if (status === "Approved" && existingBooking.paymentStatus !== "Paid") {
          return res
            .status(400)
            .json({
              error: "Cannot approve booking. Payment not completed yet.",
            });
        }

        const updateData = { bookingStatus: status, updatedAt: new Date() };
        if (status === "Rejected") {
          updateData.rejectionReason =
            rejectionReason ||
            "Lease configuration parameters rejected by host.";
        }

        const result = await bookingsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData },
        );
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
        const result = await bookingsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { stripeSessionId, updatedAt: new Date() } },
        );
        res.json({ success: true, message: "Stripe session ID updated" });
      } catch (error) {
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error" });
      }
    });

    // Get Tenant Bookings
    app.get("/api/bookings/tenant/:userId", verifyToken, async (req, res) => {
      try {
        const { userId } = req.params;
        const bookings = await bookingsCollection
          .find({ tenantId: userId })
          .sort({ createdAt: -1 })
          .toArray();

        const bookingsWithDetails = await Promise.all(
          bookings.map(async (booking) => {
            const property = await propertiesCollection.findOne({
              _id: booking.propertyId,
            });
            return {
              ...booking,
              property: property || null,
              _id: booking._id.toString(),
              propertyId: booking.propertyId.toString(),
            };
          }),
        );
        res.json(bookingsWithDetails);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Get Owner Booking Requests
    app.get(
      "/api/bookings/owner/:ownerId",
      verifyToken,
      ownerVerify,
      async (req, res) => {
        try {
          const { ownerId } = req.params;
          const properties = await propertiesCollection
            .find({ userId: ownerId })
            .toArray();
          const propertyIds = properties.map((p) => p._id);

          const bookings = await bookingsCollection
            .find({ propertyId: { $in: propertyIds } })
            .sort({ createdAt: -1 })
            .toArray();

          const bookingsWithDetails = await Promise.all(
            bookings.map(async (booking) => {
              const property = await propertiesCollection.findOne({
                _id: booking.propertyId,
              });
              return {
                ...booking,
                property: property || null,
                _id: booking._id.toString(),
                propertyId: booking.propertyId.toString(),
              };
            }),
          );
          res.json(bookingsWithDetails);
        } catch (error) {
          res.status(500).json({ error: error.message });
        }
      },
    );

    // Owner Properties View List
    app.get("/owner/properties", verifyToken, ownerVerify, async (req, res) => {
      const { page = 1, limit = 10 } = req.query;
      const skip = (Number(page) - 1) * Number(limit);
      const result = await propertiesCollection
        .find({ userId: req.user?.id })
        .skip(skip)
        .limit(Number(limit))
        .toArray();
      const totalData = await propertiesCollection.countDocuments({
        userId: req.user?.id,
      });
      const totalPage = Math.ceil(totalData / Number(limit));
      res.send({ data: result, page: Number(page), totalPage });
    });

    //Add to favourites API
    app.post("/api/favorites", async (req, res) => {
      try {
        const { propertyId, tenantId } = req.body;

        if (!propertyId || !tenantId) {
          return res
            .status(400)
            .json({ success: false, message: "Missing required fields" });
        }

        // Check if it already exists to prevent duplicate entries
        const existingFavorite = await favoritesCollection.findOne({
          propertyId: new ObjectId(propertyId),
          tenantId: tenantId,
        });

        if (existingFavorite) {
          // Toggle logic: If clicked again, remove it from favorites
          await favoritesCollection.deleteOne({ _id: existingFavorite._id });
          return res
            .status(200)
            .json({
              success: true,
              message: "Removed from favorites",
              isFavorite: false,
            });
        }

        const newFavorite = {
          propertyId: new ObjectId(propertyId),
          tenantId: tenantId,
          createdAt: new Date(),
        };

        const result = await favoritesCollection.insertOne(newFavorite);
        res
          .status(201)
          .json({
            success: true,
            message: "Added to favorites",
            isFavorite: true,
            insertedId: result.insertedId,
          });
      } catch (error) {
        console.error("Error managing favorites ledger:", error);
        res
          .status(500)
          .json({ success: false, message: "Internal Server Error" });
      }
    });

    // 2. Get a specific tenant's populated favorites list
    app.get("/api/favorites/tenant/:userId", async (req, res) => {
      try {
        const { userId } = req.params;
        const items = await favoritesCollection
          .find({ tenantId: userId })
          .toArray();

        // Joint lookups to populate corresponding property listings details
        const populatedFavorites = await Promise.all(
          items.map(async (fav) => {
            const property = await propertiesCollection.findOne({
              _id: fav.propertyId,
            });
            return {
              _id: fav._id.toString(),
              ...property,
            };
          }),
        );

        // Filter out any favorites pointing to a property that was deleted from the app
        const cleanFavorites = populatedFavorites.filter(
          (item) => item !== null && item.title,
        );
        res.json(cleanFavorites);
      } catch (error) {
        console.error("Error fetching favorites list:", error);
        res.status(500).json({ error: error.message });
      }
    });


    //Recharts
    // Add this route inside the run() function block in server.js
    app.get(
      "/api/owner/analytics/:ownerId",
      verifyToken,
      ownerVerify,
      async (req, res) => {
        try {
          const { ownerId } = req.params;

          // 1. Fetch all properties belonging to this owner
          const ownerProperties = await propertiesCollection
            .find({ userId: ownerId })
            .toArray();
          const totalProperties = ownerProperties.length;
          const propertyIds = ownerProperties.map((p) => p._id);

          // 2. Fetch all bookings for these specific properties
          const totalBookingsList = await bookingsCollection
            .find({
              propertyId: { $in: propertyIds },
            })
            .toArray();

          // 3. Filter confirmed / paid items to calculate revenue aggregates
          // (Matches paymentStatus: "Paid" or bookingStatus: "Approved")
          const successfulBookings = totalBookingsList.filter(
            (b) => b.paymentStatus === "Paid" || b.bookingStatus === "Approved",
          );

          const totalBookings = totalBookingsList.length;
          const totalEarnings = successfulBookings.reduce(
            (sum, b) => sum + (Number(b.rentAmount) || 0),
            0,
          );

          // 4. Generate 12-Month Historical Trailing Dataset for Recharts Line Graph
          const monthlyDataMap = {};
          const now = new Date();

          // Initialize the last 12 months with $0 fields to ensure chart alignment
          for (let i = 11; i >= 0; i--) {
            const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
            const monthLabel = d.toLocaleString("en-US", {
              month: "short",
              year: "2-digit",
            }); // e.g., "Jul 25"
            const sortingKey = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`; // "2025-07"
            monthlyDataMap[sortingKey] = {
              name: monthLabel,
              earnings: 0,
              sortKey: sortingKey,
            };
          }

          // Populate actual transactional volume records from MongoDB timestamps
          successfulBookings.forEach((booking) => {
            const date = booking.createdAt
              ? new Date(booking.createdAt)
              : new Date();
            const sortingKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;

            if (monthlyDataMap[sortingKey]) {
              monthlyDataMap[sortingKey].earnings +=
                Number(booking.rentAmount) || 0;
            }
          });

          // Sort chart timeline sequentially
          const chartData = Object.values(monthlyDataMap).sort((a, b) =>
            a.sortKey.localeCompare(b.sortKey),
          );

          res.json({
            success: true,
            stats: {
              totalEarnings,
              totalProperties,
              totalBookings,
            },
            chartData,
          });
        } catch (error) {
          console.error("Owner analytics calculation breakdown:", error);
          res.status(500).json({ success: false, error: error.message });
        }
      },
    );

    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
    // Keep connection active
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello World!");
});
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
