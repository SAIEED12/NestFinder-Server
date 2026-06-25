const dns = require("node:dns");
dns.setServers(["8.8.8.8", "8.8.4.4"]);

const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { jwtVerify, createRemoteJWKSet } = require("jose-cjs");

dotenv.config();
const app = express();
const port = process.env.PORT || 5000;

// 💡 BETTER-AUTH MIDDLEWARE ADAPTER IMPORT
const { toNodeHandler } = require("better-auth/node");
const { auth } = require("./auth"); // Double-check that auth.js sits in the same directory!

app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  }),
);
app.use(express.json());

// 💡 MOUNT BETTER-AUTH WILDCARD HANDLER ROUTE ABOVE CUSTOM API ENDPOINTS
app.all("/api/auth/*", toNodeHandler(auth));

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

// Verifying User Roles
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

// 💡 FIXED: RESTORED UNIFIED ASYNC DATABASE CONNECTIVITY ENCAPSULATION WRAPPER
async function run() {
  try {
    await client.connect();
    
    const db = client.db("nestFinder");
    const propertiesCollection = db.collection("properties");
    const bookingsCollection = db.collection("bookings");
    const favoritesCollection = db.collection("favorites");
    const usersCollection = db.collection("user");
    const reviewsCollection = db.collection("reviews");

    console.log("Database layers securely connected. Registering endpoints...");

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
      try {
        const { id } = req.params;
        const result = await propertiesCollection.findOne({
          _id: new ObjectId(id),
        });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error getting property details" });
      }
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
          return res.status(400).json({
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
        res.status(201).json({
          success: true,
          bookingId: result.insertedId,
          tempId: tempId,
          booking: newBooking,
        });
      } catch (error) {
        res.status(500).json({
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

    // Id wise bookings
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
          return res.status(400).json({
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
      try {
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
      } catch (error) {
        res.status(500).send({ message: "Error loading owner properties" });
      }
    });

    // Add to favourites API
    app.post("/api/favorites", async (req, res) => {
      try {
        const { propertyId, tenantId } = req.body;

        if (!propertyId || !tenantId) {
          return res
            .status(400)
            .json({ success: false, message: "Missing required fields" });
        }

        const existingFavorite = await favoritesCollection.findOne({
          propertyId: new ObjectId(propertyId),
          tenantId: tenantId,
        });

        if (existingFavorite) {
          await favoritesCollection.deleteOne({ _id: existingFavorite._id });
          return res.status(200).json({
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
        res.status(201).json({
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

    // Specific tenant's favorites list
    app.get("/api/favorites/tenant/:userId", async (req, res) => {
      try {
        const { userId } = req.params;
        const items = await favoritesCollection
          .find({ tenantId: userId })
          .toArray();

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

        const cleanFavorites = populatedFavorites.filter(
          (item) => item !== null && item.title,
        );
        res.json(cleanFavorites);
      } catch (error) {
        console.error("Error fetching favorites list:", error);
        res.status(500).json({ error: error.message });
      }
    });

    // Recharts Owner Analytics
    app.get(
      "/api/owner/analytics/:ownerId",
      verifyToken,
      ownerVerify,
      async (req, res) => {
        try {
          const { ownerId } = req.params;

          const ownerProperties = await propertiesCollection
            .find({ userId: ownerId })
            .toArray();
          const totalProperties = ownerProperties.length;
          const propertyIds = ownerProperties.map((p) => p._id);

          const totalBookingsList = await bookingsCollection
            .find({
              propertyId: { $in: propertyIds },
            })
            .toArray();

          const successfulBookings = totalBookingsList.filter(
            (b) => b.paymentStatus === "Paid" || b.bookingStatus === "Approved",
          );

          const totalBookings = totalBookingsList.length;
          const totalEarnings = successfulBookings.reduce(
            (sum, b) => sum + (Number(b.rentAmount) || 0),
            0,
          );

          const monthlyDataMap = {};
          const now = new Date();

          for (let i = 11; i >= 0; i--) {
            const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
            const monthLabel = d.toLocaleString("en-US", {
              month: "short",
              year: "2-digit",
            });
            const sortingKey = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
            monthlyDataMap[sortingKey] = {
              name: monthLabel,
              earnings: 0,
              sortKey: sortingKey,
            };
          }

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

    // Admin API - Users
    app.get("/api/admin/users", async (req, res) => {
      try {
        const users = await usersCollection
          .find({})
          .sort({ createdAt: -1 })
          .toArray();
        res.json(users);
      } catch (error) {
        console.error("Admin fetch users failure:", error);
        res
          .status(500)
          .json({ error: "Internal Server Error compiling user records." });
      }
    });

    // Change a user's access control role
    app.patch("/api/admin/users/:id/role", async (req, res) => {
      try {
        const { id } = req.params;
        const { role } = req.body;

        if (!["admin", "owner", "tenant"].includes(role)) {
          return res
            .status(400)
            .json({ error: "Invalid role transition parameter." });
        }

        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role, updatedAt: new Date() } },
        );

        if (result.matchedCount === 0) {
          const fallbackResult = await usersCollection.updateOne(
            { id: id },
            { $set: { role, updatedAt: new Date() } },
          );

          if (fallbackResult.matchedCount === 0) {
            return res
              .status(404)
              .json({ error: "Target user profile index record not found." });
          }
        }

        res.json({
          success: true,
          message: `User role successfully elevated/changed to ${role}.`,
        });
      } catch (error) {
        console.error("Role update mutation error:", error);
        res.status(500).json({ error: error.message });
      }
    });

    // Admin API - Properties Listing Index
    app.get("/api/admin/properties", async (req, res) => {
      try {
        const properties = await propertiesCollection
          .find({})
          .sort({ createdAt: -1 })
          .toArray();
        res.json(properties);
      } catch (error) {
        console.error("Admin properties fetch breakdown:", error);
        res
          .status(500)
          .json({ error: "Internal Server Error compiling global listings." });
      }
    });

    // Approve/Reject with feedback
    app.patch("/api/admin/properties/:id/status", async (req, res) => {
      try {
        const { id } = req.params;
        const { status, adminFeedback } = req.body;

        if (!["Approved", "Rejected", "Pending"].includes(status)) {
          return res
            .status(400)
            .json({ error: "Invalid status state transition." });
        }

        const updateData = { status, updatedAt: new Date() };

        if (adminFeedback !== undefined) {
          updateData.adminFeedback = adminFeedback;
        }

        const result = await propertiesCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData },
        );

        if (result.matchedCount === 0) {
          return res
            .status(404)
            .json({ error: "Target listing profile not located." });
        }

        res.json({
          success: true,
          message: `Property status adjusted cleanly to ${status}.`,
        });
      } catch (error) {
        console.error("Status adjustment database exception:", error);
        res.status(500).json({ error: error.message });
      }
    });

    // Delete Property Catalog Index
    app.delete("/api/admin/properties/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const result = await propertiesCollection.deleteOne({
          _id: new ObjectId(id),
        });
        if (result.deletedCount === 0) {
          return res.status(404).json({ error: "Listing index not found." });
        }
        res.json({
          success: true,
          message: "Property eliminated successfully from catalog index.",
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Admin Update Property Structure Modifications
    app.patch("/api/admin/properties/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const { title, location, rent, propertyType, status } = req.body;

        const updateData = { updatedAt: new Date() };
        if (title) updateData.title = title;
        if (location) updateData.location = location;
        if (rent) updateData.rent = Number(rent);
        if (propertyType) updateData.propertyType = propertyType;
        if (status) updateData.status = status;

        const result = await propertiesCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData },
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: "Property not found." });
        }

        res.json({ success: true, message: "Property updated successfully." });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Show Bookings Registry to Administration
    app.get("/api/admin/bookings", async (req, res) => {
      try {
        const bookings = await bookingsCollection
          .find({})
          .sort({ createdAt: -1 })
          .toArray();

        const populatedBookings = await Promise.all(
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

        res.json(populatedBookings);
      } catch (error) {
        console.error("Admin bookings fetch exception:", error);
        res.status(500).json({
          error: "Internal Server Error compiling global booking registry.",
        });
      }
    });

    // Admin Platform Transaction Ledger Processing
    app.get("/api/admin/transactions", async (req, res) => {
      try {
        const paidBookings = await bookingsCollection
          .find({ paymentStatus: "Paid" })
          .sort({ updatedAt: -1 })
          .toArray();

        const enrichedTransactions = await Promise.all(
          paidBookings.map(async (booking) => {
            const property = await propertiesCollection.findOne({
              _id: booking.propertyId,
            });

            let ownerName = "System Allocation";
            if (property && property.userId) {
              const ownerAccount = await db.collection("user").findOne({
                $or: [
                  { _id: new ObjectId(property.userId) },
                  { id: property.userId },
                ],
              });
              if (ownerAccount)
                ownerName = ownerAccount.name || ownerAccount.email;
            }

            return {
              transactionId:
                booking.paymentIntentId ||
                booking.stripeSessionId ||
                `TXN-${booking._id.toString().substring(18)}`,
              propertyName:
                booking.propertyTitle ||
                property?.title ||
                "Premium Rental Unit",
              tenantName: booking.tenantName || "Verified Tenant",
              ownerName: ownerName,
              amount: booking.rentAmount,
              date: booking.updatedAt || booking.createdAt,
              propertyId: booking.propertyId.toString(),
            };
          }),
        );

        res.json(enrichedTransactions);
      } catch (error) {
        console.error("Admin transactions ledger compile exception:", error);
        res.status(500).json({
          error: "Internal Server Error compiling platform financial balances.",
        });
      }
    });

    // Submit Review Endpoint Hook
    app.post("/api/properties/:id/reviews", async (req, res) => {
      try {
        const { id } = req.params;
        const { tenantName, tenantEmail, rating, comment } = req.body;

        if (!rating || rating < 1 || rating > 5) {
          return res.status(400).json({
            error: "Rating score value must sit exactly between 1 and 5 stars.",
          });
        }

        const reviewDocument = {
          propertyId: new ObjectId(id),
          tenantName,
          tenantEmail,
          rating: Number(rating),
          comment: comment?.trim() || "",
          createdAt: new Date(),
        };

        const result = await reviewsCollection.insertOne(reviewDocument);
        res.json({
          success: true,
          message: "Review posted successfully to structural log files!",
          review: reviewDocument,
        });
      } catch (error) {
        console.error("Review submission mutation crash:", error);
        res.status(500).json({ error: error.message });
      }
    });

    // Fetch all reviews logged against a single property entry
    app.get("/api/properties/:id/reviews", async (req, res) => {
      try {
        const { id } = req.params;
        const reviewLogs = await reviewsCollection
          .find({ propertyId: new ObjectId(id) })
          .sort({ createdAt: -1 })
          .toArray();

        res.json(reviewLogs);
      } catch (error) {
        console.error("Reviews query engine error:", error);
        res
          .status(500)
          .json({ error: "Failed to compile property review listings." });
      }
    });

    // Fetch 4 high-quality tenant reviews for the homepage showcase
    app.get("/api/home/top-reviews", async (req, res) => {
      try {
        const highQualityReviews = await reviewsCollection
          .find({ rating: { $gte: 4 } })
          .sort({ createdAt: -1 })
          .limit(4)
          .toArray();

        const populatedHomeReviews = await Promise.all(
          highQualityReviews.map(async (review) => {
            const property = await propertiesCollection.findOne({
              _id: review.propertyId,
            });
            return {
              ...review,
              propertyTitle: property ? property.title : "Premium Rental Unit",
              _id: review._id.toString(),
              propertyId: review.propertyId.toString(),
            };
          }),
        );

        res.json(populatedHomeReviews);
      } catch (error) {
        console.error("Homepage reviews compilation exception:", error);
        res
          .status(500)
          .json({ error: "Failed to compile highlighted tenant reviews." });
      }
    });

    // Searching, Sorting, Filtering Engine with Facet Pagination
    app.get("/api/public/properties", async (req, res) => {
      try {
        const { search, propertyType, sort, minPrice, maxPrice, page = 1, limit = 12 } = req.query;

        const activePage = Math.max(1, parseInt(page));
        const pageLimit = Math.max(1, parseInt(limit));
        const skipOffset = (activePage - 1) * pageLimit;

        let queryFilter = { status: "Approved" };

        if (search && search !== "undefined" && search.trim() !== "") {
          queryFilter.location = { $regex: search.trim(), $options: "i" };
        }

        if (propertyType && propertyType !== "all") {
          queryFilter.propertyType = propertyType.trim().toLowerCase();
        }

        let sortConfig = {};
        if (sort === "asc" || sort === "low-to-high") {
          sortConfig.rent = 1;
        } else if (sort === "desc" || sort === "high-to-low") {
          sortConfig.rent = -1;
        } else {
          sortConfig.createdAt = -1;
        }

        let priceFilter = {};
        if (minPrice && !isNaN(minPrice)) {
          priceFilter.rent = { ...priceFilter.rent, $gte: Number(minPrice) };
        }
        if (maxPrice && !isNaN(maxPrice)) {
          priceFilter.rent = { ...priceFilter.rent, $lte: Number(maxPrice) };
        }

        const aggregationResult = await propertiesCollection
          .aggregate([
            { $match: queryFilter },
            {
              $addFields: {
                rent: {
                  $convert: {
                    input: "$rent",
                    to: "double",
                    onError: 0,
                    onNull: 0,
                  },
                },
              },
            },
            ...(Object.keys(priceFilter).length > 0 ? [{ $match: priceFilter }] : []),
            {
              $facet: {
                totalCount: [{ $count: "count" }],
                paginatedData: [
                  { $sort: sortConfig },
                  { $skip: skipOffset },
                  { $limit: pageLimit }
                ]
              }
            }
          ])
          .toArray();

        const totalCount = aggregationResult[0]?.totalCount[0]?.count || 0;
        const properties = aggregationResult[0]?.paginatedData || [];
        const totalPages = Math.ceil(totalCount / pageLimit);

        res.json({
          success: true,
          data: properties,
          meta: {
            totalItems: totalCount,
            totalPages: totalPages,
            currentPage: activePage,
            itemsPerPage: pageLimit
          }
        });
      } catch (error) {
        console.error("Public sorting pagination fallback crash:", error);
        res.status(500).json({
          success: false,
          error: "Failed to accurately compile paginated property grids."
        });
      }
    });

    // Base verification path handler for Vercel default domain status metrics check
    app.get("/", (req, res) => {
      res.send("NestFinder Server Operational.");
    });
    app.listen(port, () => {
      console.log(`Server executing seamlessly over port: ${port}`);
    });

  } catch (err) {
    console.error("Critical server initialization crash:", err);
  }
}

run().catch(console.dir);

module.exports = app;