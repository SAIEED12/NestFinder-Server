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
    console.log(error);
    return res.status(401).json({ message: "Unauthorized" });
  }
};

// Verifying User
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
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    const db = client.db("nestFinder");
    const propertiesCollection = db.collection("properties");
    const bookingsCollection = db.collection("bookings");

    //Featured Properties
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

    //Get All Properties
app.get('/all-properties', async (req, res) => {
  try {
    const { search, propertyType, sort } = req.query;
    const query = {status: 'Approved'};

    if (search && search !== "undefined") {
      query.location = { $regex: search, $options: 'i' };
    }

    if (propertyType && propertyType !== 'all') {
      query.propertyType = propertyType.toLowerCase(); 
    }

    const sortQuery = {};
    if (sort === 'low-to-high') {
      sortQuery.rent = 1;  
    } else if (sort === 'high-to-low') {
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


//Detaails Page
app.get('/all-properties/:id', async(req, res) =>{
  const {id} = req.params
  const result = await propertiesCollection.findOne({_id:new ObjectId(id)})
  res.send(result)
})

    //Owner Add Property
    app.post(
      "/owner/properties",
      verifyToken,
      ownerVerify,
      async (req, res) => {
        const data = req.body;
        const result = await propertiesCollection.insertOne({
          ...data,
          userId: req.user.id,
        });
        res.send(result);
      },
    );

    //Booking API
    app.post('/api/bookings', async (req, res) =>{
      const booking = req.body
      const newBooking = {
        ...booking,
        createdAt: new Date()
      }
      const result = await bookingsCollection.insertOne(newBooking)
      res.send(result)
    
    })

    //Owner Properties
    app.get("/owner/properties", verifyToken, ownerVerify, async (req, res) => {
      const { page = 1, limit = 10 } = req.query;
      const skip = (Number(page) - 1) * Number(limit);
      const result = await propertiesCollection
        .find({ userId: req.user.id })
        .skip(skip)
        .limit(Number(limit))
        .toArray();
      const totalData = await propertiesCollection.countDocuments({
        userId: req.user.id,
      });
      const totalPage = Math.ceil(totalData / Number(limit));
      res.send({ data: result, page: Number(page), totalPage });
    });

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
