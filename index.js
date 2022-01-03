const express = require("express");
const JsonDB = require("node-json-db").JsonDB;
const Config = require("node-json-db/dist/lib/JsonDBConfig").Config;
const uuid = require("uuid");
const cors = require('cors');
const app = express();

var db = new JsonDB(new Config("myDataBase", true, false, "/"));
const authenticator = require('authenticator');

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.get("/api", (req, res) => {
  res.json({ message: "Welcome to the two factor authentication exmaple" });
});

app.post("/api/register", (req, res) => {
  const id = uuid.v4();
  try {
    const path = `/user/${id}`;
    const formattedKey = authenticator.generateKey();
    db.push(path, { id, secret: formattedKey });
    const url = authenticator.generateTotpUri(formattedKey, "radhika@mailinator.com", 'INTECH FINANCE SA', 'SHA1', 10, 60);
    const formattedToken = authenticator.generateToken(formattedKey);
    res.json({ id, secret: formattedKey, token: formattedToken, url });
  } catch (e) {
    console.log(e);
    res.status(500).json({ message: "Error generating secret key" });
  }
});

app.post("/api/regenerate-token", (req, res) => {
  const { userId} = req.body;
  try {
    const path = `/user/${userId}`;
    const user = db.getData(path);
    const { secret } = user;
    const formattedToken = authenticator.generateToken(secret);
    if (formattedToken) {
      res.json({ token: formattedToken});
    } else {
      res.json({ verified: false });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error retrieving user" });
  }
});

app.post("/api/verify", (req, res) => {
  const { userId, token } = req.body;
  try {
    const path = `/user/${userId}`;
    const user = db.getData(path);
    const { secret } = user;
    const verified = authenticator.verifyToken(secret, token);
    if (verified) {
      db.push(path, { id: userId, secret: user.secret });
      res.json({ verified: true });
    } else {
      res.json({ verified: false });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error retrieving user" });
  }
});

const port = 9000;

app.listen(port, () => {
  console.log(`App is running on PORT: ${port}.`);
});
