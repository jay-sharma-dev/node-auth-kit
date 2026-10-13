import "dotenv/config";
import express from "express";
import { createAuth } from "../src/index";

const app = express();
app.use(express.json());

const auth = createAuth();

app.get("/public", (_req, res) => {
  res.json({ message: "Public route" });
});

app.get("/private", auth.middleware, (_req, res) => {
  res.json({
    message: "You are authenticated",
    user: res.locals.auth,
  });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
