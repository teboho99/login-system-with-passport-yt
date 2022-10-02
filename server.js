const express = require("express");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const initialize = require("./initializePassport");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const usersDB = {
  users: [],
  setUsers: function (payload) {
    this.users = payload;
  },
};

initialize(
  passport,
  (email) => usersDB.users.find((user) => user.email == email),
  (id) => usersDB.users.find((user) => user.id == id)
);

app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.get("/", checkAuthenticated, (req, res) => {
  res.render("index.ejs", { name: req.user.name.toUpperCase() });
});
app.get("/register", checkUnauthenticated, (req, res) => {
  res.render("register.ejs");
});
app.get("/login", checkUnauthenticated, (req, res) => {
  res.render("login.ejs");
});
app.post("/register", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    usersDB.setUsers([
      ...usersDB.users,
      {
        id: Date.now().toString(),
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
      },
    ]);
    res.redirect("/login");
  } catch (e) {
    res.redirect("/register");
  }
});
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureFlash: true,
    failureRedirect: "/login",
  })
);

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}
function checkUnauthenticated(req, res, next) {
  if (req.isAuthenticated()) return res.redirect("/");
  next();
}
app.listen(PORT, () => console.log(`listening on ${PORT}`));
