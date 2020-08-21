//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");


const app = express();

console.log(process.env.API_KEY);

const port = process.env.PORT || 3000;

app.use(express.static("public"));
app.use(bodyParser.urlencoded({
  extended: true
}));
app.set("view engine", "ejs");

//tell app to use session package and set up. PLACEMENT IS IMPORTANT (above mongoose.connect)
app.use(session({
  secret: "I'll keep you a dirty little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize()); //tells app to init passport
app.use(passport.session()); //tells app to use passport to setup session


mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

userSchema.plugin(passportLocalMongoose); //will hash and salt passwords and save users in db

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get('/', (req, res) => {
  res.render('home');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.get("/secrets", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res){
   req.logout();
   res.redirect("/");
});


//use passport-local-mongoose docs
app.post("/register", function(req, res) {

  User.register({username: req.body.username}, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets"); //create app.get secrets
      });
    }
  });

});

app.post("/login", function(req, res) {

      const user = new User({
        username: req.body.username,
        password: req.body.password
      });

      //req.login from passport
      req.login(user, function(err) {
        if (err) {
          console.log(err);
        } else {
          passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
          });
        }
      });
  });

      app.listen(3000, function() {
        console.log("Server started on port 3000.");
      });
