//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");
// const FacebookStrategy = require('passport-facebook').Strategy;


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

// passport.serializeUser(function(user, done) {
//   done(null, user.id);
// });
//
// passport.deserializeUser(function(id, done) {
//   User.findById(id, function(err, user) {
//     done(err, user);
//   });
// });


mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true }, // values: email address, googleId, facebookId
  password: String,
  provider: String, // values: 'local', 'google', 'facebook'
  email: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose, {
  usernameField: "username"
});
userSchema.plugin(findOrCreate); //calls findOrCreate function via plugin

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// SECTION 3: Google Strategy
passport.use(new GoogleStrategy({
       clientID: process.env.CLIENT_ID,
       clientSecret: process.env.CLIENT_SECRET,
       callbackURL: "http://localhost:3000/auth/google/secrets",
       userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
   },
   function (accessToken, refreshToken, profile, cb) {
console.log(profile);

       User.findOrCreate( //findOrCreate is a Passport pseudocode
         { username: profile.id },
         {
           provider: "google",
           email: profile._json.email
         },
         function (err, user) {
             return cb(err, user);
         }
       );
   }
));

// //Facebook Strategy
// passport.use(new FacebookStrategy({
//         clientID: process.env.FACEBOOK_APP_ID,
//         clientSecret: process.env.FACEBOOK_APP_SECRET,
//         callbackURL: "http://localhost:3000/auth/facebook/secrets",
//         profileFields: ["id", "email"]
//     },
//     function (accessToken, refreshToken, profile, cb) {
//         User.findOrCreate(
//           { username: profile.id },
//           {
//             provider: "facebook",
//             email: profile._json.email
//           },
//           function (err, user) {
//             return cb(err, user);
//           }
//         );
//     }
// ));

app.get('/', (req, res) => {
  res.render('home');
});

app.get('/auth/google',
    passport.authenticate('google', {
        scope: ['profile', 'email']
    })
);

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
  });




app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.get("/secrets", function(req, res) {
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err){
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers}); //pass in usersWithSecrets variable to foundUsers as value
      }
    }
  });
});



app.get("/submit", function(req, res){
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

//Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  // console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
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
