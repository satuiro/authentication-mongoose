require("dotenv").config();

// importing the required modules
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const TwitterStrategy = require("passport-twitter").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();


app.use(express.static("public"));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded({extended:true}));


//initializing the session and cookies 
app.use(session({
    secret:"little secret",
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());

//connecting to local mongooseDB server 
mongoose.connect("mongodb://127.0.0.1:27017/userDB",{useNewUrlParser:true});

const userSchema = new mongoose.Schema({
        email:String,
        password:String,
        googleId:String,
        secret:String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("user",userSchema);


passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });


// *****************authentication using google and twitter*****************
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


passport.use(new TwitterStrategy({
    consumerKey: process.env.TCLIENT_ID,
    consumerSecret: process.env.TCLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/twitter/secrets"
  },
  function(token, tokenSecret, profile, cb) {
    User.findOrCreate({ twitterId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
// ***************************************************


//setting up app route 
app.get("/",function(req,res){
    res.render("home");
});

app.route('/auth/google')

  .get(passport.authenticate('google', {

    scope: ['profile']

  }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


  app.get('/auth/twitter',
  passport.authenticate('twitter'));

app.get('/auth/twitter/secrets', 
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.get("/secrets",function(req,res){
    User.find({"secret":{$ne: null}})
    .then(function(foundUser){
        res.render("secrets",{userWithSecrets:foundUser});
    })
});

app.get("/submit",function(req,res){
    if (req.isAuthenticated()){
        res.render("submit");
    }else{
        res.render("login");
    }    
});
app.post("/submit",function(req,res){
    const secretText = req.body.secret;
    User.findById(req.user.id)
    .then(function(foundUser,err){
        if (foundUser){
            foundUser.secret=secretText;

            foundUser.save()
            .then(function(){
                res.redirect("/secrets");
            });
        }
    });
})

app.get("/logout",function(req,res){
    req.logout(function(err){});
    res.redirect("/");
})

app.post("/register",function(req,res){
   User.register({username:req.body.username},req.body.password,function(err,user){
    if (err){
        console.log(err);
        res.redirect("/register");
    }else{
        passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
        })
    }
   })

});



app.post("/login", function(req, res) {

    const user = new User({
        username:req.body.username,
        password:req.body.password
    });

    req.login(user, function(err){
        if (err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            })
        }
    });
  
  });

app.listen(3000,function(){
    console.log("The server is up and running");
});