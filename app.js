//jshint esversion:6
import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import encrypt from "mongoose-encryption"
import _ from "lodash";
// import md5 from "md5";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as FacebookStrategy } from "passport-facebook";
import LocalStrategy from "passport-local";
import passportLocalMongoose from "passport-local-mongoose";
import findOrCreate from "mongoose-findorcreate";
// import bcrypt from "bcrypt";
// const saltRounds = 10;

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

const mongoAtlas = `mongodb+srv://${process.env.SERVER_NAME}:${process.env.SERVER_PASS}@secretscluster.jrjpx.mongodb.net/UserDB`

main().catch(err => console.log(err));

async function main() {
    await mongoose.connect(mongoAtlas);

    // schema stuff
    const userSchema = new mongoose.Schema({
        email: String,
        password: String,
        googleId: String,
        facebookId: String,
        secret: String
    });

    // userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

    userSchema.plugin(passportLocalMongoose);
    userSchema.plugin(findOrCreate);
    // userSchema.plugin(findOrCreate);

    const User = mongoose.model("User", userSchema);

    passport.use(User.createStrategy());

    passport.serializeUser(function (user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function (id, done) {
        User.findById(id, function (err, user) {
            done(err, user);
        });
    });

    passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets"
    },
        function (accessToken, refreshToken, profile, cb) {
            console.log(profile);
            User.findOrCreate({ googleId: profile.id }, function (err, user) {
                return cb(err, user);
            });
        }
    ));

    passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_CLIENT_ID,
        clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/callback"
    },
        function (accessToken, refreshToken, profile, cb) {
            User.findOrCreate({ facebookId: profile.id }, function (err, user) {
                return cb(err, user);
            });
        }
    ));

    // passport.use(new TwitterStrategy({
    //     consumerKey: TWITTER_CONSUMER_KEY,
    //     consumerSecret: TWITTER_CONSUMER_SECRET,
    //     callbackURL: "http://localhost:3000/auth/twitter/callback"
    // },
    //     function (token, tokenSecret, profile, cb) {
    //         User.findOrCreate({ twitterId: profile.id }, function (err, user) {
    //             return cb(err, user);
    //         });
    //     }
    // ));

    // routing

    // google authenticating
    app.get("/auth/google",
        passport.authenticate("google", { scope: ["profile"] }));

    app.get("/auth/google/secrets",
        passport.authenticate("google", { failureRedirect: "/login" }),
        function (req, res) {
            // Successful authentication, redirect home.
            res.redirect("/secrets");
        });

    // facebook authenticating
    app.get("/auth/facebook",
        passport.authenticate("facebook"));

    app.get("/auth/facebook/callback",
        passport.authenticate("facebook", { failureRedirect: "/login" }),
        function (req, res) {
            // Successful authentication, redirect home.
            res.redirect("/");
        });

    // // twitter authenticating
    // app.get("/auth/twitter",
    //     passport.authenticate("twitter"));

    // app.get("/auth/twitter/callback",
    //     passport.authenticate("twitter", { failureRedirect: "/login" }),
    //     function (req, res) {
    //         // Successful authentication, redirect home.
    //         res.redirect("/");
    //     });

    app.route("/")
        .get((req, res) => {
            res.render("home")
        });


    app.route("/login")
        .get((req, res) => {
            res.render("login")
        })
        .post((req, res) => {
            const username = req.body.username;
            const password = req.body.password;
            const user = new User({
                username: username,
                password: password
            });
            req.login(user, (err) => {
                if (!err) {
                    passport.authenticate("local")(req, res, function () {
                        res.redirect("/secrets")
                    })
                } else {
                    console.log(err);
                }
            })
        });
    // .post((req, res) => {
    // const username = req.body.username;
    // const password = req.body.password;
    //     User.findOne({
    //         email: username
    //     }, (err, foundUser) => {
    //         if (!err) {
    //             if (bcrypt.compare(password, foundUser.password)) {
    //                 res.render("secrets");
    //             } else {
    //                 console.log("Incorrect password");
    //             }
    //         } else {
    //             console.log(err);
    //         }
    //     })
    // });

    app.route("/secrets")
        .get((req, res) => {
            User.find({ "secret": { $ne: null } }, (err, foundUsers) => {
                if (!err) {
                    if (foundUsers) {
                        res.render("secrets", { usersWithSecrets: foundUsers })
                    }
                } else {
                    console.log(err);
                }
            })
        });

    app.route("/register")
        .get((req, res) => {
            res.render("register")
        })
        .post((req, res) => {
            const newUserEmail = req.body.username;
            const newUserPass = req.body.password;
            User.findOne({ username: newUserEmail }, (err, foundUser) => {
                if (!err) {
                    if (foundUser) {
                        console.log("Email already in use");
                    } else {
                        User.register({ username: newUserEmail }, newUserPass, (err, user) => {
                            if (!err) {
                                passport.authenticate("local")(req, res, function () {
                                    res.redirect("/secrets")
                                });
                            } else {
                                console.log(err);
                                res.redirect("/register")
                            };
                        });
                    };
                };
            });
        });

    app.route("/logout")
        .get((req, res) => {
            req.logout();
            res.redirect("/")
        });

    app.route("/submit")
        .get((req, res) => {
            if (req.isAuthenticated()) {
                res.render("submit")
            } else {
                res.redirect("/login");
            };
        })
        .post((req, res) => {
            const newSecret = req.body.secret;

            User.findById(req.user.id, function (err, foundUser) {
                if (!err) {
                    foundUser.secret = newSecret;
                    foundUser.save(function () {
                        res.redirect("/secrets");
                    })
                } else {
                    console.log(err);
                }
            })
        });

    // .post((req, res) => {
    // const newUserEmail = req.body.username;
    // const newUserPass = req.body.password;
    //     bcrypt.hashSync(newUserPass, saltRounds, function (err, hash) {
    //         const newUser = new User({
    //             email: newUserEmail,
    //             password: hash
    //         });
    //         User.findOne({
    //             email: newUserEmail
    //         }, (err, foundUser) => {
    //             if (!err) {
    //                 if (foundUser) {
    //                     console.log("Email already in use");
    //                 } else {
    //                     newUser.save(err => {
    //                         if (!err) {
    //                             res.render("secrets");
    //                         } else {
    //                             console.log(err);
    //                         };
    //                     });
    //                 };
    //             } else {
    //                 console.log(err);
    //             };
    //         });
    //     });
    // });


    let port = process.env.PORT;
    if (port == null || port == "") {
        port = 3000;
    }

    app.listen(port, function () {
        console.log(`Your server is running on ${port}`);
    });
}
