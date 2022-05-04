import express from 'express';
// import passport from "passport";
import { Passport } from 'passport';
import session from 'express-session';
import localStrategy from "passport-local";

const app = express();

app.route("/")
    .get((req, res) => {
        res.render("home")
    });

app.route("/login")
    .get((req, res) => {
        res.render("login")
    })
    .post((req, res) => {
        '/authenticate', Passport.authenticate('local', { successRedirect: "/", failureRedirect: "/login" }
        )
    });

app.route("/register")
    .get((req, res) => {
        res.render("register");
    })
    .post((req, res) => {
        '/authenticate', Passport.authenticate('local', { successRedirect: "/", failureRedirect: "/register" }
        )
    });
