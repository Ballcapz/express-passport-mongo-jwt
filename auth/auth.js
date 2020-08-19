const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const UserModel = require('../model/model');

passport.use('signup', new localStrategy({
    usernameField: 'email',
    passwordField: 'password',
}, async (email, password, done) => {
    try {
        const user = await UserModel.create({ email, password });
        return done(null, user);
    } catch (err) {
        // IF THIS BREAKS, RETURN DONE.
        done(err);
    }
}));

passport.use('login', new localStrategy({
    usernameField: 'email',
    passwordField: 'password',
}, async (email, password, done) => {
    try {
        const user = await UserModel.findOne({ email });
        if (!user) {
            return done(null, false, { message: 'User not found' });
        }

        const validate = await user.isValidPassword(password);
        if (!validate) {
            return done(null, false, { message: 'Wrong password' });
        }

        return done(null, user, { message: 'logged in successfully' });
    } catch (err) {
        return done(err);
    }
}))

// JWT

const JWTStrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;

passport.use(new JWTStrategy({
    secretOrKey: 'top_secret',
    jwtFromRequest: ExtractJWT.fromUrlQueryParameter('secret_token')
}, async (token, done) => {
    try {
        return done(null, token.user);
    } catch (error) {
        done(error)
    }
}));