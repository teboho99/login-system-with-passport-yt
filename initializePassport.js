const bcrypt = require("bcrypt");
const LocalStrategy = require("passport-local").Strategy;

function initialize(passport, getUserByEmail, getUserById) {
  const authUser = async (email, password, done) => {
    const user = getUserByEmail(email);
    if (user == null) return done(null, false, { message: "Invalid email" });
    try {
      if (await bcrypt.compare(password, user.password))
        return done(null, user);
      else return done(null, false, { message: "Password mismatch" });
    } catch (e) {
      done(e);
    }
  };
  passport.use(new LocalStrategy({ usernameField: "email" }, authUser));
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => {
    return done(null, getUserById(id));
  });
}

module.exports = initialize;
