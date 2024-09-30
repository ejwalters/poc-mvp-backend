const bcrypt = require('bcrypt');

const password = 'newpassword123';  // Replace this with the password you want to use
const saltRounds = 10;

bcrypt.hash(password, saltRounds, (err, hash) => {
  if (err) {
    console.error(err);
  } else {
    console.log(`Hashed password: ${hash}`);
  }
});
