// controllers/UsersController.js

const crypto = require('crypto');
const dbClient = require('../utils/db');

class UsersController {
  static async postNew(req, res) {
    const { email, password } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Missing email' });
    }

    if (!password) {
      return res.status(400).json({ error: 'Missing password' });
    }

    const usersCollection = dbClient.db.collection('users');
    const userExists = await usersCollection.findOne({ email });

    if (userExists) {
      return res.status(400).json({ error: 'Already exist' });
    }

    const hashedPassword = crypto
      .createHash('sha1')
      .update(password)
      .digest('hex');
    const result = await usersCollection.insertOne({
      email,
      password: hashedPassword,
    });

    const user = result.ops[0];
    return res.status(201).json({ id: user._id, email: user.email });
  }
}

module.exports = UsersController;
