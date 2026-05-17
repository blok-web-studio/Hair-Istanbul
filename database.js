const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join(__dirname, 'hair_istanbul_db.json');
const adapter = new JSONFile(dbPath);
const db = new Low(adapter, {
  users: [],
  visitors: [],
  bookings: []
});

async function initializeDatabase() {
  await db.read();
  
  db.data = db.data || {
    users: [],
    visitors: [],
    bookings: []
  };

  const permanentUser = db.data.users.find(u => u.username === process.env.PERMANENT_USER_USERNAME);
  
  if (!permanentUser) {
    const passwordHash = bcrypt.hashSync(process.env.PERMANENT_USER_PASSWORD, 12);
    db.data.users.push({
      id: Date.now(),
      username: process.env.PERMANENT_USER_USERNAME,
      password_hash: passwordHash,
      is_permanent: true,
      created_at: new Date().toISOString()
    });
  }

  const adminUser = db.data.users.find(u => u.username === process.env.ADMIN_USERNAME);
  
  if (!adminUser) {
    const passwordHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
    db.data.users.push({
      id: Date.now() + 1,
      username: process.env.ADMIN_USERNAME,
      password_hash: passwordHash,
      is_permanent: false,
      created_at: new Date().toISOString()
    });
  }

  await db.write();
}

initializeDatabase();

module.exports = db;
