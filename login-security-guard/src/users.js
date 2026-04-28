// Mock user database
const users = {
  alice: { password: "password123", role: "admin" },
  bob: { password: "securepass", role: "user" },
  charlie: { password: "charlie99", role: "user" },
};

function validateUser(username, password) {
  const user = users[username];
  if (!user) return { valid: false, reason: "user_not_found" };
  if (user.password !== password) return { valid: false, reason: "wrong_password" };
  return { valid: true, role: user.role };
}

module.exports = { validateUser };
