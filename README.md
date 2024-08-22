# Discord OAuth2 Strategy for Passport.js

## Overview

This repository contains a custom OAuth2 strategy for authenticating with Discord using Passport.js. It facilitates user authentication via Discord and enables the retrieval of user data, including profile information, guilds, and connections.

## Installation

To use this strategy, first install Passport.js and then the custom strategy:

```bash
npm install passport discord-strategy
```

## Usage

Integrate the strategy into your Express application as follows:

### Example Setup

```javascript
const express = require("express");
const passport = require("passport");
const Strategy = require("discord-strategy");

const app = express();

// Define options for the Strategy
const options = {
  clientID: "YOUR_CLIENT_ID",
  clientSecret: "YOUR_CLIENT_SECRET",
  callbackURL: "http://localhost:3000/auth/discord/callback",
  scope: ["identify", "email", "guilds", "connections"], // Example scopes
};

// Create a new instance of the Strategy
passport.use(new Strategy(options, verify));

// Define the verify function
function verify(accessToken, refreshToken, profile, done) {
  profile.connection((err) => {
    if (err) return done(err, false);
    profile.guilds((err) => {
      if (err) return done(err, false);
      console.log("Authentication successful!", profile);
      // Call clean before saving to the database.
      // Since we're not using any other functionalities,
      // there's no need to call clean here.
      done(null, profile);
    });
  });
}

// Initialize Passport
app.use(passport.initialize());

// Define routes
app.get("/auth/discord", passport.authenticate("discord"));

app.get(
  "/auth/discord/callback",
  passport.authenticate("discord", { session: false }),
  (req, res) => {
    res.send(`
      <h1>Authentication successful!</h1>
      <h2>User Profile:</h2>
      <pre>${JSON.stringify(req.user, null, 2)}</pre>
    `);
  }
);

app.listen(3000, () => {
  console.log("Login via http://localhost:3000/auth/discord");
});
```

## Strategy Options

- **`clientID`**: Your Discord application's Client ID.
- **`clientSecret`**: Your Discord application's Client Secret.
- **`callbackURL`**: The URL to which Discord will redirect after authorization.
- **`scope`**: An array of scopes specifying the level of access (default: `["identify", "email"]`).

## Consumable Functions

You might ask why functions are attached to the profile instead of just fetching data directly and then putting it on the profile object. The reason lies in the structure of the Discord API and the flow of Passport.js. Since Passport.js is callback-based, if I want to add new functions in the future, I need to check scopes, invloke each function one by one, and then send it, which adds a little complexity. This approach avoids unnecessary complexity, increases the readability of your code, and simplifies logic.

Fancy reasons aside, I’m just lazy, and this way feels good.

These functions are available on the `profile` object to fetch additional data:

- **`profile.connection(callback)`**: Fetches the user's connections. Requires the `connections` scope.
- **`profile.guilds(callback)`**: Fetches the guilds the user is part of. Requires the `guilds` scope.
- **`profile.clean(callback)`**: Cleans the profile object by removing functions.
- **`profile.guildJoiner(botToken, serverId, nickname, roles, callback)`** : Adds the user to a guild with optional parameters for setting a nickname and assigning roles.
- **`profile.resolver(key, api, callback)`**: Fetches data from a specified API endpoint and stores it under the given key in the profile.
- **`profile.complexResolver(method, api, body, callback)`**: Allows customization of data fetching with more complex API interactions. The access token is sent as a query parameter btw.

### Example Profile Object

**Before Consuming Connections:**

```json
{
  "id": "123456789",
  "username": "exampleUser",
  "connections": [function: "getConnections"],
  "resolver" : [function: "resolver"],
  "complexResolver" : [function: "complexResolver"],
  "clean": [function: "clean"]
}
```

**After Consuming Connections and Applying Clean:**

```json
{
  "id": "123456789",
  "username": "exampleUser",
  "connections": [
    { "connectionName": "Steam", "id": "steam_12345" },
    { "connectionName": "Twitch", "id": "twitch_12345" }
  ]
}
```

## Cleaner Function

The `clean` function removes any functions from the profile object, leaving only the essential data.

```javascript
clean(profile, done) {
  Object.keys(profile).forEach((key) => {
    if (typeof profile[key] === "function") {
      delete profile[key];
    }
  });
  return done();
}
```

### Example Usage

```javascript
function verify(accessToken, refreshToken, profile, done) {
  profile.resolver("guilds", "users/@me/guilds", (err) => {
    if (err) return done(err);
    profile.clean(() => {
      // Perform operations like saving to the database here
      done(null, profile);
    });
  });
}
```

## guildJoiner()

```javascript
function verify(accessToken, refreshToken, profile, done) {
  profile.guildJoiner(
    "bot_token",
    "server_id",
    null, // value to set user's nickname to (string)
    null, // array of role IDs to assign to the user (string[])
    (err) => {
      // Response status codes:
      // 201 => Joined
      // 204 => Already in the guild
      if (err) return done(err, false, "Failed to join guild");
      done(null, profile);
      console.log("Authentication successful!", profile);
    }
  );
}
```

## Resolver Functions

### Basic Get Resolver

The `resolver` function allows for the customization of data fetching for basic GET requests:

```javascript
profile.resolver = (key, api, done) => {
  this.resolveApi(api, (err, data) => {
    if (err) return done(err);
    profile[key] = data; // Store the resolved data in the profile under the specified key
    return done(null, profile);
  });
};
```

### Example Usage

**Fetching Guilds Data with Resolver:**

```javascript
function verify(accessToken, refreshToken, profile, done) {
  profile.resolver("guilds", "users/@me/guilds", (err) => {
    if (err) return done(err);
    done(null, profile); // Stored in profile[guilds]
  });
}
```

### Complex Resolver

The `complexResolver` function allows for more complex data interactions:

```javascript
profile.complexResolver(
  "PUT",
  `guilds/${serverId}/members/${profile.id}`,
  {
    Authorization: `Bot ${botToken}`,
    "content-type": "application/json",
  },
  JSON.stringify({
    nick: nickname,
    roles: ["role_id_1", "role_id_2", "role_id_3", "role_id_4"],
  }),
  (err, result, res) => {
    if (err) return done(err, false);
    if (res.statusCode === 201 || res.statusCode === 204)
      return done(null, profile);
  }
);
```

## Basic Information Only

For scenarios where only basic user information is needed:

```javascript
function verify(accessToken, refreshToken, profile, done) {
  console.log("Fetched", profile);
  return done(null, profile);
}
```

Before invoking the `done` function, the cleaner method will be called to remove any unused consumable functions from the profile object. This ensures that only essential data is passed forward.

## Refresh Tokens and Additional Handling

If you need to store the `refreshToken`, manage sessions, or handle other processes unrelated to Discord OAuth, please refer to the Passport.js documentation for more information on managing these tasks or explore other strategies that might be necessary for additional handling.

## Changelog

### v1.1 Patch

- No longer required to pass the access token to the consumable functions.
- Added two new consumable functions: `complexResolver()` and `guildJoiner()`.

### v1.0.1 Patch

- Bound the cleaner function to the `clean` property of the profile (`profile.clean()`).
