# Discord OAuth2 Strategy for Passport.js

## Overview

This repository contains a custom OAuth2 strategy for authenticating with Discord using Passport.js. It allows user authentication via Discord and facilitates retrieval of user data, including profile information, guilds, and connections.

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
  profile.connection(accessToken, (err) => {
    if (err) return done(err, false);
    profile.guilds(accessToken, (err) => {
      if (err) return done(err, false);
      console.log("Authentication successful!", profile);
      // Call clean before saving to the database. Since we aren't using any other functionalities,
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

## Features

- **Data Consumption**: Allows for on-demand fetching of additional data.

- **Customizable Strategy**: Fully customizable strategy options, including custom data resolution via resolverApi function.

## Consumable Functions

These functions are available on the `profile` object to fetch additional data:

- **`profile.connection(accessToken, callback)`**: Fetches the user's connections. Requires the `connections` scope.
- **`profile.guilds(accessToken, callback)`**: Fetches the guilds the user is part of. Requires the `guilds` scope.
- **`profile.clean(callback)`** : Cleans the profile object by removing functions.
  more are comming soon..

### Example Profile Object

**Before Fetching Connections:**

```json
{
  "id": "123456789",
  "username": "exampleUser",
  "connections": [function: "getConnections"],
  "resolver" : [function: "resolver"],
  "clean": [function: "clean"]
}
```

**After Fetching Connections:**

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

The `clean` function cleans the profile object by removing functions.

```js
clean(profile, done) {
    Object.keys(profile).forEach((key) => {
      if (profile[key] instanceof Function) {
        delete profile[key];
      }
    });
    return done();
  }
```

### Example Usage

```js
function verify(accessToken, refreshToken, profile, done) {
  profile.resolver("guilds", "users/@me/guilds", accessToken, (err) => {
    if (err) return done(err);
    profile.clean(() => {
      // Perform operations like saving to the database here
      // Note: The cleaner will automatically run when invoking the done() function
      done(null, profile);
    });
  });
}
```

## Resolver Function

The `resolver` function allows customization of data fetching:

```js
profile.resolver = (key, api, accessToken, done) => {
  this.resolveApi(api, accessToken, (err, data) => {
    if (err) return done(err);
    profile[key] = data; // Store the resolved data in profile under the specified key
    return done(null, profile);
  });
};
```

### Example Usage

**Fetching Guilds Data with Resolver:**

```js
function verify(accessToken, refreshToken, profile, done) {
  profile.resolver("guilds", "users/@me/guilds", accessToken, (err) => {
    if (err) return done(err);
    done(null, profile); //stored in profile[given_key]
  });
}
```

## Basic Information Only

For scenarios where only basic user information is needed:

```js
function verify(accessToken, refreshToken, profile, done) {
  console.log("Fetched", profile);
  return done(null, profile);
}
```

After retrieving the data, before invoking `done function` will call a cleaner method that removes any unused consumable functions from the profile object. This ensures that only the essential data is passed forward.

## Refresh Tokens and Additional Handling

If you need to store the refreshToken, manage sessions, or handle other processes unrelated to Discord OAuth, such as storing data in a database, kindly refer to the passport.js documentation for more information on how to manage these tasks or explore other strategies that might need to be used for this additional handling.

## v1.0.1 patch

- Bound the cleaner function to the clean property of the profile, i.e., profile.clean().
