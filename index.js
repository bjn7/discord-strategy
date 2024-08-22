const OAuth2Strategy = require("passport-oauth2"),
  { InternalOAuthError } = require("passport-oauth2"),
  utils = require("passport-oauth2/lib/utils");

const url = require("url");
const API_BASE = "https://discord.com/api/";

/**
 * `Strategy` constructor.
 *
 * The Discord authentication strategy authenticates requests by delegating to
 * Discord using the OAuth 2.0 protocol.
 *P
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Discord application's Client ID
 *   - `clientSecret`  your Discord application's Client Secret
 *   - `callbackURL`   URL to which Discord will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new Strategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret',
 *         callbackURL: 'https://www.example.com/auth/discord/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate({ discordId: profile.id }, function (err, user) {
 *           return done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options - Configuration options.
 * @param {Function} verify - The verify callback function.
 */

class Strategy extends OAuth2Strategy {
  constructor(options, verify) {
    options = options || {};
    options.authorizationURL =
      options.authorizationURL || "https://discord.com/api/oauth2/authorize";
    options.tokenURL =
      options.tokenURL || "https://discord.com/api/oauth2/token";
    options.scopeSeparator = options.scopeSeparator || " ";
    options.scope = options.scope || ["identify", "email"];

    if (!options.callbackURL) throw new Error("Missing callbackURL property");
    if (!options.clientID) throw new Error("Missing clientID property");
    if (!options.clientSecret) throw new Error("Missing clientSecret property");

    super(options, verify); // Call the parent constructor
    this.name = "discord";
    this._oauth2.useAuthorizationHeaderforGET(true);
  }

  /**
   * Retrieve user profile from Discord.
   * @param {String} accessToken - The access token used to authenticate the request.
   * @param {Function} done - The callback function to call with the result.
   */
  userProfile(accessToken, done) {
    this.getUser(accessToken, (err, result) => {
      if (err) {
        return done(err, null);
      }

      let profile = result;
      //Allowed Sizes 16, 32, 64, 128, 256, 512, 1024, 2048, 4096
      profile.avtarUrl = `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}`;
      profile.connection = this.getConnection.bind(this, profile, accessToken);
      profile.guilds = this.getGuilds.bind(this, profile, accessToken);
      profile.clean = this.clean.bind(this, profile);
      profile.guildJoiner = this.guildJoiner.bind(this, profile, accessToken);
      profile.complexResolver = this._oauth2._request;
      profile.resolver = (key, api, accessToken, done) => {
        this.resolveApi(api, accessToken, (err, data) => {
          if (err) {
            return done(err);
          }
          profile[key] = data; // Store the resolved data in profile under the specified key
          return done(null, profile);
        });
      };
      return done(null, profile);
    });
  }

  /**
   * Retrieve user information from the Discord API.
   * @param {String} accessToken - The access token used to authenticate the request.
   * @param {Function} done - The callback function to call with the result.
   */
  getUser(accessToken, done) {
    return this.resolveApi("users/@me", accessToken, done);
  }

  /**
   * Retrieve user connections from the Discord API.
   * @param {Object} profile - The user profile object.
   * @param {String} accessToken - The access token used to authenticate the request.
   * @param {Function} done - The callback function to call with the result.
   */
  getConnection(profile, accessToken, done) {
    if (!this._scope || !this._scope.includes("connections"))
      return done(new Error("Missing Scope, 'connections'"), null);

    this.resolveApi(
      "users/@me/connections",
      accessToken,
      (err, connections) => {
        if (err) {
          return done(err);
        }
        profile.connection = connections; // Store connections in profile
        return done(null, profile);
      }
    );
  }

  getGuilds(profile, accessToken, done) {
    if (!this._scope || !this._scope.includes("guilds"))
      return done(new Error("Missing Scope, 'guilds'"));
    this.resolveApi("users/@me/guilds", accessToken, (err, guild) => {
      if (err) {
        return done(err);
      }
      profile.guilds = guild; // Store connections in profile
      return done(null, profile);
    });
  }
  guildJoiner(profile, accessToken, botToken, serverId, nick, roles, done) {
    /*
    nick	string	value to set user's nickname to	MANAGE_NICKNAMES
    roles	array of snowflakes	array of role ids the member is assigned	MANAGE_ROLES
    mute	boolean	whether the user is muted in voice channels	MUTE_MEMBERS
    deaf	boolean	whether the user is deafened in voice channels	DEAFEN_MEMBERS
    */
    if (!this._scope || !this._scope.includes("guilds.join"))
      return done(new Error("Missing Scope, 'guilds.join'"));
    // can't use resolve api, as it is only support for get.
    //gotta use inter _request api.
    var _default = {
      access_token: accessToken,
    };

    if (nick) _default.nick = nick;
    if (roles) _default.roles = roles;

    // Mute and deaf don't seem to have any practical use, so they have been skipped.
    // If you want to use it, just copy this code, modify and pass to complexResolver.

    return this._oauth2._request(
      "PUT",
      API_BASE + `guilds/${serverId}/members/${profile?.id}`,
      {
        Authorization: `Bot ${botToken}`,
        "content-type": "application/json",
      },
      JSON.stringify(_default),
      null,
      (err, result, res) => {
        if (err) done(err);
        if (res.statusCode === 201 || res.statusCode === 204) return done();
      }
    );
  }

  /**
   * Clean the user object by removing functions.
   * @param {Object} profile - The user object to clean.
   * @returns {Function} done - The cleaned user object.
   */
  clean(profile, done) {
    Object.keys(profile).forEach((key) => {
      if (profile[key] instanceof Function) {
        delete profile[key];
      }
    });
    return done();
  }

  /**
   * Resolve the API request and parse the result.
   * @param {String} api - The API endpoint.
   * @param {String} accessToken - The access token used to authenticate the request.
   * @param {Function} cb - The callback function to call with the result.
   */

  resolveApi(api, accessToken, cb) {
    this._oauth2.get(API_BASE + api, accessToken, (err, result) => {
      this._oauth2.get;
      if (err) {
        return cb(new InternalOAuthError("Failed to resolve API", err));
      }
      try {
        const parsedData = JSON.parse(result);
        return cb(null, parsedData);
      } catch (e) {
        return cb(new Error("Failed to parse the user profile."), null);
      }
    });
  }

  /**
   * Authenticate the request.
   * @param {Object} req - The request object.
   * @param {Object} options - Authentication options.
   */
  authenticate(req, options) {
    options = options || {};
    var self = this;

    if (req.query && req.query.error) {
      if (req.query.error == "access_denied") {
        return this.fail({ message: req.query.error_description });
      } else {
        return this.error(
          new AuthorizationError(
            req.query.error_description,
            req.query.error,
            req.query.error_uri
          )
        );
      }
    }

    var callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      var parsed = url.parse(callbackURL);
      if (!parsed.protocol) {
        // The callback URL is relative, resolve a fully qualified URL from the
        // URL of the originating request.
        callbackURL = url.resolve(
          utils.originalURL(req, { proxy: this._trustProxy }),
          callbackURL
        );
      }
    }

    var meta = {
      authorizationURL: this._oauth2._authorizeUrl,
      tokenURL: this._oauth2._accessTokenUrl,
      clientID: this._oauth2._clientId,
      callbackURL: callbackURL,
    };

    if ((req.query && req.query.code) || (req.body && req.body.code)) {
      function loaded(err, ok, state) {
        if (err) {
          return self.error(err);
        }
        if (!ok) {
          return self.fail(state, 403);
        }

        var code = (req.query && req.query.code) || (req.body && req.body.code);

        var params = self.tokenParams(options);
        params.grant_type = "authorization_code";
        if (callbackURL) {
          params.redirect_uri = callbackURL;
        }
        if (typeof ok == "string") {
          // PKCE
          params.code_verifier = ok;
        }

        self._oauth2.getOAuthAccessToken(
          code,
          params,
          function (err, accessToken, refreshToken, params) {
            if (err) {
              return self.error(
                self._createOAuthError("Failed to obtain access token", err)
              );
            }
            if (!accessToken) {
              return self.error(new Error("Failed to obtain access token"));
            }

            self._loadUserProfile(accessToken, function (err, profile) {
              if (err) {
                return self.error(err);
              }

              function verified(err, user, info) {
                //if cleaner wasn't called this will make sure to clean, while storing in session
                Object.keys(user).forEach((key) => {
                  if (user[key] instanceof Function) {
                    delete user[key];
                  }
                });
                if (err) {
                  return self.error(err);
                }
                if (!user) {
                  return self.fail(info);
                }

                info = info || {};
                if (state) {
                  info.state = state;
                }
                self.success(user, info);
              }

              try {
                if (self._passReqToCallback) {
                  var arity = self._verify.length;
                  if (arity == 6) {
                    self._verify(
                      req,
                      accessToken,
                      refreshToken,
                      params,
                      profile,
                      verified
                    );
                  } else {
                    // arity == 5
                    self._verify(
                      req,
                      accessToken,
                      refreshToken,
                      profile,
                      verified
                    );
                  }
                } else {
                  var arity = self._verify.length;
                  if (arity == 5) {
                    self._verify(
                      accessToken,
                      refreshToken,
                      params,
                      profile,
                      verified
                    );
                  } else {
                    // arity == 4
                    self._verify(accessToken, refreshToken, profile, verified);
                  }
                }
              } catch (ex) {
                return self.error(ex);
              }
            });
          }
        );
      }

      var state =
        (req.query && req.query.state) || (req.body && req.body.state);
      try {
        var arity = this._stateStore.verify.length;
        if (arity == 4) {
          this._stateStore.verify(req, state, meta, loaded);
        } else {
          // arity == 3
          this._stateStore.verify(req, state, loaded);
        }
      } catch (ex) {
        return this.error(ex);
      }
    } else {
      var params = this.authorizationParams(options);
      params.response_type = "code";
      if (callbackURL) {
        params.redirect_uri = callbackURL;
      }
      var scope = options.scope || this._scope;
      if (scope) {
        if (Array.isArray(scope)) {
          scope = scope.join(this._scopeSeparator);
        }
        params.scope = scope;
      }
      var verifier, challenge;

      if (this._pkceMethod) {
        verifier = base64url(crypto.pseudoRandomBytes(32));
        switch (this._pkceMethod) {
          case "plain":
            challenge = verifier;
            break;
          case "S256":
            challenge = base64url(
              crypto.createHash("sha256").update(verifier).digest()
            );
            break;
          default:
            return this.error(
              new Error(
                "Unsupported code verifier transformation method: " +
                  this._pkceMethod
              )
            );
        }

        params.code_challenge = challenge;
        params.code_challenge_method = this._pkceMethod;
        if (this._stateStore) {
          var state = utils.uid(24);
          params.state = state;
          this._stateStore.save(req, state, verifier, meta, function (err) {
            if (err) {
              return this.error(err);
            }
            this.redirect(self._oauth2.getAuthorizeUrl(params));
          });
        } else {
          this.redirect(self._oauth2.getAuthorizeUrl(params));
        }
      } else {
        this.redirect(self._oauth2.getAuthorizeUrl(params));
      }
    }
  }
}

module.exports = Strategy;
