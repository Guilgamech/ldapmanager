process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

const assert = require("assert");

const router = require("express").Router();
const ldap = require("ldapjs");
const win32_js_date = require("win32-js-date");
const { body, validationResult } = require("express-validator");

let client = null;

const baseDN = "OU=CATALOGO,DC=reduc,DC=edu,DC=cu";
const searchDN = "DC=reduc,DC=edu,DC=cu";

router.get("/", (req, res) => {
  res.send("api works");
});

router.post(
  "/login",
  ldapConnect,
  [body("email").isEmail(), body("password").not().isEmpty()],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    bind(req.body.email, req.body.password, function (err) {
      if (err) {
        return res.status(400).send({
          error: err.message,
        });
      } else {
        const authToken = Buffer.from(
          `${req.body.email}:${req.body.password}`,
          "utf8"
        ).toString("base64");

        search(req.body.email, (user, error) => {
          if (error) {
            return res.status(400).send({
              error,
            });
          } else {
            user[0]["authToken"] = authToken;
            res.json(user);
            return;
          }
        });
      }
    });
  }
);

router.get("/logout", (req, res) => {
  ldapDisconnect();
  res.end();
});

router.post(
  "/find",
  [body("query").not().isEmpty()],
  ldapConnect,
  auth,
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    search(req.body.query, (users, error) => {
      if (error) {
        return res.status(400).send({
          error,
        });
      } else {
        res.json(users);
        return;
      }
    });
  }
);

router.post(
  "/add",
  body("dn").not().isEmpty(),
  ldapConnect,
  auth,
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const entry = req.body.entry;
    entry["mail"] = entry["sAMAccountName"] + "@reduc.edu.cu";
    entry["userPrincipalName"] = entry["mail"];
    entry["objectClass"] = ["top", "person", "organizationalPerson", "user"];
    entry["userAccountControl"] = 66048;
    entry["serviceInternet"] = "enable";
    entry["serviceMail"] = "enable";
    entry["serviceJabber"] = "enable";
    entry["serviceMailRecipient"] = "int";
    entry["serviceMailSender"] = "int";
    entry["unicodePwd"] = Buffer.from(
      `"${entry["unicodePwd"]}"`,
      "utf16le"
    ).toString();
    if (entry["accountExpires"]) {
      entry["accountExpires"] = win32_js_date.toWin(
        new Date(entry["accountExpires"])
      );
    } else {
      delete entry["accountExpires"];
    }

    client.add(req.body.dn, entry, function (err) {
      if (err) {
        return res.status(400).send({
          error: err.message,
        });
      }
      return res.sendStatus(200);
    });
  }
);

router.put(
  "/update",
  body("dn").not().isEmpty(),
  ldapConnect,
  auth,
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    let modification = req.body.modification["unicodePwd"]
      ? {
          unicodePwd: Buffer.from(
            `"${req.body.modification["unicodePwd"]}"`,
            "utf16le"
          ).toString(),
          userAccountControl: 66048,
        }
      : req.body.modification;

    const change = new ldap.Change({
      operation: "replace",
      modification: modification,
    });

    client.modify(req.body.dn, change, function (err) {
      if (err) {
        return res.status(400).send({
          error: err.message,
        });
      }
      return res.sendStatus(200);
    });
  }
);

router.put(
  "/move",
  [body("oldDN").not().isEmpty(), body("newDN").not().isEmpty()],
  ldapConnect,
  auth,
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    client.modifyDN(req.body.oldDN, req.body.newDN, (err) => {
      if (err) {
        return res.status(400).send({
          error: err.message,
        });
      }
      return res.sendStatus(200);
    });
  }
);

router.delete(
  "/delete",
  body("dn").not().isEmpty(),
  ldapConnect,
  auth,
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    client.del(req.body.dn, function (err) {
      if (err) {
        return res.status(400).send({
          error: err.message,
        });
      }
      return res.sendStatus(200);
    });
  }
);

router.post("/ou", ldapConnect, auth, (req, res) => {
  const opts = {
    scope: "one",
    timeLimit: 6000,
    attributes: ["ou", "description"],
  };

  const searchOU = `${req.body.ou},${baseDN}`;

  client.search(searchOU, opts, (err, resp) => {
    if (err) {
      return resp.status(400).send({
        error: err.message,
      });
    }

    const ous = [];
    resp.on("searchEntry", function (entry) {
      ous.push(entry.object);
    });
    resp.on("searchReference", function (referral) {
      console.log("referral: " + referral.uris.join());
    });
    resp.on("error", function (err) {
      console.error("error: " + err.message);
      res.status(500).send({
        error: err.message,
      });
    });
    resp.on("end", function (result) {
      console.log("status: " + result.status);
      res.json(ous);
      return;
    });
  });
});

function auth(req, res, next) {
  // check for basic auth header
  if (
    !req.headers.authorization ||
    req.headers.authorization.indexOf("Bearer ") === -1
  ) {
    return res.status(401).json({ error: "Missing Authorization Header" });
  }

  // verify auth credentials
  const base64Credentials = req.headers.authorization.split(" ")[1];
  const credentials = Buffer.from(base64Credentials, "base64").toString("utf8");
  const [email, password] = credentials.split(":");

  bind(email, password, function (err) {
    if (err) {
      return res.status(400).send({
        error: err.message,
      });
    } else {
      next();
    }
  });
}

function bind(email, password, callback) {
  client.bind(email, password, function (err) {
    if (err) {
      return callback(err);
    }
    return callback();
  });
}

function search(query, callback) {
  let filter = "";

  const mailformat =
    /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;
  const ciformat = /^\d{11}$/;

  if (query.match(mailformat)) {
    filter = `(mail=${query})`;
  } else if (query.match(ciformat)) {
    filter = `(identification=${query})`;
  } else {
    filter = `(|(cn=*${query}*)(sn=*${query}*))`;
  }

  if (filter) {
    const opts = {
      filter: filter,
      scope: "sub",
      timeLimit: 6000,
      attributes: [
        "dn",
        "displayName",
        "givenName",
        "sAMAccountName",
        "identification",
        "description",
        "mail",
        "whenCreated",
        "whenChanged",
        "role",
        "serviceJabber",
        "serviceInternet",
        "serviceMail",
        "userAccountControl",
        "mailQuota",
      ],
    };

    client.search(searchDN, opts, (err, res) => {
      if (err) {
        return res.status(400).send({
          error: err.message,
        });
      }

      const users = [];
      res.on("searchEntry", function (entry) {
        users.push(entry.object);
      });
      res.on("searchReference", function (referral) {
        console.log("referral: " + referral.uris.join());
      });
      res.on("error", function (err) {
        console.error("error: " + err.message);
        return callback(null, err);
      });
      res.on("end", function (result) {
        console.log("status: " + result.status);
        return callback(users, null);
      });
    });
  }
}

function ldapConnect(req, res, next) {
  if (!client) {
    try {
      client = ldap.createClient({
        url: "ldaps://reduc.edu.cu:636",
        reconnect: true,
      });
      client.on("error", (err) => {
        console.debug(`[CLIENT ERROR]: ${err}`);
      });
    } catch (error) {
      console.debug(`[CREATE CLIENT ERROR]: ${error}`);
    }
  }
  next();
}

function ldapDisconnect() {
  if (client) {
    client.unbind(function (err) {
      assert.ifError(err);
    });
    client = null;
  }
}

module.exports = router;
