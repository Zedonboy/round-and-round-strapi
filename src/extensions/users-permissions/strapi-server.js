const utils = require("@strapi/utils");
const { sanitize } = utils;
const { ApplicationError, ValidationError } = utils.errors;
const _ = require("lodash");

const getService = (name) => {
  return strapi.plugin("users-permissions").service(name);
};


const emailRegExp =
  /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

function getRandom(length) {
  return Math.floor(
    Math.pow(10, length - 1) + Math.random() * 9 * Math.pow(10, length - 1)
  );
}

const sanitizeUser = (user, ctx) => {
  const { auth } = ctx.state;
  const userSchema = strapi.getModel("plugin::users-permissions.user");

  return sanitize.contentAPI.output(user, userSchema, { auth });
};

module.exports = (plugin) => {
  plugin.controllers.auth.forgotPassword = async (ctx) => {
    let { email } = ctx.request.body;

    // Check if the provided email is valid or not.
    const isEmail = emailRegExp.test(email);

    if (isEmail) {
      email = email.toLowerCase();
    } else {
      throw new ValidationError("Please provide a valid email address");
    }

    // if(!isEmail) {
    //   throw new ValidationError("Please provide a valid email address");
    // }

    // Find the user by email.
    const user = await strapi
      .query("plugin::users-permissions.user")
      .findOne({ where: { email } });

    // User not found.
    if (!user) {
      throw new ApplicationError("This email does not exist");
    }

    // User blocked
    if (user.blocked) {
      throw new ApplicationError("This user is disabled");
    }

    // Generate random token.
    const resetPasswordToken = getRandom(6);

    const msg = {
      to: email, // Change to your recipient
      from: "hutsyapp@gmail.com", // Change to your verified sender
      subject: "Hutsy Reset Password",
      html: `Your reset password toke is <strong>${resetPasswordToken}</strong>`,
    };
    await strapi.plugins["email"].services.email.send(msg);
    await strapi
      .query("plugin::users-permissions.user")
      .update({ where: { id: user.id }, data: { resetPasswordToken } });

    return ctx.send({ ok: true });
  };

  plugin.controllers.auth.resetPassword = async (ctx) => {
    const params = _.assign({}, ctx.request.body, ctx.params);
    if (params.password && params.code && params.email) {
      const user = await strapi
        .query("plugin::users-permissions.user")
        .findOne({
          where: {
            resetPasswordToken: `${params.code}`,
            email: `${params.email}`,
          },
        });

      if (!user) {
        throw new ValidationError("Incorrect code provided");
      }

      await getService("user").edit(user.id, {
        resetPasswordToken: null,
        password: params.password,
      });
      // Update the user.

      ctx.send({
        jwt: getService("jwt").issue({ id: user.id }),
        user: await sanitizeUser(user, ctx),
      });
    } else {
      throw new ValidationError("Incorrect params provided");
    }
  };

  return plugin;
};
