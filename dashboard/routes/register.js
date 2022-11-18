const bcrypt = require('bcrypt');
const expres = require('express');
const router = expres.Router();

module.exports = function ({ unAuthenticated_G, isWaitVerifyAccount_G, unAuthenticated_P, isWaitVerifyAccount_P, isVerifyRecaptcha, validateEmail, randomNumberApikey, transporter, generateEmailVerificationCode, dashBoardData, expireVerifyCode }) {
	router
		.get("/", unAuthenticated_G, (req, res) => {
			res.render('register');
		})
		.get("/submit-code", [unAuthenticated_G, isWaitVerifyAccount_G], (req, res) => {
			res.render('register-submit-code');
		})
		.get("/resend-code", [unAuthenticated_G, isWaitVerifyAccount_G], async (req, res) => {
			res.render('register-resend-code');
		})

		.post("/", unAuthenticated_P, async (req, res) => {
			if (!await isVerifyRecaptcha(req.body['g-recaptcha-response']))
				return res.status(400).send({
					status: "error",
					message: "Invalid Captcha"
				});
			const { name, email, password, password_confirmation } = req.body;
			const errors = [];
			if (!name || !email || !password || !password_confirmation)
				errors.push({ msg: "You have not filled in enough information" });
			if (!validateEmail(email))
				errors.push({ msg: "Email address is not valid" });
			if (email.length > 100 || email.length < 5)
				errors.push({ msg: "Email addresses must be between 5 and 100 characters in length" });
			if (dashBoardData.get(email))
				errors.push({ msg: `Email address ${email} already in use` });
			if (password !== password_confirmation)
				errors.push({ msg: "password incorrect" });
			if (password.length < 6)
				errors.push({ msg: "Passwords must be at least 6 characters" });
			if (errors.length > 0) {
				return res.status(400).send({
					status: "error",
					errors
				});
			}

			const code = randomNumberApikey(6);
			await transporter.sendMail({
				from: "Goat-Bot",
				to: email,
				subject: "Verify your account",
				html: generateEmailVerificationCode(code)
			});

			// if you want better security, you can use hash password before saving to database
			const hashPassword = bcrypt.hashSync(password, 10);
			const user = {
				email,
				name,
				password: hashPassword,
				code
			};
			req.session.waitVerifyAccount = user;
			res.redirect('/register/submit-code');
			setTimeout((() => {
				delete req.session.waitVerifyAccount;
			}), expireVerifyCode);
		})
		.post("/resend-code", [unAuthenticated_P, isWaitVerifyAccount_P], async (req, res) => {
			const email = req.body.email;
			if (!validateEmail(email)) {
				req.flash('errors', { msg: "Địa chỉ email không hợp lệ" });
				return res.status(400).send({ status: "error", message: "Email address is not valid" });
			}

			if (dashBoardData.get(email)) {
				req.flash('errors', { msg: "This email address is already in use" });
				return res.redirect('/register/resend-code');
			}

			req.session.waitVerifyAccount.email = email;
			const code = randomNumberApikey(6);

			try {
				await transporter.sendMail({
					from: "Goat-Bot",
					to: email,
					subject: "Verify your account",
					html: generateEmailVerificationCode(code)
				});
			}
			catch (err) {
				req.flash('errors', { msg: "An error occurred, please try again later" });
				return res.redirect('/register/resend-code');
			}

			req.session.waitVerifyAccount.code = code;
			res.redirect('/register/submit-code');
		})
		.post("/submit-code", [unAuthenticated_P, isWaitVerifyAccount_P], async (req, res, next) => {
			const { code } = req.body;
			const { waitVerifyAccount } = req.session;
			if (!waitVerifyAccount)
				return res.redirect('/register');
			if (code !== waitVerifyAccount.code) {
				req.flash('errors', { msg: 'Code is not correct' });
				return res.redirect('/register/submit-code');
			}
			delete waitVerifyAccount.code;
			const user = await dashBoardData.create(waitVerifyAccount);
			const redirectLink = req.session.redirectTo || '/';

			req.logIn(user, (err) => {
				if (err) {
					return next(err);
				}
				delete req.session.redirectTo;
				req.flash('success', { msg: 'You have successfully registered' });
				res.redirect(redirectLink);
			});
		});

	return router;
};
