const bcrypt = require('bcrypt');
const expres = require('express');
const router = expres.Router();

module.exports = function ({ unAuthenticated_G, validateEmail, randomNumberApikey, transporter, generateEmailVerificationCode, expireVerifyCode, dashBoardData }) {
	router
		.get('/', unAuthenticated_G, (req, res) => {
			res.render('forgot-password');
		})
		.get('/submit-code', unAuthenticated_G, (req, res) => {
			if (!req.session.resetPassword)
				return res.redirect('/forgot-password');
			res.render('forgot-password-submit-code');
		})
		.get('/new-password', unAuthenticated_G, (req, res) => {
			if (!req.session.resetPassword)
				return res.redirect('/forgot-password');
			res.render('forgot-password-new-password');
		})

		.post('/', unAuthenticated_G, async (req, res) => {
			const { email } = req.body;
			if (!validateEmail(email)) {
				req.flash('errors', { msg: "Địa chỉ email không hợp lệ" });
				return res.redirect('/forgot-password');
			}
			const user = await dashBoardData.get(email);
			if (!user) {
				req.flash('errors', { msg: "Không tìm thấy email này" });
				return res.redirect('/forgot-password');
			}
			const code = randomNumberApikey(6);
			try {
				await transporter.sendMail({
					from: "Goat-Bot",
					to: email,
					subject: "Reset your password",
					html: generateEmailVerificationCode(code, 'Hi, you have requested a password reset at Goat-Bot. Below is your confirmation code.')
				});
			}
			catch (e) {
				req.flash("errors", { msg: "Email could not be sent, please try again later" });
				return res.redirect('/forgot-password');
			}
			req.session.resetPassword = {
				email,
				code
			};
			res.redirect('/forgot-password/submit-code');
			setTimeout((() => {
				delete req.session.resetPassword.code;
			}), expireVerifyCode);
		})
		.post('/submit-code', unAuthenticated_G, async (req, res) => {
			const { code } = req.body;
			const { resetPassword } = req.session;
			if (!resetPassword)
				return res.redirect('/forgot-password');
			if (code !== resetPassword.code) {
				req.flash('errors', { msg: 'Confirmation code is incorrect' });
				return res.redirect('/forgot-password/submit-code');
			}
			res.redirect('/forgot-password/new-password');
		})
		.post('/new-password', unAuthenticated_G, async (req, res) => {
			if (!req.session.resetPassword)
				return res.redirect('/forgot-password');
			const email = req.session.resetPassword.email;
			const { password, password_confirmation } = req.body;
			if (password !== password_confirmation) {
				req.flash('errors', { msg: "password incorrect" });
				return res.redirect('/forgot-password/new-password');
			}
			if (password.length < 6) {
				req.flash('errors', { msg: "Passwords must be at least 6 characters" });
				return res.redirect('/forgot-password/new-password');
			}
			const hashPassword = bcrypt.hashSync(password, 10);
			await dashBoardData.set(email, { password: hashPassword });
			delete req.session.resetPassword;
			req.flash('success', { msg: 'Changed password successfully' });
			res.redirect('/login');
		});

	return router;
};
