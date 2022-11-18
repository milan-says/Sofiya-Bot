const express = require('express');
const router = express.Router();
const { findUid, getText } = global.utils;
const waitingVeryFbid = [];

module.exports = function ({ isAuthenticated_G, isAuthenticated_P, randomNumberApikey, expireVerifyCode, isVerifyRecaptcha, dashBoardData, api, createLimiter, config }) {
	router
		.get('/', isAuthenticated_G, (req, res) => {
			req.session.redirectTo = req.query.redirect;
			res.render("verifyfbid");
		})
		.get('/submit-code', [isAuthenticated_G, function (req, res, next) {
			if (!req.user.waitVerify)
				return res.redirect('/verifyfbid');
			next();
		}], (req, res) => {
			res.render("verifyfbid-submit-code");
		})

		.post('/', isAuthenticated_P, async (req, res) => {
			if (!await isVerifyRecaptcha(req.body['g-recaptcha-response']))
				return res.status(400).json({ errors: [{ msg: 'Recaptcha is not correct' }] });
			if (!api)
				return res.status(400).send({ errors: [{ msg: 'The bot is currently inactive, please come back later' }] });
			let { fbid } = req.body;
			const code = randomNumberApikey(6);
			if (!fbid)
				return res.status(400).send({ errors: [{ msg: 'Please enter facebook id' }] });
			try {
				if (isNaN(fbid))
					fbid = await findUid(fbid);
			}
			catch (e) {
				return res.status(400).send({ errors: [{ msg: 'Facebook id or profile url does not exist' }] });
			}
			const email = req.user.email;
			const index = waitingVeryFbid.findIndex(item => item.email === email);
			if (index !== -1)
				waitingVeryFbid[index] = { email, code, fbid };
			else
				waitingVeryFbid.push({ email, code, fbid });
			req.user.waitVerify = fbid;
			setTimeout(() => {
				const index = waitingVeryFbid.findIndex(item => item.email === email);
				if (index !== -1)
					waitingVeryFbid.splice(index, 1);
				delete req.user.waitVerify;
			}, expireVerifyCode);

			try {
				await api.sendMessage(getText('verifyfbid', 'sendCode', code, config.dashBoard.expireVerifyCode / 60000, global.GoatBot.config.language), fbid);
			}
			catch (e) {
				const errors = [];
				if (e.blockedAction)
					errors.push({ msg: 'The bot is currently blocked and cannot send messages, please try again later' });
				else
					errors.push({ msg: `Can't send confirmation code to facebook id "${fbid}", have you turned on receiving waiting messages from strangers?` });
			}
			req.flash('success', { msg: 'The verification code has been sent to your facebook id, if you don't see it, please check the message' });
			res.send({
				status: 'success',
				message: 'The verification code has been sent to your facebook id, if you don't see it, please check the message'
			});
		})
		.post('/submit-code', [isAuthenticated_P, function (req, res, next) {
			if (!req.user.waitVerify)
				return res.redirect('/verifyfbid');
			next();
		}, createLimiter(1000 * 60 * 5, 20)], async (req, res) => {
			const { code } = req.body;
			const user = await dashBoardData.get(req.user.email);
			const index = waitingVeryFbid.findIndex(item => item.email === user.email);
			if (waitingVeryFbid[index].code === code) {
				const fbid = req.user.waitVerify;
				console.log(`User ${user.email} verify fbid ${fbid}`);
				delete req.user.waitVerify;
				await dashBoardData.set(user.email, { facebookUserID: fbid });
				req.flash('success', { msg: 'Confirmed facebook user id successfully' });
				res.send({
					status: 'success',
					message: 'Confirmed facebook user id successfully',
					redirectLink: req.session.redirectTo || '/dashboard'
				});
			}
			else {
				return res.status(400).send({ errors: [{ msg: 'Incorrect code' }] });
			}
		});

	return router;
};
