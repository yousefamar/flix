const fs         = require('fs');
const path       = require('path');
const util       = require('util');
const exec       = util.promisify(require('child_process').exec);
const crypto     = require('crypto');
const express    = require('express');
const bodyParser = require('body-parser');
const bcrypt     = require('bcrypt');
const bent       = require('bent')
const yifysubs   = require('yifysubtitles');
const apiKeys    = require('./api-keys.json');

const getMetadata = (() => {
	let tmdb   = bent('https://api.themoviedb.org/3', 'json');
	let search = (title, year) => tmdb(`/search/movie?api_key=${apiKeys.tmdb}&query=${title}&year=${year}`);
	let movie  = id => tmdb(`/movie/${id}?api_key=${apiKeys.tmdb}`);
	return async (title, year) => {
		let res = null;
		try {
			res = await search(title, year);
			res = await movie(res.results[0].id);
		} catch (e) {
			// TODO: Error handling
			console.error(e);
		}
		return res;
	};
})();

// Source: https://stackoverflow.com/a/52171480/1477456
const cyrb53 = (str, seed = 0) => {
	let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
	for (let i = 0, ch; i < str.length; i++) {
		ch = str.charCodeAt(i);
		h1 = Math.imul(h1 ^ ch, 2654435761);
		h2 = Math.imul(h2 ^ ch, 1597334677);
	}
	h1 = Math.imul(h1 ^ h1>>>16, 2246822507) ^ Math.imul(h2 ^ h2>>>13, 3266489909);
	h2 = Math.imul(h2 ^ h2>>>16, 2246822507) ^ Math.imul(h1 ^ h1>>>13, 3266489909);
	return 4294967296 * (2097151 & h2) + (h1>>>0);
};

const app    = express();
const secret = crypto.randomBytes(32).toString('base64');

app.disable('x-powered-by');
app.use(express.static('static'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'pug');

const basicAuthRealm = 'flix.amar.io';

let catalog;
try {
	catalog = fs.readFileSync('catalog.json', { encoding: 'utf8' });
} catch (e) {
	if (e.code === 'ENOENT') {
		fs.writeFileSync('catalog.json', JSON.stringify({}, null, '\t') + '\n');
		catalog = fs.readFileSync('catalog.json', { encoding: 'utf8' });
	}
}
catalog = JSON.parse(catalog);

async function walk(dir) {
	let files = await fs.promises.readdir(dir);
	files = await Promise.all(files.map(async file => {
		const filePath = path.join(dir, file);
		const stats = await fs.promises.stat(filePath);
		return stats.isDirectory() ? walk(filePath) : filePath;
	}));

	return files.reduce((all, dirContents) => all.concat(dirContents), []);
}

async function rescan() {
	// TODO: Check exists
	console.log('Scanning movies...');
	let files = await walk('./static/movies/');

	// Remove samples
	files = files.filter(f => f.toLowerCase().indexOf('sample') < 0);

	let mp4s = new Set(files.filter(f => f.endsWith('.mp4')).map(f => f.substring(0, f.length - 4)));
	let convertables = files.filter(f => f.endsWith('.mkv') || f.endsWith('.avi'));
	convertables = convertables
		.filter(f => !mp4s.has(f.substring(0, f.length - 4)));

	for (let convertable of convertables) {
		console.log('Converting file:', convertable);
		const { stdout, stderr } = await exec(`ffmpeg -i ${convertable} -codec copy -map 0 ${convertable.substring(0, convertable.length - 4)}.mp4`);
		console.log('stdout:', stdout);
		console.error('stderr:', stderr);
	}

	console.log('Scanning movies again...');
	files = await walk('./static/movies/');
	files = files
		.filter(f => f.toLowerCase().indexOf('sample') < 0)
		.filter(f => f.endsWith('.mp4'))
		.map(f => f.replace('static/', ''));

	let byHash = files.reduce((acc, curr) => (acc[cyrb53(curr)] = curr) && acc, {});

	let currFiles    = new Set(Object.keys(byHash));
	let oldFiles     = new Set(Object.keys(catalog));
	let newFiles     = Object.keys(byHash).filter(f => !oldFiles.has(f));
	let deletedFiles = Object.keys(catalog).filter(f => !currFiles.has(f));

	for (let h of deletedFiles) {
		console.log('File deleted or moved:', catalog[h].path);
		delete catalog[h];
	}

	for (let h of newFiles) {
		let f = byHash[h];
		console.log('New file:', f);
		let name = f.split('/');
		name = name[name.length - 1];
		year = name.match(/\b(19|[2-9][0-9])\d{2}\b/g)[0];
		name = name.split(year)[0].replace(/\[|\]|\(\)/g, '').replace(/\./g, ' ').trim();
		console.log('Fetching metadata...');
		let metadata = await getMetadata(name, year);

		let dir = 'static/' + path.dirname(f);
		let subs;
		try {
			console.log('Fetching subs (' + metadata.imdb_id + ')...');
			subs = await yifysubs(metadata.imdb_id, {
				path: dir,
				langs: [ 'en', 'de', 'ar', 'it' ]
			});
			for (let sub of subs) {
				sub.langNice = sub.lang.charAt(0).toUpperCase() + sub.lang.substring(1);
				sub.path = sub.path.replace('static/', '');
			}
		} catch (e) {
			// TODO: Error handling
			console.error(e);
		}

		catalog[h] = {
			path: f,
			searchName: name,
			searchYear: year,
			metadata,
			subs
		};
	}

	console.log('Updating catalog...');
	fs.writeFileSync('catalog.json', JSON.stringify(catalog, null, '\t') + '\n');
	console.log('Done');
}

rescan();

app.use((req, res, next) => {
	const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
	const [ username, password ] = Buffer.from(b64auth, 'base64').toString().split(':');

	if (!username || !password){
		res.set('WWW-Authenticate', 'Basic realm="' + basicAuthRealm + '"');
		res.status(401).send();
		return;
	}

	fs.readFile('./users.json', (err, data) => {
		if (err) {
			res.status(500).send(err);
			return;
		}
		let users = JSON.parse(data);
		if (!users[username] || !users[username].passwordHash) {
			res.set('WWW-Authenticate', 'Basic realm="' + basicAuthRealm + '"');
			res.status(401).send();
			return;
		}
		bcrypt.compare(password, users[username].passwordHash, (err, result) => {
			if (err) {
				res.status(500).send(err);
				return;
			}
			if (!result) {
				res.set('WWW-Authenticate', 'Basic realm="' + basicAuthRealm + '"');
				res.status(401).send();
				return;
			}
			req.users    = users;
			req.username = username;
			req.user     = users[username];
			next();
		});
	});
});

app.get('/', (req, res) => {
	res.render('index', {
		username: req.username,
		shouldChangePassword: req.user.shouldChangePassword,
		catalog
	});
});

app.post('/change-password', (req, res) => {
	if (!req.body.password) {
		res.status(400).send('Unspecified password');
		return;
	}

	bcrypt.hash(req.body.password, 10, (err, hash) => {
		if (err) {
			res.status(500).send(err);
			return;
		}
		req.user.passwordHash = hash;
		delete req.user.shouldChangePassword;

		fs.writeFile('./users.json', JSON.stringify(req.users, null, '\t'), err => {
			if (err) {
				res.status(500).send(err);
				return;
			}
			res.send();
		});
	});
});

app.get('/rescan', async (req, res) => {
	await rescan();
	res.send();
});

app.get('/:hash', (req, res) => {
	let hash = req.params.hash;
	if (!hash) {
		res.status(400).send('Movie ID not defined');
		return;
	}
	if (!(hash in catalog)) {
		res.status(404).send('Movie not in catalog');
		return;
	}
	res.render('movie', {
		username: req.username,
		info: catalog[hash]
	});
});

app.listen(process.env.PORT || 8096);
