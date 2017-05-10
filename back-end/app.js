var express = require('express');
var path = require('path');
var favicon = require('static-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var multer = require('multer');
var fs = require('fs');
var mongoose = require('mongoose');
var cors = require('cors');
var expressJwt = require('express-jwt');
var jwt = require('jsonwebtoken');
var csrf = require('csrf');
var httpProxy = require('http-proxy');
var flash = require('connect-flash');
var app = express();

app.use('/api', expressJwt({ secret: 'amarTokenCode' }));


//helmet for security
var helmet = require('helmet');
app.use(helmet());

// Setting memory body parser

/*var whitelist = ['https://localhost:7300']; // Acceptable domain names. ie: https://www.example.com 
var corsOptions = { 
	credentials: true, 
	origin: function(origin, callback){ 
		var originIsWhitelisted = whitelist.indexOf(origin) !== -1; 
		
		//callback(null, originIsWhitelisted); 
		 callback(null, true);// uncomment this and comment the above to allow all 
	} 
}; 
// Enable CORS 
app.use(cors(corsOptions)); 

// Enable CORS Pre-Flight 
app.options('*', cors(corsOptions)); 

/*var corsOptions = {
origin: 'http://localhost:7300',
credentials:true,
preflightContinue: true  // <- I am assuming this is correct
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));*/



/*var whitelist = ['http://localhost:7300', 'http://localhost:8000'];
var corsOptionsDelegate = function(req, callback){
  var corsOptions;
  if(whitelist.indexOf(req.header('Origin')) !== -1){
    corsOptions = { origin: true, credentials: true }; // reflect (enable) the requested origin in the CORS response
  }else{
    corsOptions = { origin: false,  credentials: true }; // disable CORS for this request
  }
  callback(null, corsOptions); // callback expects two parameters: error and options
};

app.use(cors(corsOptionsDelegate));
app.options('*', cors(corsOptionsDelegate));*/

//test
// configuration of environment 
app.set('env', "development");
//app.set('env',"production");

if (app.get('env') === 'development') {

	//create a write stream (in append mode)
	var accessLogStream = fs.createWriteStream(__dirname + '/access.log', {
		flags: 'a'
	});
	//var accessLogStream = fs.createWriteStream('/var/log/origin/access.log',{flags: 'a'});

	// logging options
	morganOptions = {
		stream: accessLogStream
		// , skip: function (req, res) { return res.statusCode < 400; }  // uncomment this to log errors only
	};
	// enable logger
	app.use(logger('combined', morganOptions));

	// setup the logger
	//app.use(logger('combined', {stream: accessLogStream}));

	//app.use(express.errorHandler());

}

//// Environment Based DB selection
//if (app.get('env') === 'development') {
//
//	dbConfig.url = dbConfig.developmenturl;
//
//} else if (app.get('env') === 'production') {
//
//	dbConfig.url = dbConfig.url;
//
//} else {
//	dbConfig.url = dbConfig.developmenturl;
//}

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(favicon());
app.use(logger('dev'));

var expressSession = require('express-session');

var sessionstore = require('sessionstore');
// TODO - Why Do we need this key ?
app.use(expressSession({
	store: sessionstore.createSessionStore(),
	secret: '!@OlaHivemSangeet@!',
	resave: true,
	saveUninitialized: true,
	key: 'sid',
	cookie: {
		maxAge: null,
		httpOnly: true
	}

}));


app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json({
	limit: '2mb'
}));

app.use(require('express-method-override')('method_override_param_name'));

var proxyOptions = {
	changeOrigin: true
};

httpProxy.prototype.onError = function (err) {
	console.log(err);
};

var apiProxy = httpProxy.createProxyServer(proxyOptions);

var allowCrossDomain = function (req, res, next) {
	var allowedOrigins = ['http://127.0.0.1:7300', 'http://52.201.131.87:7300', 'http://beta.msangeet.com:7300', 'http://localhost:7300', 'http://52.66.93.102:7300'];
	var origin = req.headers.origin;
	if (allowedOrigins.indexOf(origin) > -1) {
		res.setHeader('Access-Control-Allow-Origin', origin);
	}
	//res.header('Access-Control-Allow-Origin', "http://localhost:7300"); 
	res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
	res.header("Access-Control-Allow-Credentials", true);
	res.header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With, if-none-match, x-access-token, Authorization');
	res.header("Access-Control-Expose-Headers", "Etag, Authorization, Origin, X-Requested-With, Content-Type, Accept, If-None-Match, Access-Control-Allow-Origin");
	if ('OPTIONS' == req.method) {
		res.sendStatus(200);
	} else {
		next();
	}
};
app.use(allowCrossDomain);


app.use(cookieParser());
app.use(express.static(path.join(__dirname + '.../public')));

//var d = require('domain').create();
//d.on('error', function(err, req, res, next) {
//
//	var MongoMail = require(__dirname + '/utils/mailer');
//	console.log('Oh no, something wrong with DB');
//	mongoalertStatus = 1;
//	data = {
//		email : 'ram@olahive.com'
//	};
//	// MongoMail.sendMailMongo(data);
//
//});
//
//d.run(function() {
//	mongoose.connect(dbConfig.url);
//	console.log("MongoDb connected Successfully !!!");
//});

app.use(multer({
	dest: './uploads/',
	limits: {
		fieldNameSize: 50,
		files: 1,
		fields: 10,
		fileSize: 5 * 1024 * 1024
	},
	rename: function (fieldname, filename) {
		return filename;
	},
	onFileUploadStart: function (file) {
		console.log('Starting file upload process.');
	},
	inMemory: true
	//This is important. It's what populates the buffer.
}));




// Configuring Passport
var passport = require('passport');

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());


// Initialize Passport
var initPassport = require('./passport/init');
initPassport(passport);

var routes = require('./routes/v1/index')(passport);
var routesv1 = require('./routes/v1/index')(passport);
//var routesv2 = require('./routes/v2/index')(passport);
app.use(require('express-domain-middleware'));

app.use('/', routes);
app.use('/mSangeet/api/v1', routesv1);
//app.use('/mSangeet/api/v2', routesv2);

/// catch 404 and forward to error handler
app.use(function (req, res, next) {
	var err = new Error('Not Found');
	err.status = 404;
	//next(err);
	res.status(err.status || 404);
	res.send({
		"code": "404",
		"error": "Not Found"
	});
});

// development error handler
// will print stacktrace

if (app.get('env') === 'development') {
	app.use(function (err, req, res, next) {
		if (app.get('env') === 'production') {

			accessLogStream.write(err.stack);

		}
		console.log(err.message)
		res.status(err.status || 500);
		//        res.render('error', {
		//            message: err.message,
		//            error: err
		//        });
		res.send({
			"code": "500",
			"error": "Internal Server Error"
		});
	});
}

if (app.get('env') === 'production') {

	console.log = function () {
	};

	/*	console.err = function() {
		};
	*/


}

module.exports = app;
